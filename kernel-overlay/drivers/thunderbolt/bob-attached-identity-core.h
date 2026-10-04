/* SPDX-License-Identifier: GPL-2.0 */
/* Bounded TB3 identity only. I/O callbacks always address ACIO0 route 1.
 * EEPROM READ requires control writes, but never unlock/tunnel/auth writes.
 * Clock/bit order follows pinned drivers/thunderbolt/eeprom.c.
 */
#define BOB_ID_UID PROVISION_PRIVATE_ID_1
#define BOB_ID_MAX_DROM 1036
#define BOB_ID_MAX_OPS 80000
#define BOB_EE_SK 1U
#define BOB_EE_CS 2U
#define BOB_EE_DI 4U
#define BOB_EE_DO 8U
#define BOB_EE_ENABLE 16U

struct bob_id_io {
	int (*read)(void *ctx, unsigned int off, unsigned int count, u32 *data);
	int (*write)(void *ctx, unsigned int off, u32 data);
	bool (*expired)(void *ctx);
	void *ctx;
	unsigned int operations;
	unsigned int ctl_offset;
	bool cleanup_failed;
};

static int bob_id_read(struct bob_id_io *io, unsigned int off,
		       unsigned int count, u32 *data)
{
	if (!count || count > 13 || off > 0x2000U - count)
		return -EINVAL;
	if (io->operations++ >= BOB_ID_MAX_OPS || io->expired(io->ctx))
		return -ETIMEDOUT;
	return io->read(io->ctx, off, count, data);
}

static int bob_id_write(struct bob_id_io *io, u32 data)
{
	if (io->ctl_offset > 0x1fff)
		return -EINVAL;
	if (io->operations++ >= BOB_ID_MAX_OPS || io->expired(io->ctx))
		return -ETIMEDOUT;
	return io->write(io->ctx, io->ctl_offset, data);
}

/* Cleanup is attempted even after deadline, budget exhaustion or partial enable.
 * Do not retry a failed operation. Try clearing bitbang even if CS write fails.
 * An uncertain cleanup always rejects identity and retains the upstream owner.
 */
static int bob_id_cleanup(struct bob_id_io *io, u32 last)
{
	int a, b;

	if (io->ctl_offset > 0x1fff)
		return -EINVAL;
	last = (last | BOB_EE_CS) & ~BOB_EE_SK;
	a = io->write(io->ctx, io->ctl_offset, last);
	b = io->write(io->ctx, io->ctl_offset, last & ~BOB_EE_ENABLE);
	if (a || b) {
		io->cleanup_failed = true;
		return a ? a : b;
	}
	return 0;
}

static int bob_id_out(struct bob_id_io *io, u8 value, u32 *last)
{
	unsigned int bit;
	int ret;

	for (bit = 0; bit < 8; bit++) {
		*last = (*last & ~(BOB_EE_DI | BOB_EE_SK)) |
			((value & 0x80) ? BOB_EE_DI : 0);
		ret = bob_id_write(io, *last);
		if (ret)
			return ret;
		ret = bob_id_write(io, *last | BOB_EE_SK);
		if (ret)
			return ret;
		ret = bob_id_write(io, *last);
		if (ret)
			return ret;
		value <<= 1;
	}
	return 0;
}

static int bob_id_in(struct bob_id_io *io, u8 *value, u32 *last)
{
	unsigned int bit;
	u32 sample;
	int ret;

	*value = 0;
	for (bit = 0; bit < 8; bit++) {
		ret = bob_id_write(io, *last | BOB_EE_SK);
		if (ret)
			return ret;
		ret = bob_id_read(io, io->ctl_offset, 1, &sample);
		if (ret)
			return ret;
		*value = (*value << 1) | !!(sample & BOB_EE_DO);
		ret = bob_id_write(io, *last & ~BOB_EE_SK);
		if (ret)
			return ret;
	}
	return 0;
}

static int bob_id_eeprom(struct bob_id_io *io, unsigned int base,
			 unsigned int offset, u8 *data, unsigned int count)
{
	u32 last;
	unsigned int i, address;
	int ret, cleanup;

	if (!count || count > BOB_ID_MAX_DROM || base > 0xffff ||
	    offset > 0xffff - base || count > 0x10000 - base - offset)
		return -EINVAL;
	address = base + offset;
	ret = bob_id_read(io, io->ctl_offset, 1, &last);
	if (ret)
		return ret;
	/* Reject an already owned/active transaction rather than take it over. */
	if ((last & BOB_EE_ENABLE) || !(last & BOB_EE_CS) ||
	    !(last & 0x80) || (last & 0x20))
		return -EBUSY;
	last = (last | BOB_EE_ENABLE) & ~BOB_EE_SK;
	ret = bob_id_write(io, last);
	if (ret)
		goto out;
	last &= ~BOB_EE_CS;
	ret = bob_id_write(io, last);
	if (ret)
		goto out;
	ret = bob_id_out(io, 3, &last); /* EEPROM READ, never WRITE/ERASE */
	if (!ret)
		ret = bob_id_out(io, address >> 8, &last);
	if (!ret)
		ret = bob_id_out(io, address, &last);
	for (i = 0; !ret && i < count; i++)
		ret = bob_id_in(io, data + i, &last);
 out:
	cleanup = bob_id_cleanup(io, last);
	return cleanup ? cleanup : ret;
}

static u8 bob_id_crc8(const u8 *data)
{
	u8 crc = 0xff;
	unsigned int i, j;

	for (i = 0; i < 8; i++) {
		crc ^= data[i];
		for (j = 0; j < 8; j++)
			crc = (crc << 1) ^ ((crc & 0x80) ? 7 : 0);
	}
	return crc;
}

static u32 bob_id_crc32c(const u8 *data, unsigned int len)
{
	u32 crc = ~0U;
	unsigned int i, bit;

	for (i = 0; i < len; i++) {
		crc ^= data[i];
		for (bit = 0; bit < 8; bit++)
			crc = (crc >> 1) ^ ((crc & 1) ? 0x82f63b78 : 0);
	}
	return ~crc;
}

static u64 bob_id_le64(const u8 *p)
{
	u64 v = 0;
	unsigned int i;

	for (i = 0; i < 8; i++)
		v |= (u64)p[i] << (8 * i);
	return v;
}

static int bob_id_uid(const u8 *data)
{
	if (bob_id_crc8(data + 1) != data[0])
		return -EBADMSG;
	return bob_id_le64(data + 1) == BOB_ID_UID ? 0 : -EACCES;
}

/* Strict bounded walk: no generic capability helper, no TMU enable side effect. */
static int bob_id_cap(struct bob_id_io *io, unsigned int start, unsigned int *base)
{
	unsigned int seen[64], n = 0, i, off = start, next, len;
	u32 cap[13];
	int ret;

	while (off) {
		if (off < 5 || off > 0x1ff3 || n == 64)
			return -EINVAL;
		for (i = 0; i < n; i++)
			if (seen[i] == off)
				return -ELOOP;
		seen[n++] = off;
		ret = bob_id_read(io, off, 2, cap);
		if (ret)
			return ret;
		if (((cap[0] >> 8) & 0xff) == 3) {
			off = cap[0] & 0xff;
			continue;
		}
		if (((cap[0] >> 8) & 0xff) != 5)
			return -EOPNOTSUPP;
		len = cap[0] >> 24;
		next = cap[0] & 0xff;
		if (!len) {
			/* Long VSE layout is not the short EEPROM capability. */
			if (next)
				return -EINVAL;
			next = cap[1] & 0xffff;
			if (((cap[0] >> 16) & 0xff) == 1)
				return -EOPNOTSUPP;
		} else if (((cap[0] >> 16) & 0xff) == 1) {
			if (len < 13 || len > 0x2000 - off)
				return -EINVAL;
			ret = bob_id_read(io, off, 13, cap);
			if (ret)
				return ret;
			if (!(cap[4] & 0x80) || (cap[4] & 0x20) || cap[12] > 0xffff)
				return -ENODEV;
			io->ctl_offset = off + 4;
			*base = cap[12];
			return 0;
		}
		off = next;
	}
	return -ENOENT;
}

static int bob_id_tb3(struct bob_id_io *io, u8 *drom, unsigned int *size)
{
	u32 header[5];
	unsigned int base, total, len, off;
	int ret;

	ret = bob_id_read(io, 0, 5, header);
	if (ret)
		return ret;
	/* Only the reviewed TB3 route type; USB4 has a different DROM protocol. */
	if ((header[4] >> 24) != 3)
		return -EOPNOTSUPP;
	if (((header[1] >> 20) & 7) != 1 || header[2] != 1 ||
	    (header[3] & 0x7fffffff) || !((header[1] >> 8) & 63) ||
	    ((header[1] >> 8) & 63) > ((header[1] >> 14) & 63))
		return -EINVAL;
	ret = bob_id_cap(io, header[1] & 0xff, &base);
	if (ret)
		return ret;
	ret = bob_id_eeprom(io, base, 0, drom, 9);
	if (ret)
		return ret;
	ret = bob_id_uid(drom);
	if (ret)
		return ret; /* No length/full-DROM read after a wrong fresh UID. */
	ret = bob_id_eeprom(io, base, 13, drom + 13, 3);
	if (ret)
		return ret;
	len = drom[14] | ((unsigned int)drom[15] << 8);
	if (drom[13] > 1 || len < 9 || len > 1023)
		return -EINVAL;
	total = len + 13;
	ret = bob_id_eeprom(io, base, 0, drom, total);
	if (ret)
		return ret;
	ret = bob_id_uid(drom);
	if (ret)
		return ret;
	if (drom[13] > 1 || (drom[14] | ((unsigned int)drom[15] << 8)) != len)
		return -EINVAL;
	if (bob_id_crc32c(drom + 13, len) !=
	    (u32)(drom[9] | (u32)drom[10] << 8 | (u32)drom[11] << 16 |
		  (u32)drom[12] << 24))
		return -EBADMSG;
	if (drom[16] != 0x14 || drom[17] != 0x04 ||
	    drom[18] != 0x63 || drom[19] != 0x7a)
		return -EACCES;
	for (off = 22; off < total; off += drom[off])
		if (drom[off] < 2 || drom[off] > total - off)
			return -EINVAL;
	*size = total;
	return 0;
}
