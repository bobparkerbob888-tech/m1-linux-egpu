/* SPDX-License-Identifier: GPL-2.0 */
/* A single memory-decode probe, independent of the closed discovery window. */
#ifndef APCIEC_MMIO_PROBE_CORE_H
#define APCIEC_MMIO_PROBE_CORE_H
struct mp_state {
 u64 deadline;
 unsigned ops, next, enabled;
 bool attempted, failed, armed, pending;
 bool w1c_armed, w1c_pending, w1c_complete;
 bool headerlog_armed, headerlog_pending;
 unsigned headerlog_step;
 unsigned w1c_rid, w1c_offset, w1c_width, w1c_slot;
 u32 w1c_value, w1c_mask, w1c_consumed;
};
static bool mp_active(const struct mp_state *s, u64 now)
{
 return s && s->attempted && !s->failed && s->deadline &&
        now < s->deadline && s->ops < 1024 && s->next <= 4 &&
        s->enabled == ((1U << s->next) - 1);
}
/* Single upstream AER logging-mask transaction, then exact restoration.
 * This changes logging only; Device Control reporting remains disabled.
 */
static bool mp_arm_headerlog(struct mp_state *s, u64 now, bool restore)
{
 if (!mp_active(s, now) || s->next != 4 || s->enabled != 15 ||
     !s->w1c_complete || s->w1c_armed || s->w1c_pending ||
     s->armed || s->pending || s->headerlog_armed || s->headerlog_pending ||
     s->headerlog_step != (restore ? 1U : 0U)) return false;
 s->headerlog_armed = true;
 return true;
}
static bool mp_allow_headerlog(struct mp_state *s, u64 now, unsigned rid,
                               unsigned off, unsigned width, u32 before, u32 value)
{
 if (!mp_active(s, now) || !s->headerlog_armed || s->headerlog_pending ||
     !s->w1c_complete || s->w1c_armed || s->w1c_pending || s->armed || s->pending ||
     s->next != 4 || s->enabled != 15 || s->headerlog_step > 1 ||
     rid != 0x100 || off != 0x100 + PCI_ERR_COR_MASK || width != 4 ||
     before != (s->headerlog_step ? 0U : PCI_ERR_COR_ADV_NFAT) ||
     value != (s->headerlog_step ? PCI_ERR_COR_ADV_NFAT : 0U)) return false;
 s->headerlog_armed = false;
 s->headerlog_pending = true;
 s->headerlog_step++; /* Consume before the hardware write, including failures. */
 return true;
}
static bool mp_complete_headerlog(struct mp_state *s, unsigned rid, u32 after)
{
 if (!s || s->failed || !s->headerlog_pending || s->headerlog_armed ||
     rid != 0x100 || (s->headerlog_step != 1 && s->headerlog_step != 2) ||
     after != (s->headerlog_step == 1 ? 0U : PCI_ERR_COR_ADV_NFAT)) return false;
 s->headerlog_pending = false;
 return true;
}
/* Exact selected path, status registers only. No command/control aliases. */
static u32 mp_w1c_mask(unsigned rid, unsigned off, unsigned width, unsigned *slot)
{
 unsigned j, pcie, aer, kind;
 u32 mask;
 if (rid > 0x300 || (rid & 0xff)) return 0;
 j = rid >> 8;
 pcie = j == 0 ? 0x70 : j == 3 ? 0x60 : 0xc0;
 aer = j == 3 ? 0x1b8 : 0x100;
 if (width == 2 && off == PCI_STATUS) {
  kind = 0;
  mask = PCI_STATUS_PARITY | PCI_STATUS_SIG_TARGET_ABORT |
         PCI_STATUS_REC_TARGET_ABORT | PCI_STATUS_REC_MASTER_ABORT |
         PCI_STATUS_SIG_SYSTEM_ERROR | PCI_STATUS_DETECTED_PARITY;
 } else if (width == 2 && j < 3 && off == PCI_SEC_STATUS) {
  kind = 1;
  mask = PCI_STATUS_PARITY | PCI_STATUS_SIG_TARGET_ABORT |
         PCI_STATUS_REC_TARGET_ABORT | PCI_STATUS_REC_MASTER_ABORT |
         PCI_STATUS_SIG_SYSTEM_ERROR | PCI_STATUS_DETECTED_PARITY;
 } else if (width == 2 && off == pcie + PCI_EXP_DEVSTA) {
  kind = 2;
  mask = PCI_EXP_DEVSTA_CED | PCI_EXP_DEVSTA_NFED | PCI_EXP_DEVSTA_FED | PCI_EXP_DEVSTA_URD;
 } else if (width == 4 && off == aer + PCI_ERR_UNCOR_STATUS) {
  kind = 3;
  /* Defined status bits applicable to these captured AER v1/v2 functions. */
  mask = PCI_ERR_UNC_DLP | PCI_ERR_UNC_SURPDN | PCI_ERR_UNC_POISON_TLP |
         PCI_ERR_UNC_FCP | PCI_ERR_UNC_COMP_TIME | PCI_ERR_UNC_COMP_ABORT |
         PCI_ERR_UNC_UNX_COMP | PCI_ERR_UNC_RX_OVER | PCI_ERR_UNC_MALF_TLP |
         PCI_ERR_UNC_ECRC | PCI_ERR_UNC_UNSUP | PCI_ERR_UNC_ACSV |
         PCI_ERR_UNC_INTN | PCI_ERR_UNC_MCBTLP | PCI_ERR_UNC_ATOMEG | PCI_ERR_UNC_TLPPRE;
 } else if (width == 4 && off == aer + PCI_ERR_COR_STATUS) {
  kind = 4;
  mask = PCI_ERR_COR_RCVR | PCI_ERR_COR_BAD_TLP | PCI_ERR_COR_BAD_DLLP |
         PCI_ERR_COR_REP_ROLL | PCI_ERR_COR_REP_TIMER | PCI_ERR_COR_ADV_NFAT |
         PCI_ERR_COR_INTERNAL | PCI_ERR_COR_LOG_OVER;
 } else if (width == 4 && !j && off == aer + PCI_ERR_ROOT_STATUS) {
  kind = 5;
  mask = PCI_ERR_ROOT_COR_RCV | PCI_ERR_ROOT_MULTI_COR_RCV |
         PCI_ERR_ROOT_UNCOR_RCV | PCI_ERR_ROOT_MULTI_UNCOR_RCV |
         PCI_ERR_ROOT_FIRST_FATAL | PCI_ERR_ROOT_NONFATAL_RCV | PCI_ERR_ROOT_FATAL_RCV;
 } else return 0;
 *slot = j * 6 + kind;
 return mask;
}
static bool mp_arm_w1c(struct mp_state *s, u64 now, unsigned rid,
                        unsigned off, unsigned width, u32 observed)
{
 unsigned slot;
 u32 mask = mp_w1c_mask(rid, off, width, &slot);
 if (!mp_active(s, now) || s->next != 4 || s->enabled != 15 ||
     s->armed || s->pending || s->w1c_armed || s->w1c_pending ||
     s->w1c_complete || !mask || !observed || (observed & ~mask) ||
     (s->w1c_consumed & (1U << slot))) return false;
 s->w1c_rid = rid; s->w1c_offset = off; s->w1c_width = width;
 s->w1c_value = observed; s->w1c_mask = mask; s->w1c_slot = slot;
 s->w1c_armed = true;
 return true;
}
static bool mp_allow_w1c(struct mp_state *s, u64 now, unsigned rid,
                          unsigned off, unsigned width, u32 before, u32 value)
{
 if (!mp_active(s, now) || !s->w1c_armed || s->w1c_pending ||
     s->w1c_complete || s->armed || s->pending || s->next != 4 ||
     rid != s->w1c_rid || off != s->w1c_offset || width != s->w1c_width ||
     value != s->w1c_value || (before & s->w1c_mask) != value ||
     (s->w1c_consumed & (1U << s->w1c_slot))) return false;
 s->w1c_consumed |= 1U << s->w1c_slot; /* Before the physical write. */
 s->w1c_armed = false; s->w1c_pending = true;
 return true;
}
static bool mp_complete_w1c(struct mp_state *s, unsigned rid, u32 after)
{
 if (!s || s->failed || !s->w1c_pending || s->w1c_armed ||
     rid != s->w1c_rid || (after & s->w1c_mask)) return false;
 s->w1c_pending = false;
 return true;
}
/* Match ordinary pci_enable_device_mem ancestor forwarding state.
 * Endpoint0300 keeps MASTER clear; unused functions stay disabled. */
static unsigned mp_target_command(unsigned rid)
{
 if (rid > 0x300 || (rid & 0xff)) return 0;
 return rid < 0x300 ? PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER : PCI_COMMAND_MEMORY;
}
static bool mp_allow_write(struct mp_state *s, u64 now, unsigned rid,
                           unsigned off, unsigned width, u32 before, u32 value)
{
 if (!mp_active(s, now) || !s->armed || s->pending || s->next >= 4 ||
     rid != s->next * 0x100 || off != 4 || width != 2 || before || value != mp_target_command(rid))
  return false;
 s->armed = false; /* Consume before issuing even a potentially failed write. */
 s->pending = true;
 return true;
}
static bool mp_complete_write(struct mp_state *s, unsigned rid, u32 value)
{
 if (!s || s->failed || s->armed || !s->pending || s->next >= 4 ||
     rid != s->next * 0x100 || value != mp_target_command(rid) ||
     s->enabled != ((1U << s->next) - 1)) return false;
 s->enabled |= 1U << s->next;
 s->next++;
 s->pending = false;
 return true;
}
static unsigned mp_expected_command(const struct mp_state *s, unsigned rid)
{
 if (s && s->attempted && rid <= 0x300 && !(rid & 0xff) &&
     (s->enabled & (1U << (rid >> 8)))) return mp_target_command(rid);
 return 0;
}
static bool mp_boot0_valid(u32 first, u32 second)
{
 /* NVIDIA public nv_ref.h and ctrl2080mc.h: GB200 architecture, GB206 impl. */
 return first == second && first && first != 0xffffffffU &&
        ((first >> 24) & 0x1f) == 0x1b &&
        !(first & (1U << 8)) && ((first >> 20) & 0xf) == 6;
}
#endif
