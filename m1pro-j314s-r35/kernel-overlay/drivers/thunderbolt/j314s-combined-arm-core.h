/* SPDX-License-Identifier: GPL-2.0 */
/* Called while the real arm mutex is held. All callbacks are software/OF
 * validation only. No overlay, probe or power action may occur in this core. */
struct j314s_combined_arm_io {
 bool (*pristine)(void *); bool (*slot_pristine)(void *,unsigned);
 void *ctx; unsigned consumed,committed; bool attempted;
};
static int j314s_combined_arm_once(struct j314s_combined_arm_io *io,unsigned mask)
{
 if(!io||!io->pristine||!io->slot_pristine||(mask!=3&&mask!=5))return -EINVAL;
 if(io->attempted)return -EALREADY;
 io->attempted=true;
 /* Consume every selected slot together, even if the first check fails. */
 if(io->consumed||io->committed){io->consumed|=mask;return -EPERM;}
 io->consumed=mask;
 if(!io->pristine(io->ctx))return -EPERM;
 for(unsigned i=0;i<3;i++)if(!io->slot_pristine(io->ctx,i))return -EPERM;
 if(!io->pristine(io->ctx))return -EPERM;
 io->committed=mask;return 0;
}
