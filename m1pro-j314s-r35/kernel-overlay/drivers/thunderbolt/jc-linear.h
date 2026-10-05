/* SPDX-License-Identifier: GPL-2.0 */
/* prepare(index) returns1 only for fresh read-only terminal survey, zero
 * for one completed router, negative for every failed/partial attempt. */
struct jc_linear_io {
 int (*prepare)(void*,unsigned);int (*record)(void*,unsigned,bool);
 bool (*valid)(void*);void*ctx;bool attempted;unsigned count;bool terminal;
};
static int jc_linear_once(struct jc_linear_io*i)
{
 int ret;
 if(!i||!i->prepare||!i->record||!i->valid)return -EINVAL;
 if(i->attempted)return -EALREADY;
 i->attempted=true;
 for(unsigned j=0;j<=3;j++){
  if(!i->valid(i->ctx))return -ETIMEDOUT;
  ret=i->prepare(i->ctx,j);
  if(ret<0)return ret;
  if(!i->valid(i->ctx))return -ETIMEDOUT;
  if(ret==1){ret=i->record(i->ctx,j,true);if(ret)return ret;i->terminal=true;return 0;}
  if(ret||j==3)return -E2BIG;
  ret=i->record(i->ctx,j,false);if(ret)return ret;i->count++;
 }
 return -E2BIG;
}
