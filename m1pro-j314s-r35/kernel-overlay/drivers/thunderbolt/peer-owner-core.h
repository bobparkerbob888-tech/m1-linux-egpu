/* Per-controller cold identity lease. No hardware/callbacks or C0 changes. */
#ifndef J314S_PEER_OWNER_CORE_H
#define J314S_PEER_OWNER_CORE_H
struct jp_owner { const void *cio,*nhi,*ticket; unsigned controller,cable,operations;
 unsigned long long deadline; bool consumed,complete,failed; };
static int jp_begin(struct jp_owner *o,unsigned controller,const void *cio,
 const void *nhi,const void *ticket,unsigned cable,unsigned long long now,
 unsigned long long deadline)
{
 if(!o||controller<1||controller>2||!cio||!nhi||!ticket||!cable||
    deadline<=now||deadline-now>20000000000ULL)return -1;
 if(o->consumed)return -1;
 *o=(struct jp_owner){.cio=cio,.nhi=nhi,.ticket=ticket,.controller=controller,
  .cable=cable,.deadline=deadline,.consumed=true};return 0;
}
static bool jp_valid(const struct jp_owner *o,unsigned controller,const void *cio,
 const void *nhi,const void *ticket,unsigned cable,unsigned long long now)
{
 return o&&o->consumed&&!o->complete&&!o->failed&&controller>=1&&controller<=2&&
  o->controller==controller&&o->cio==cio&&o->nhi==nhi&&o->ticket==ticket&&
  o->cable==cable&&now<o->deadline&&o->operations<512;
}
static int jp_finish(struct jp_owner *o,int status,unsigned long long now)
{
 if(!o||!o->consumed||o->complete||o->failed)return -1;
 if(status||now>=o->deadline){o->failed=true;return -1;}
 o->complete=true;return 0;
}
#endif
