/* SPDX-License-Identifier: GPL-2.0 */
#ifndef JMN_MSI_OWNER_H
#define JMN_MSI_OWNER_H
/* Use under real shared MSI allocator mutex. Parent irq_domain/AIC2 proof and
 * irq_data/descriptor/action checks remain mandatory adapter obligations. */
struct jmn_msi_owner {const struct jmn_owner*n;const void*domain;unsigned virq[32],client[32];bool failed;};
static int jmn_msi_client(const struct jmn_msi_owner*m,const void*device)
{
 if(!m||!m->n||!m->domain||m->failed||m->n->failed||!m->n->complete||
    m->n->phase!=JMN_PUBLISHED||m->n->evidence.msi!=m->domain||
    !m->n->io->valid(m->n->io->ctx,true))return -1;
 for(unsigned j=0;j<m->n->plan.count;j++)if(device&&device==m->n->evidence.device[j])return j;
 return -1;
}
static int jmn_msi_claim(struct jmn_msi_owner*m,const void*device,unsigned base,unsigned irq,unsigned count)
{
 int client=jmn_msi_client(m,device);
 if(client<0||!count||count>32||base>32-count||!irq||irq>~0U-count+1)return -EPERM;
 for(unsigned j=0;j<count;j++){
  if(m->virq[base+j])return -EBUSY;
  for(unsigned k=0;k<32;k++)if(m->virq[k]==irq+j)return -EPERM;
 }
 for(unsigned j=0;j<count;j++){m->virq[base+j]=irq+j;m->client[base+j]=client+1;}
 return 0;
}
static int jmn_msi_owned(const struct jmn_msi_owner*m,const void*device,unsigned local,unsigned irq)
{
 int client=jmn_msi_client(m,device);
 return client>=0&&local<32&&irq&&m->virq[local]==irq&&m->client[local]==(unsigned)client+1?0:-EPERM;
}
static int jmn_msi_release(struct jmn_msi_owner*m,const void*device,unsigned local,unsigned irq)
{
 /* Release is exact matching metadata cleanup; does not release DMA owners or
  * authorize retries. May follow a latched failure while module unwinds. */
 if(!m||!m->n||local>=32||!irq||m->virq[local]!=irq||!m->client[local]||
    m->client[local]>m->n->plan.count||m->n->evidence.device[m->client[local]-1]!=device)return -EPERM;
 m->virq[local]=0;m->client[local]=0;return 0;
}
#endif
