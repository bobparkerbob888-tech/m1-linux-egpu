import copy,hashlib,itertools,unittest
import five_policy as F
BOOT='PROVISION_TARGET_UUID'
def fixture():
 c=dict(schema=2,boot_id=BOOT,kernel='7.3.0-rc1-j293-router-r54',power_limit_watts=150,thermal_stop_c=85,automatic_retry=False)
 for k in ('kernel_sha256','nvidia_sha256','uvm_sha256','phase30_evidence_sha256'):c[k]=hashlib.sha256(k.encode()).hexdigest()
 for key,bdf,rid,sid,dsn,uid,parts in [
 ('fourth','0002:06:00.0',0x600,1,'PROVISION_PRIVATE_ID_9','PROVISION_TARGET_UUID',('00:00.0','01:00.0','02:01.0','04:00.0','05:00.0','06:00.0')),
 ('fifth','0002:03:00.0',0x300,2,'123456789abcdef0','PROVISION_TARGET_UUID',('00:00.0','01:00.0','02:00.0','03:00.0'))]:
  c[key]=dict(bdf=bdf,rid=rid,sid=sid,dsn=dsn,uuid=uid,host_of_path=F.OF1,enclosure_uids=F.UIDS,sysfs_path=F.HOST1+'pci0002:00/'+'/'.join('0002:'+s for s in parts))
 d=dict(slot=2,devices=[dict(x,minor=i) for i,x in enumerate(F.mining_config(c,BOOT))])
 a=dict(miner_name='krig-miner',miner_version='1.5.6',devices=[dict(index=i,type='gpu',pci_address=x['bdf'][5:],algorithms=[dict(name='pearlhash',hashrate=80e12,shares=dict(accepted=3+i,rejected=0,stale=0))]) for i,x in enumerate(d['devices'])])
 return c,d,a
class Tests(unittest.TestCase):
 def test_api_order_ambiguity(self):
  c,d,a=fixture()
  for order in itertools.permutations(a['devices']):
   v=copy.deepcopy(a);v['devices']=list(copy.deepcopy(order))
   for i,x in enumerate(v['devices']):x['index']=i
   self.assertTrue(F.eligible(v,100,400,80,d,c,BOOT))
   r=F.accepted_records(v,d,c,BOOT)
   self.assertEqual([x['accepted_shares'] for x in r],[3,4,5,4,3])
   self.assertEqual([len(x['api_index_candidates']) for x in r],[2,2,1,2,2])
 def test_every_card_required(self):
  for i in range(5):
   for mode in ('missing','duplicate_index','zero_hash','rejected','bad_address'):
    c,d,a=fixture();x=a['devices'][i]
    if mode=='missing':a['devices'].pop(i)
    if mode=='duplicate_index':x['index']=(i+1)%5
    if mode=='zero_hash':x['algorithms'][0]['hashrate']=0
    if mode=='rejected':x['algorithms'][0]['shares']['rejected']=1
    if mode=='bad_address':x['pci_address']='04:00.0'
    with self.assertRaises(ValueError):F.eligible(a,100,400,80,d,c,BOOT)
   c,d,a=fixture();a['devices'][i]['algorithms'][0]['shares']['accepted']=2
   self.assertFalse(F.eligible(a,100,400,80,d,c,BOOT))
 def test_fifth_identity_and_old_four_pins(self):
  for k,v in [('dsn','0'*16),('dsn','f'*16),('dsn','PROVISION_PRIVATE_ID_9'),('dsn',F.FIRST[0][2]),('uuid',F.FIRST[0][1]),('sid',1),('rid',0x600),('bdf','0001:03:00.0'),('sysfs_path',F.HOST1+'wrong')]:
   c,d,a=fixture();c['fifth'][k]=v
   with self.assertRaises(ValueError):F.mining_config(c,BOOT)
  for key in ('uuid','dsn','bdf'):
   c,d,a=fixture();c['fourth'][key]=c['fifth'][key]
   with self.assertRaises(ValueError):F.mining_config(c,BOOT)
 def test_contexts(self):
  c,d,a=fixture();e=F.mining_config(c,BOOT)
  rows=['2375, '+x['uuid']+', 7830' for x in e]
  self.assertEqual(len(F.compute_contexts('\n'.join(rows),2375,e)),5)
  for i in range(5):
   for mode in ('missing','pid','memory','duplicate'):
    r=list(rows)
    if mode=='missing':r.pop(i)
    if mode=='pid':r[i]=r[i].replace('2375,','2376,')
    if mode=='memory':r[i]=r[i].replace('7830','0')
    if mode=='duplicate':r[i]=r[(i+1)%5]
    with self.assertRaises(ValueError):F.compute_contexts('\n'.join(r),2375,e)
 def test_runtime_thermal(self):
  c,d,a=fixture();self.assertFalse(F.eligible(a,100,399,80,d,c,BOOT))
  for temp in (85,-1,float('nan'),float('inf'),True):
   with self.assertRaises(ValueError):F.eligible(a,100,400,temp,d,c,BOOT)
if __name__=='__main__':unittest.main(verbosity=2)
