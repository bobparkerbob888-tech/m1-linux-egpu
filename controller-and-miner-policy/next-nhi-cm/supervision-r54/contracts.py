"""Strict root-owned R54 artifacts and five-card/two-controller contracts."""
import hashlib,json,math,os,re,stat
from pathlib import Path
import proven_guard as G
KERNEL='7.3.0-rc1-j293-router-r54'
STOCK_BOOT_SHA='dea2de33883e45a5b22cd5cf6bfc38f58194a2a3e0eeacede71c31b3df13cfd4'
FIRST={
 '0001:03:00.0':('PROVISION_TARGET_UUID','PROVISION_PRIVATE_ID_6'),
 '0001:06:00.0':('PROVISION_TARGET_UUID','PROVISION_PRIVATE_ID_7'),
 '0001:09:00.0':('PROVISION_TARGET_UUID','PROVISION_PRIVATE_ID_8')}
def digest(v):return isinstance(v,str) and re.fullmatch('[0-9a-f]{64}',v) is not None and v!='0'*64
def finite(v):return type(v) in (float,int) and math.isfinite(v)
def secure_bytes(path,limit=64*1024*1024):
 p=Path(path)
 if not p.is_absolute():raise RuntimeError('absolute root path required')
 for parent in [p.parent,*p.parents]:
  st=parent.lstat()
  if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:raise RuntimeError('unsafe parent '+str(parent))
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  st=os.fstat(fd)
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode&0o022 or st.st_size>limit:raise RuntimeError('unsafe root artifact')
  with os.fdopen(fd,'rb',closefd=False) as f:data=f.read(limit+1)
  if len(data)>limit:raise RuntimeError('oversized artifact')
  return data
 finally:os.close(fd)
def pinned(item):
 if not isinstance(item,dict) or set(item)!={'path','sha256'} or not digest(item['sha256']):raise RuntimeError('missing artifact pin')
 raw=secure_bytes(item['path'])
 if hashlib.sha256(raw).hexdigest()!=item['sha256']:raise RuntimeError('artifact hash mismatch '+item['path'])
 return raw

def artifacts(a,boot,verify=False):
 if not isinstance(a,dict) or a.get('schema')!=1 or a.get('boot_id')!=boot or a.get('kernel')!=KERNEL:raise RuntimeError('artifact identity')
 for key in ('image','initrd','stock_m1n1','nvidia','uvm'):
  item=a.get(key)
  if not isinstance(item,dict) or not digest(item.get('sha256')) or not isinstance(item.get('path'),str) or not item['path'].startswith('/'):raise RuntimeError('missing '+key)
  if verify:pinned(item)
 if a['stock_m1n1']['sha256']!=STOCK_BOOT_SHA:raise RuntimeError('stock stage2 changed')
 cs=a.get('controllers')
 if not isinstance(cs,list) or len(cs)!=2:raise RuntimeError('two controller artifacts required')
 paths=[]
 for i,c in enumerate(cs):
  if not isinstance(c,dict) or c.get('index')!=i or c.get('phase')!=(22 if i==0 else 30):raise RuntimeError('controller ordering/phase')
  if c.get('module_name')!=('acio_runtime_enable' if i==0 else 'acio_runtime_enable_port1'):raise RuntimeError('module identity')
  for key in ('module','preflight'):
   v=c.get(key)
   if not isinstance(v,dict) or not digest(v.get('sha256')) or not isinstance(v.get('path'),str) or not v['path'].startswith('/'):raise RuntimeError('missing controller pin')
   if verify:pinned(v)
  paths.append(c['module']['path'])
  if verify:
   pf=json.loads(pinned(c['preflight']))
   if not all(digest(pf.get(k)) for k in ('adt_sha256','adt_receipt_sha256','overlay_sha256')) or pf.get('all_controller_properties_equal') is not True or pf.get('all_host_properties_equal') is not True:raise RuntimeError('fresh ADT comparison incomplete')
   if any(pf.get(k)!=v for k,v in {'schema':1,'boot_id':boot,'kernel':KERNEL,'controller':i,'module_sha256':c['module']['sha256'],'image_sha256':a['image']['sha256'],'fresh_adt_payload_verified':True,'stock_fallback_verified':True,'overlay':'efi-disabled-r52'}.items()):raise RuntimeError('fresh controller preflight missing')
 if len(set(paths))!=2 or cs[0]['module']['sha256']==cs[1]['module']['sha256']:raise RuntimeError('distinct modules required')
 return a

def receipts_ok(receipts,m):
 if not isinstance(receipts,list) or len(receipts)!=2:return False
 prior=m['armed_boottime']
 for i,r in enumerate(receipts):
  if not isinstance(r,dict) or any(r.get(k)!=m[k] for k in ('trial_id','boot_id','kernel','nonce')):return False
  if r.get('controller')!=i or r.get('phase')!=(22 if i==0 else 30) or r.get('module_sha256')!=m['artifacts']['controllers'][i]['module']['sha256'] or r.get('status')!='native-ready':return False
  start,end=r.get('started_boottime'),r.get('finished_boottime')
  if not finite(start) or not finite(end) or not prior<=start<=end<m['deadline_boottime'] or not digest(r.get('journal_sha256')):return False
  prior=end
 return True

def seal_ok(seal,m,receipt):
 try:
  import five_policy as F
  F.mining_config(seal,m['boot_id'])
  for k,a in [('kernel_sha256','image'),('nvidia_sha256','nvidia'),('uvm_sha256','uvm')]:
   if seal[k]!=m['artifacts'][a]['sha256']:return False
  if seal['phase30_evidence_sha256']!=receipt['journal_sha256']:return False
  for key,b,s in [('fourth','target_bdf','target_dsn'),('fifth','secondary_bdf','secondary_dsn')]:
   if seal[key]['bdf']!=receipt[b] or seal[key]['dsn']!=receipt[s]:return False
  return True
 except (ValueError,TypeError,KeyError):return False
