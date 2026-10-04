"""Exact controller1 pair proof; local R54 preparation only."""
import re
from five_policy import need,endpoint_config,mining_config,FIRST,HOST1

def phase30(lines,c,boot):
 fourth,fifth=endpoint_config(c,boot)
 records=[x for x in lines if 'pair-native: phase30 ' in x]
 wanted='pair-native: phase30 target'+fourth['bdf']+' serial'+fourth['dsn']+' target'+fifth['bdf']+' serial'+fifth['dsn']+' ready; audio0301/0601 untouched'
 need(len(records)==1 and records[0].endswith(wanted) and '530000000.apciec' in records[0].split('pair-native:')[0],'Missing exact controller1 phase30 pair identity')
 return fourth,fifth

def pci_pair(devices,c,boot,after=False):
 fourth,fifth=endpoint_config(c,boot)
 rids=(0,0x100,0x200,0x300,0x208,0x400,0x500,0x600)
 names={'0002:%02x:%02x.%u'%(r>>8,(r&255)>>3,r&7) for r in rids}
 actual={b for b,v in devices.items() if v['path'].startswith(HOST1)}
 need(actual==names,'Unexpected controller1 function')
 gpu_names={x[0] for x in FIRST}|{fourth['bdf'],fifth['bdf']}
 need({b for b,v in devices.items() if v['vendor']=='0x10de' and int(v['class'],16)>>16==3}==gpu_names,'GPU set is not exactly five')
 groups=[devices[b]['iommu_group'] for b in gpu_names]
 need(all(groups) and len(set(groups))==5,'Nonunique or absent DMA groups')
 for f,addresses in ((fourth,(0x604000000,0x580000000,0x590000000)),(fifth,(0x608000000,0x5a0000000,0x5b0000000))):
  d=devices[f['bdf']]
  for k,v in {'vendor':'0x10de','device':'0x2d04','class':'0x030000','revision':'0xa1','subsystem_vendor':'0x1458','subsystem_device':'0x41cd','path':f['sysfs_path']}.items():need(d.get(k)==v,'Controller1 PCI identity mismatch:'+k)
  need(d['driver']==('/sys/bus/pci/drivers/nvidia' if after else None) and d['override']==('nvidia' if after else 'apple-apciec-native-pending'),'Wrong pair driver ownership')
  if not after:need(d['enable']=='0','GPU enabled before native probe')
  a,b,z=addresses
  expected=[(a,a+0x3ffffff,0x200),(b,b+0xfffffff,0x10220c),(0,0,0),(z,z+0x1ffffff,0x10220c),(0,0,0),(0,0x7f,0x40101),(0,0x7ffff,0x46200)]
  need(len(d['resource'])==13,'Wrong pair resource table')
  for i,want in enumerate(expected):
   got=tuple(d['resource'][i]);got=(got[0],got[1],got[2]&~0x40000) if i in(0,1,3) else got
   need(got==want,'Pair BAR mismatch:'+str(i))
  need(all(x==[0,0,0] for x in d['resource'][7:]),'Extra GPU resource')
 for b in actual-{fourth['bdf'],fifth['bdf']}:
  v=devices[b];need(v['driver'] is None and v['iommu_group'] is None,'Controller1 bridge has unexpected driver/DMA')
  if not after:need(v['enable']=='0','Bridge enabled before probe')

def query_five(rows,information,c,boot):
 fourth,f=endpoint_config(c,boot);targets={b:u for b,u,s in FIRST};targets[fourth['bdf']]=fourth['uuid'];targets[f['bdf']]=f.get('uuid')
 need(len(rows)==5 and all(len(x)==6 for x in rows),'Incomplete five-GPU query')
 seen=set();uids=set();minors=set();result={}
 for raw in rows:
  row=[x.strip() for x in raw];parts=row[0].lower().split(':')
  need(len(parts)==3 and re.fullmatch('[0-9a-f]{4}(?:[0-9a-f]{4})?',parts[0]),'Invalid full PCI identity')
  b=f'{int(parts[0],16):04x}:'+':'.join(parts[1:]);need(b in targets and b not in seen,'Unknown/duplicate NVIDIA GPU');seen.add(b)
  need(re.fullmatch(r'GPU-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',row[1]) and row[1] not in uids,'Invalid/duplicate UUID');uids.add(row[1])
  if targets[b] is not None:need(row[1]==targets[b],'Pinned NVIDIA UUID changed')
  need(row[2]=='615.71.09' and '5060 Ti' in row[3] and row[4].isdigit() and 0<=int(row[4])<85,'Driver/model/thermal mismatch')
  info=information[b];need(re.findall(r'^GPU Firmware:\s+(\S+)\s*$',info,re.M)==['615.71.09'],'GSP firmware mismatch')
  mi=re.findall(r'^Device Minor:\s+([0-4])\s*$',info,re.M);need(len(mi)==1 and int(mi[0]) not in minors,'Invalid NVIDIA minor');minors.add(int(mi[0]))
  result[b]={'bdf':b,'uuid':row[1],'minor':int(mi[0]),'driver_version':row[2],'name':row[3],'temperature_gpu':int(row[4]),'power_draw_watts':row[5],'gsp_firmware_version':'615.71.09','dsn':f['dsn'] if b==f['bdf'] else fourth['dsn'] if b==fourth['bdf'] else next(s for bb,u,s in FIRST if bb==b)}
 need(seen==set(targets) and minors==set(range(5)),'Incomplete five-device NVIDIA inventory')
 return {'devices':[result[b] for b in [x[0] for x in FIRST]+[fourth['bdf'],f['bdf']]],'native_query_verified':True,'fifth_uuid_observed':result[f['bdf']]['uuid']}
