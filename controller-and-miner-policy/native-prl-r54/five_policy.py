"""Five exact GPUs across two controllers; no hardware access or discovery fallback."""
import math,re,csv,io
from collections import Counter
FIRST = (
 ('0001:03:00.0','PROVISION_TARGET_UUID','PROVISION_PRIVATE_ID_6'),
 ('0001:06:00.0','PROVISION_TARGET_UUID','PROVISION_PRIVATE_ID_7'),
 ('0001:09:00.0','PROVISION_TARGET_UUID','PROVISION_PRIVATE_ID_8'))
HOST1='/sys/devices/platform/soc/530000000.apciec/'
OF1='/soc/apciec@530000000'
UIDS=['PROVISION_PRIVATE_ID_4','PROVISION_PRIVATE_ID_5']
UUID=r'GPU-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
SHA=r'[0-9a-f]{64}'
def match(pattern,value):return isinstance(value,str) and re.fullmatch(pattern,value)
def need(ok,msg):
 if not ok:raise ValueError(msg)
def endpoint_config(c,boot):
 need(c.get('schema')==2 and c.get('boot_id')==boot and match(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',boot or ''),'Fresh explicit boot required')
 need(c.get('kernel')=='7.3.0-rc1-j293-router-r54','Exact R54 release required')
 for key in ('kernel_sha256','nvidia_sha256','uvm_sha256','phase30_evidence_sha256'):
  need(match(SHA,c.get(key,'')) and len(set(c[key]))>1,'Fresh artifact/evidence pin required: '+key)
 need(c.get('power_limit_watts')==150 and c.get('thermal_stop_c')==85 and c.get('automatic_retry') is False,'Tune/thermal/retry changed')
 fourth=c.get('fourth',{});fifth=c.get('fifth',{})
 need(fourth.get('bdf')=='0002:06:00.0' and fourth.get('dsn')=='PROVISION_PRIVATE_ID_9' and fourth.get('uuid')=='PROVISION_TARGET_UUID','Winning fourth identity changed')
 for f,rid,sid,parts in ((fourth,0x600,1,('00:00.0','01:00.0','02:01.0','04:00.0','05:00.0','06:00.0')),(fifth,0x300,2,('00:00.0','01:00.0','02:00.0','03:00.0'))):
  need(f.get('host_of_path')==OF1 and f.get('enclosure_uids')==UIDS and f.get('rid')==rid and f.get('sid')==sid,'Wrong controller1 pair identity')
  need(f.get('bdf')=='0002:'+parts[-1],'Wrong exact second-controller BDF')
  need(f.get('sysfs_path')==HOST1+'pci0002:00/'+'/'.join('0002:'+v for v in parts),'Wrong exact branch PCI path')
 serial=fifth.get('dsn','');need(match('[0-9a-f]{16}',serial) and serial not in ['0'*16,'f'*16,fourth['dsn'],*[x[2] for x in FIRST]],'Fresh distinct fifth DSN required')
 return fourth,fifth

def mining_config(c,boot):
 fourth,fifth=endpoint_config(c,boot);uid=fifth.get('uuid','')
 need(match(UUID,uid) and uid not in [fourth['uuid'],*[x[1] for x in FIRST]],'Explicit queried fifth UUID required')
 return [{'bdf':b,'uuid':u,'dsn':s} for b,u,s in FIRST]+[{k:f[k] for k in ('bdf','uuid','dsn')} for f in (fourth,fifth)]

def device_group(d,c,boot):
 expected=mining_config(c,boot);devs=d.get('devices',[])
 need(d.get('slot')==2 and len(devs)==5,'Exactly five selected cards required')
 need({x.get('minor') for x in devs}==set(range(5)) and all(type(x.get('minor'))is int for x in devs),'Unique exact device minors required')
 # Physical identity order is significant for CUDA selection, not KRig API indices.
 for i,(got,want) in enumerate(zip(devs,expected)):
  need(all(got.get(k)==v for k,v in want.items()),'Pinned UUID/BDF/DSN order changed at index'+str(i))
 return expected

def eligible(api,started,now,temperature,d,c,boot):
 expected=device_group(d,c,boot)
 need(api.get('miner_name')=='krig-miner' and api.get('miner_version')=='1.5.6','Official KRig1.5.6 required')
 cards=api.get('devices',[]);need(len(cards)==5,'Missing GPU API record')
 need(all(type(x.get('index'))is int for x in cards) and {x['index'] for x in cards}==set(range(5)),'Missing or duplicate GPU API index')
 need(all(type(x)in(int,float) and math.isfinite(x) for x in (started,now,temperature)) and 0<=started<=now and 0<=temperature<85,'Unsafe observation')
 ready=now-started>=300
 need(Counter(x.get('pci_address') for x in cards)==Counter(x['bdf'][5:] for x in expected),'API short-address multiplicity differs from exact physical inventory')
 for x in cards:
  need(x.get('type')=='gpu','Non-GPU API record')
  alg=x.get('algorithms',[]);need(len(alg)==1 and alg[0].get('name')=='pearlhash','Wrong algorithm')
  a=alg[0];v=a.get('hashrate');need(type(v)in(int,float) and math.isfinite(v) and v>0,'No actual per-card hashrate')
  shares=a.get('shares',{});need(all(type(shares.get(k))is int and shares[k]>=0 for k in ('accepted','rejected','stale')),'Invalid shares')
  need(shares['rejected']==0,'Rejected shares require review');ready=ready and shares['accepted']>=3
 return ready

def accepted_records(api,d,c,boot):
 expected=device_group(d,c,boot);cards=api['devices']
 need(len(cards)==5 and all(type(x.get('index')) is int for x in cards) and {x['index'] for x in cards}==set(range(5)),'Incomplete API index inventory')
 need(Counter(x.get('pci_address') for x in cards)==Counter(x['bdf'][5:] for x in expected),'Incorrect API address multiplicity')
 result=[]
 for slot,x in enumerate(expected):
  candidates=[v for v in cards if v['pci_address']==x['bdf'][5:]]
  accepted=[v['algorithms'][0]['shares']['accepted'] for v in candidates]
  rejected=[v['algorithms'][0]['shares']['rejected'] for v in candidates]
  need(all(type(v)is int and v>=3 for v in accepted) and all(type(v)is int and v==0 for v in rejected),'Every candidate must independently satisfy acceptance')
  result.append(dict(x,index=slot,index_kind='physical_identity_slot',api_index_candidates=sorted(v['index'] for v in candidates),accepted_shares=min(accepted),accepted_shares_kind='minimum_over_matching_short_address',rejected_shares=0,api_uuid_mapping_proven=len(candidates)==1))
 return result

def compute_contexts(text,miner_pid,expected):
 need(type(miner_pid)is int and miner_pid>1,'Invalid miner PID')
 uuids={x['uuid'] for x in expected};need(len(uuids)==5,'Five unique UUIDs required')
 records=[]
 for row in csv.reader(io.StringIO(text)):
  if not row:continue
  need(len(row)==3,'Malformed compute context row')
  pid,uuid,memory=[v.strip() for v in row]
  need(pid.isdecimal() and memory.isdecimal(),'Unknown compute context PID or memory')
  need(int(pid)==miner_pid and uuid in uuids and int(memory)>0,'Unexpected PID, UUID or empty compute memory')
  records.append({'pid':int(pid),'uuid':uuid,'used_gpu_memory_mib':int(memory)})
 need(len(records)==5 and {v['uuid'] for v in records}==uuids,'Missing or duplicate physical GPU compute context')
 return sorted(records,key=lambda v:v['uuid'])
