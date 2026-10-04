#!/usr/bin/python3
"""Root-owned one-shot controller trial. No loader, boot selection or retries."""
import fcntl, hashlib, json, math, os, subprocess, sys, tempfile, time
from pathlib import Path
import proven_guard as G
import contracts as C
TRIAL='oldm1-acio-router54-20261004'
KERNEL='7.3.0-rc1-j293-router-r54'
RUN=Path('/run/bob-acio-router54-trial')
STATE=Path('/var/lib/bob-acio-router54-trial')
MANIFEST=RUN/'manifest.json'
UNIT='bob-acio-router54-trial'

def clock(): return time.clock_gettime(time.CLOCK_BOOTTIME)
def boot(): return Path('/proc/sys/kernel/random/boot_id').read_text().strip()
def expected(m): return {k:m[k] for k in ('trial_id','boot_id','kernel','nonce')}
def valid_manifest(m,boot_id,kernel):
 if not isinstance(m,dict): return False
 if m.get('trial_id')!=TRIAL or m.get('boot_id')!=boot_id or m.get('kernel')!=kernel or kernel!=KERNEL:return False
 a=m.get('armed_boottime');d=m.get('deadline_boottime');mono=m.get('armed_monotonic')
 if type(a) not in (float,int) or type(d) not in (float,int) or type(mono) not in (float,int):return False
 if not math.isfinite(a) or not math.isfinite(d) or not math.isfinite(mono) or a<0 or mono<0 or mono>a+0.01 or abs(d-a-1200)>1e-6:return False
 if not isinstance(m.get('nonce'),str) or len(m['nonce'])!=32:return False
 try:C.artifacts(m.get('artifacts'),boot_id)
 except (RuntimeError,TypeError,KeyError):return False
 return m.get('hardware_watchdog_confirmed') is True


def mining_ack(a,m,now,receipts=None,seal=None):
 if not isinstance(a,dict) or any(a.get(k)!=v for k,v in expected(m).items()):return None
 if a.get('phase')!='official-krig-five-card-mining' or a.get('official_miner_compute_verified') is not True:return None
 if not C.receipts_ok(receipts,m) or not C.seal_ok(seal,m,receipts[1]):return None
 devices=a.get('devices',[])
 if not isinstance(devices,list) or len(devices)!=5 or any(not isinstance(d,dict) for d in devices):return None
 expected_devices=dict(C.FIRST);f=seal['fourth'];expected_devices[f['bdf']]=(f['uuid'],f['dsn']);f=seal['fifth'];expected_devices[f['bdf']]=(f['uuid'],f['dsn'])
 seen=set();uuids=set();indices=set()
 for d in devices:
  bdf=d.get('bdf');uid=d.get('uuid');dsn=d.get('dsn');idx=d.get('index')
  if not isinstance(bdf,str) or bdf in seen or bdf not in expected_devices or (uid,dsn)!=expected_devices[bdf] or uid in uuids:return None
  if type(idx)is not int or not 0<=idx<5 or idx in indices:return None
  seen.add(bdf);uuids.add(uid);indices.add(idx)
  if type(d.get('accepted_shares'))is not int or d['accepted_shares']<3 or type(d.get('rejected_shares'))is not int or d['rejected_shares']!=0:return None
 values=[a.get('approved_boottime'),a.get('miner_started_boottime'),a.get('temperature_c')]
 if any(not C.finite(v) for v in values):return None
 approved,started,temp=values
 if not receipts[1]['finished_boottime']<=started<=approved-300 or not 0<=now-approved<=60 or not 0<=temp<85 or approved>=m['deadline_boottime']:return None
 if not C.digest(a.get('validation_sha256')):return None
 return expected(m)

def read_mining_ack(m):
 try:
  receipts=[]
  for i in range(2):
   r=G.read_json_file(STATE/f"controller-{i}-{m['boot_id']}.json",0)
   if not r:return None
   raw=C.secure_bytes(STATE/f"controller-{i}-journal-{m['boot_id']}.json")
   if hashlib.sha256(raw).hexdigest()!=r.get('journal_sha256'):return None
   receipts.append(r)
  seal=G.read_json_file(STATE/f"mining-identity-{m['boot_id']}.json",0)
  a=G.read_json_file(RUN/'mining-ack.json',0)
  result=mining_ack(a,m,clock(),receipts,seal)
  if not result:return None
  # Validate the actual immutable proof, not an ACK containing a free-form hash.
  raw=C.secure_bytes(STATE/f"official-mining-validation-{m['boot_id']}.json")
  if hashlib.sha256(raw).hexdigest()!=a['validation_sha256']:return None
  proof=json.loads(raw)
  if any(proof.get(k)!=a.get(k) for k in ('boot_id','kernel','devices')):return None
  return result
 except (OSError,ValueError,RuntimeError,KeyError,TypeError):return None


def atomic(path,value):
 fd,tmp=tempfile.mkstemp(prefix='.atomic-',dir=path.parent)
 try:
  with os.fdopen(fd,'w') as f:
   os.fchmod(f.fileno(),0o600);json.dump(value,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
  os.replace(tmp,path)
  fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
  try:os.fsync(fd)
  finally:os.close(fd)
 finally:
  if os.path.exists(tmp):os.unlink(tmp)

def main():
 if os.geteuid()!=0:raise RuntimeError('root required')
 m=G.read_json_file(MANIFEST,0)
 if not valid_manifest(m,boot(),os.uname().release):raise RuntimeError('manifest identity/deadline rejected')
 # No directories are created on an unrelated boot. Arm owns directory setup.
 for p in (RUN,STATE):G.prepare_directory(p,0,0,0o700,{0})
 with open(RUN/'guard.lock','a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  ident=expected(m);previous=G.read_json_file(STATE/'result.json',0)
  # A root-validated official-miner acceptance ends this one-time admission guard.
  if isinstance(previous,dict) and all(previous.get(k)==v for k,v in ident.items()) and previous.get('outcome') in G.TERMINAL:return 0
  atomic(RUN/'ready.json',dict(ident,deadline_boottime=m['deadline_boottime'],guard_pid=os.getpid()))
  outcome=G.run_guard(ident,clock,lambda:read_mining_ack(m),time.sleep,lambda v:atomic(STATE/'result.json',v),G.normal_reboot,previous,deadline=m['deadline_boottime'])
  print('ACIO runtime guard: '+outcome,flush=True)
 return 0
if __name__=='__main__':sys.exit(main())
