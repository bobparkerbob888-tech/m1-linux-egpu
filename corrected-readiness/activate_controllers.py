#!/usr/bin/python3
"""One cold-boot attempt per controller; no reset, unload, retry, or ACK."""
import fcntl,json,hashlib,os,re,subprocess,time
from pathlib import Path
import runtime_guard as R
import proven_guard as G
import contracts as C

def exclusive(path,value):
 raw=(json.dumps(value,sort_keys=True)+'\n').encode()
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(fd,'wb',closefd=False) as f:f.write(raw);f.flush();os.fsync(f.fileno())
 finally:os.close(fd)
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
 return hashlib.sha256(raw).hexdigest()

# Two independent asynchronous log sequences are ordered internally only.
# external_outer_complete_port() queues work before the activation caller
# prints outer/apply. Their printed position relative to the worker is not
# a synchronization contract. Never require worker terminal before apply.
def terminal(rows,index):
 text='\n'.join(str(x[1]) for x in rows)
 if re.search(r'SError|Kernel panic|(?:DART|IOMMU).*fault|Unable to handle kernel|\bOops\b|\bBUG\s*:|watchdog.*(?:lockup|stall)|(?:soft|hard)\s+lockup|rcu.*stall|stall.*rcu',text,re.I):raise RuntimeError('kernel failure')
 def matches(pattern):return [(i,re.search(pattern,t)) for i,(_,t) in enumerate(rows) if re.search(pattern,t)]
 attempts=matches(r'platform-only: consuming sole boot attempt')
 if index not in (0,1) or len(attempts)!=1:return None
 starts=matches(rf'ACIO activation: applying fixed port{index} authenticated-tunables overlay once')
 outer=matches(r'ACIO activation: external outer-return barrier status (-?\d+)')
 ends=matches(r'ACIO activation: apply result (-?\d+) overlay -?\d+; retained until reboot')
 if any(len(x)!=1 for x in (starts,outer,ends)) or outer[0][1][1]!='0' or ends[0][1][1]!='0' or not starts[0][0]<outer[0][0]<ends[0][0]:return None
 if index==0:
  native=matches(r'3b0000000\.apciec: chain-native: status0 phase22 step[^ ]+ functions22; all owners retained')
  # Exact count comes from existing AM_FUNCTIONS; root must not relax this.
  final=matches(r'retained-native-driver: terminal status 0 phase 22; retained until stock reboot; selected GPU driver pending')
  if len(native)!=1 or len(final)!=1 or not starts[0][0]<attempts[0][0]<native[0][0]<final[0][0]:return None
  return {'phase':22}
 outer_native=matches(r'pair-native-driver: outer status0 native-audit0 tunnel-proof0 phase30; targets0600\+0300 only')
 terminal_native=matches(r'retained-controller1-pair: terminal status 0 phase 30; targets0600\+0300 only; audio0301/0601 excluded')
 if len(outer_native)!=1 or len(terminal_native)!=1:return None
 native=matches(r'530000000\.apciec: pair-native: phase30 target(0002:06:00\.0) serial(PROVISION_PRIVATE_ID_9) target(0002:03:00\.0) serial([0-9a-f]{16}) ready; audio0301/0601 untouched')
 if len(native)!=1:return None
 b,d,b2,d2=native[0][1].groups()
 if int(d2,16) in (0,2**64-1) or d2 in [d,*[v[1] for v in C.FIRST.values()]]:return None
 if not starts[0][0]<attempts[0][0]<native[0][0]<outer_native[0][0]<terminal_native[0][0]:return None
 return {'phase':30,'target_bdf':b,'target_dsn':d,'secondary_bdf':b2,'secondary_dsn':d2}

def journal(boot,since):
 raw=subprocess.check_output(['/usr/bin/journalctl','-k','-b','0','-o','json','--no-pager'],timeout=15,text=True)
 rows=[]
 for line in raw.splitlines():
  r=json.loads(line)
  if r.get('_BOOT_ID')!=boot.replace('-',''):continue
  when=int(r['__MONOTONIC_TIMESTAMP'])/1e6
  if when>=since:rows.append([when,str(r.get('MESSAGE',''))])
 return rows

def active_guard(m):
 if R.boot()!=m['boot_id'] or os.uname().release!=R.KERNEL or R.clock()>=m['deadline_boottime']-350:raise RuntimeError('boot/deadline rejected')
 ready=G.read_json_file(R.RUN/'ready.json',0)
 if not ready or any(ready.get(k)!=v for k,v in R.expected(m).items()):raise RuntimeError('guard not ready')
 subprocess.run(['/usr/bin/systemctl','is-active','--quiet',R.UNIT],timeout=5,check=True)
 if any(Path('/sys/module/'+s).exists() for s in ('nvidia','nvidia_uvm')):raise RuntimeError('NVIDIA loaded too early')

def module_argv(path):return ['/usr/sbin/insmod',path,'arm=1']

def main():
 if os.geteuid()!=0:raise RuntimeError('root required')
 m=G.read_json_file(R.MANIFEST,0)
 if not R.valid_manifest(m,R.boot(),os.uname().release):raise RuntimeError('invalid guard manifest')
 C.artifacts(m['artifacts'],m['boot_id'],verify=True)
 with open(R.RUN/'activation.lock','a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  for i,c in enumerate(m['artifacts']['controllers']):
   active_guard(m)
   if Path('/sys/module/'+c['module_name']).exists():raise RuntimeError('module already consumed; no retry')
   if i:
    first=G.read_json_file(R.STATE/f"controller-0-{m['boot_id']}.json",0)
    if not first or first.get('phase')!=22 or first.get('status')!='native-ready' or first.get('nonce')!=m['nonce']:raise RuntimeError('controller0 not ready')
   now=R.clock();mono=time.clock_gettime(time.CLOCK_MONOTONIC)
   attempt=dict(R.expected(m),schema=1,controller=i,started_boottime=now,started_monotonic=mono,module_sha256=c['module']['sha256'])
   exclusive(R.STATE/f"controller-{i}-attempt-{m['boot_id']}.json",attempt)
   C.pinned(c['module'])
   # Preserve an in-flight loader: only the normal guard reboot releases it.
   logpath=R.STATE/f"controller-{i}-loader-{m['boot_id']}.log"
   fd=os.open(logpath,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   try:
    loader=subprocess.Popen(module_argv(c['module']['path']),stdin=subprocess.DEVNULL,stdout=fd,stderr=fd,start_new_session=True)
   finally:os.close(fd)
   exclusive(R.STATE/f"controller-{i}-loader-{m['boot_id']}.json",dict(R.expected(m),controller=i,pid=loader.pid,module_sha256=c['module']['sha256']))
   try:code=loader.wait(timeout=90)
   except subprocess.TimeoutExpired:
    raise RuntimeError('module activation still in flight; loader retained, guard remains armed, no retry')
   if code:raise RuntimeError('module activation failed; guard remains armed, no retry')
   proof=None
   while R.clock()<min(now+120,m['deadline_boottime']-350):
    rows=journal(m['boot_id'],mono);proof=terminal(rows,i)
    if proof:break
    time.sleep(.5)
   if not proof:raise RuntimeError('native proof absent; guard remains armed')
   payload=dict(R.expected(m),schema=1,controller=i,rows=rows)
   pin=exclusive(R.STATE/f"controller-{i}-journal-{m['boot_id']}.json",payload)
   receipt=dict(R.expected(m),schema=1,controller=i,status='native-ready',module_sha256=c['module']['sha256'],started_boottime=now,finished_boottime=R.clock(),journal_sha256=pin,**proof)
   exclusive(R.STATE/f"controller-{i}-{m['boot_id']}.json",receipt)
   print(json.dumps(receipt),flush=True)
  receipts=[G.read_json_file(R.STATE/f"controller-{i}-{m['boot_id']}.json",0) for i in range(2)]
  if not C.receipts_ok(receipts,m):raise RuntimeError('combined controller proof rejected')
  exclusive(R.STATE/f"controllers-ready-{m['boot_id']}.json",dict(R.expected(m),schema=1,controllers=receipts,official_mining_acknowledged=False))
 return 0
if __name__=='__main__':raise SystemExit(main())
