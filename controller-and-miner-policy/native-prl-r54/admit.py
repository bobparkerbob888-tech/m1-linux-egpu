"""Admit one official KRig attempt after actual same-boot NVIDIA/UVM and VPN proof."""
from pathlib import Path
import argparse,hashlib,json,os,stat,subprocess,sys,time
sys.path.insert(0,'/usr/local/lib/bob-native-probe-r54')
import probe as P
import launch as L
V=Path('/var/lib/bob-native-prl-r49')
def read(p):return json.loads(L.root_bytes(p))
def clock():return time.clock_gettime(time.CLOCK_BOOTTIME)
def main():
 a=argparse.ArgumentParser();a.add_argument('--boot-id',required=True);a.add_argument('--nonce',required=True);a.add_argument('--kit-sha256',required=True);a.add_argument('--vpn-sha256',required=True);a=a.parse_args()
 assert os.geteuid()==0 and os.uname().release==P.KERNEL
 assert Path('/proc/sys/kernel/random/boot_id').read_text().strip()==a.boot_id
 assert hashlib.sha256(L.root_bytes(L.HERE/'KIT-PINS.json')).hexdigest()==a.kit_sha256
 endpoint=P.identity()
 g=P.guard_live(a.boot_id,a.nonce,600)
 assert g['deadline_boottime']-g['armed_boottime']==1200
 cpath=P.STATE/('native-probe-'+a.boot_id)/'result.json';c=read(cpath)
 assert c['boot_id']==a.boot_id and c['nonce']==a.nonce and c['outcome']=='query-complete-stock-return-mandatory'
 cr=c['detail'];assert len(cr['devices'])==5;assert cr['native_query_verified'] is True and {d['bdf'] for d in cr['devices']}==set(P.TARGETS)
 ident=cr['identity_config'];assert ident['path']==str(P.STATE/('mining-identity-'+a.boot_id+'.json'))
 P.check_hash(ident['path'],ident['sha256']);config=read(ident['path']);L.F.mining_config(config,a.boot_id)
 assert config['fifth']['uuid']==cr['fifth_uuid_observed']
 assert all(config[k]==endpoint[k] for k in config if k!='fifth')
 assert all(config['fifth'][k]==endpoint['fifth'][k] for k in endpoint['fifth'] if k!='uuid')
 u=read(P.STATE/('native-uvm-direct-'+a.boot_id)/'uvm-ready.json')
 assert u['boot_id']==a.boot_id and u['module_sha256']==config['uvm_sha256'] and u['version']==P.VERSION
 P.validate_pci(P.pci_snapshot(),after=True)
 logs=P.messages(P.journal(),a.boot_id,g['armed_monotonic']);P.validate_ready_logs(logs);P.reject_faults(logs)
 for n in ['retain_prepare','retain_commit','endpoint_native_driver','endpoint_chain_resources','endpoint_pair']:
  assert Path('/sys/module/pcie_apple_apciec_experimental/parameters',n).read_text().strip()=='Y'
 test=read(V/'confinement-test.json')
 assert test['host_unchanged'] and test['unlisted_dns_denied'] and test['loopback_passed'] and len(test['denied_egress'])==3
 vp=Path('/path/to/operator/work/prl-native-20261003/prl-private-r49/vpn-source-proof.json');raw=vp.read_bytes()
 assert hashlib.sha256(raw).hexdigest()==a.vpn_sha256
 source=json.loads(raw);assert 0<=time.time()-source['checked_epoch']<=300
 assert source['vpn_only_fail_closed'] is True and source['authenticated_socks5'] is True
 assert source['proxy']=='PROVISION_NETWORK_ENDPOINT:11182' and source['target']=='prl-hk.kryptex.network:8048'
 assert source['direct_outbound_present'] is False and source['tcp_outbound']=='reality-out/vless' and source['final_action']=='reject'
 d={'slot':2,'devices':[{k:gpu[k] for k in ('bdf','uuid','minor','dsn')} for gpu in cr['devices']]}
 L.F.device_group(d,config,a.boot_id)

 # Each supported 150W cap is applied once before the official miner starts.
 power=P.STATE/('power-caps-'+a.boot_id);power.mkdir(mode=0o700)
 env=dict(P.ENV,LD_LIBRARY_PATH=str(P.RUNTIME/'lib'))
 for gpu in d['devices']:
  P.guard_live(a.boot_id,a.nonce,600)
  key=gpu['bdf'].replace(':','-');base=[str(P.RUNTIME/'bin/nvidia-smi'),'--id='+gpu['uuid']]
  P.bounded_process(base+['--query-gpu=power.min_limit,power.max_limit','--format=csv,noheader,nounits'],power,key+'-bounds',10,env)
  bounds=[float(x.strip()) for x in (power/(key+'-bounds.stdout')).read_text().strip().split(',')]
  assert len(bounds)==2 and bounds[0]<=150<=bounds[1]
  P.bounded_process(base+['--power-limit=150'],power,key+'-set',10,env)
  P.bounded_process(base+['--query-gpu=power.limit','--format=csv,noheader,nounits'],power,key+'-verify',10,env)
  assert float((power/(key+'-verify.stdout')).read_text().strip())==150
 out=V/('admission-'+a.boot_id);out.mkdir(mode=0o700)
 proofs={
  'driver_proof':{'approved':True,'boot_id':a.boot_id,'device':d,'native_query_verified':True,'synthetic_compute_test_run':False,'source_path':str(cpath),'source_sha256':hashlib.sha256(L.root_bytes(cpath)).hexdigest()},
  'owner_proof':{'approved':True,'boot_id':a.boot_id,'device':d,'native_host_retained':True,'mining_lifetime_admitted':True,'guard_reconciled_by_root':True,'lifetime_mode':'1200s bounded trial; continuous only after root validates actual accepted shares and300s running','runtime_guard':g,'kernel_native_phase22_log_verified':True,'no_owner_release':True},
  'vpn_proof':dict(source,approved=True,boot_id=a.boot_id,validated_boottime=clock(),source_sha256=a.vpn_sha256)}
 for proof in ('driver_proof','owner_proof'):
  proofs[proof].update({k:config[k] for k in ('kernel_sha256','nvidia_sha256','uvm_sha256','phase30_evidence_sha256')})
 m={'identity_config':ident,'schema':2,'boot_id':a.boot_id,'stage':'native-prl-five-card-official-trial','approved_boottime':clock(),'device':d,'device_nodes':{}}
 for n in ['/dev/nvidia0','/dev/nvidia1','/dev/nvidia2','/dev/nvidia3','/dev/nvidia4','/dev/nvidiactl','/dev/nvidia-uvm']:
  st=Path(n).lstat();assert stat.S_ISCHR(st.st_mode) and st.st_uid==0
  m['device_nodes'][n]=[os.major(st.st_rdev),os.minor(st.st_rdev)]
 for k,v in proofs.items():
  p=out/(k+'.json');p.write_text(json.dumps(v,indent=2)+'\n');p.chmod(0o600)
  m[k]={'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
 p=out/'manifest.json';p.write_text(json.dumps(m,indent=2)+'\n');p.chmod(0o600)
 L.manifest_check(m,a.boot_id,clock());L.static_preflight(m,a.kit_sha256)
 fds=[os.open(p,os.O_RDONLY|os.O_NOFOLLOW),os.open(V/'account-source.py',os.O_RDONLY|os.O_NOFOLLOW),os.open(V/'socks.json',os.O_RDONLY|os.O_NOFOLLOW)]
 for fd in fds:os.set_inheritable(fd,True)
 args=['/usr/bin/python3',str(L.HERE/'launch.py'),'--manifest-fd',str(fds[0]),'--account-source-fd',str(fds[1]),'--socks-credentials-fd',str(fds[2]),'--kit-sha256',a.kit_sha256]
 os.execv(args[0],args)
if __name__=='__main__':main()
