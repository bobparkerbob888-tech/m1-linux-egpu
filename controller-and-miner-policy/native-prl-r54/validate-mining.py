"""Validate real same-boot shares, then acknowledge existing guard exactly once."""
from pathlib import Path
import argparse, hashlib, json, math, os, re, subprocess, sys, time
sys.path.insert(0,'/usr/local/lib/bob-native-probe-r54')
import probe as P
sys.path.insert(0,'/usr/local/lib/bob-native-prl-r54')
import launch as L
sys.path.insert(0,'/usr/local/lib/bob-acio-router54-trial')
import runtime_guard as G
import importlib.util
# Original launch/probe import their original policy; only this validator uses the new proof policy.
_spec=importlib.util.spec_from_file_location('acceptance_five_policy',Path(__file__).resolve().parent/'five_policy.py')
F=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(F)

def query_compute_contexts(pid,expected,receipt_started):
    started=clock()
    def identity():
        statrow=Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()
        ticks=int(statrow[19]);exe=os.readlink('/proc/'+str(pid)+'/exe')
        assert exe==str(L.MINER/'krig-miner')
        assert 0<=receipt_started-ticks/os.sysconf('SC_CLK_TCK')<5
        return {'pid':pid,'starttime_ticks':ticks,'exe':exe}
    before=identity()
    raw_manifest=L.root_bytes(L.RUNTIME/'MANIFEST.json')
    assert hashlib.sha256(raw_manifest).hexdigest()==L.RUNTIME_MANIFEST_SHA
    runtime=json.loads(raw_manifest)
    assert hashlib.sha256(L.root_bytes(L.RUNTIME/'bin/nvidia-smi')).hexdigest()==runtime['files']['nvidia-smi']['sha256']
    args=[str(L.RUNTIME/'bin/nvidia-smi'),'--query-compute-apps=pid,gpu_uuid,used_gpu_memory','--format=csv,noheader,nounits']
    p=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=L.ENV)
    try:raw,err=p.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        L.RETAINED_QUERIES.append(p)
        raise RuntimeError('Readonly context query timed out; owner retained, no retry or signal') from None
    assert p.returncode==0 and 0<=clock()-started<5
    contexts=F.compute_contexts(raw.decode(),pid,expected)
    assert identity()==before
    return {'source':'pinned_nvidia_smi_readonly_compute_apps','process_identity':before,'argv':args,'miner_pid':pid,'observed_boottime':clock(),'contexts':contexts,'raw':raw.decode()}


def read(p):return json.loads(L.root_bytes(p))
def clock():return time.clock_gettime(time.CLOCK_BOOTTIME)
def metric(text, name):
    rows=[line for line in text.splitlines() if line.startswith(name+' ')]
    assert len(rows)==1, name
    value=float(rows[0].split()[-1]);assert math.isfinite(value)
    return value

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--boot-id',required=True);ap.add_argument('--nonce',required=True);a=ap.parse_args()
    assert os.geteuid()==0 and os.uname().release==P.KERNEL
    assert Path('/proc/sys/kernel/random/boot_id').read_text().strip()==a.boot_id
    P.identity()
    root=Path(__file__).resolve().parent
    pins=read(root/'pins.json')
    for n,h in pins.items():assert hashlib.sha256(L.root_bytes(root/n)).hexdigest()==h
    work=Path('/run/bob-native-prl-'+a.boot_id)
    g=P.guard_live(a.boot_id,a.nonce,30)
    assert not (G.RUN/'mining-ack.json').exists()
    while clock()<g['deadline_boottime']-30:
        assert Path('/proc/sys/kernel/random/boot_id').read_text().strip()==a.boot_id
        assert not (work/'result.json').exists(), 'Miner has stopped'
        r=read(work/'running.json');assert r['boot_id']==a.boot_id and r['cutoff_c']==85
        assert r['device']['slot']==2 and {d['bdf'] for d in r['device']['devices']}==set(P.TARGETS)
        assert len(r['device']['devices'])==5
        ident=r['identity_config'];raw=L.root_bytes(ident['path']);assert hashlib.sha256(raw).hexdigest()==ident['sha256']
        config=json.loads(raw);F.device_group(r['device'],config,a.boot_id)
        expected_env=','.join(x['uuid'] for x in r['device']['devices']);assert r['cuda_visible_devices']==expected_env
        sup=r['supervisor_pid'];mp=r['miner_pid']
        assert os.readlink('/proc/'+str(sup)+'/ns/net')==r['network_namespace']
        assert os.readlink('/proc/'+str(mp)+'/ns/net')==r['network_namespace']
        assert os.readlink('/proc/'+str(mp)+'/exe')==str(L.MINER/'krig-miner')
        env=dict(x.split(b'=',1) for x in Path('/proc/'+str(mp)+'/environ').read_bytes().split(b'\0') if b'=' in x)
        assert env.get(b'CUDA_VISIBLE_DEVICES')==expected_env.encode() and env.get(b'CUDA_DEVICE_ORDER')==b'PCI_BUS_ID'
        status=Path('/proc/'+str(mp)+'/status').read_text()
        assert re.search(r'^Uid:\s+65534\s+65534\s+65534\s+65534$',status,re.M)
        assert re.search(r'^PPid:\s+'+str(sup)+r'$',status,re.M)
        assert re.search(r'^NoNewPrivs:\s+1$',status,re.M)
        service=subprocess.check_output(['systemctl','show','bob-native-prl-r54','--property=MainPID,ActiveState,SubState'],text=True)
        assert 'MainPID='+str(sup)+'\n' in service and 'ActiveState=active\n' in service and 'SubState=running\n' in service
        c="import json,socket,urllib.request;assert {n for _,n in socket.if_nameindex()}=={'lo'};o=urllib.request.build_opener(urllib.request.ProxyHandler({}));print(json.dumps({'api':json.loads(o.open('http://PROVISION_NETWORK_ENDPOINT:12002/',timeout=3).read(65536)),'metrics':o.open('http://PROVISION_NETWORK_ENDPOINT:12002/metrics',timeout=3).read(65536).decode()}))"
        data=json.loads(subprocess.check_output(['nsenter','-t',str(sup),'-n','python3','-c',c],text=True,timeout=8))
        temp=L.query_temperature(r['device']);now=clock()
        accepted={d['index']:d['algorithms'][0]['shares']['accepted'] for d in data['api']['devices']}
        print(json.dumps({'status':'observing','runtime_seconds':now-r['started_boottime'],'accepted_shares':accepted,'temperature_c':temp}),flush=True)
        if not F.eligible(data['api'],r['started_boottime'],now,temp,r['device'],config,a.boot_id):time.sleep(20);continue
        metrics=data['metrics']
        for gpu in data['api']['devices']:
            index=str(gpu['index'])
            assert metric(metrics,'krig_miner_blocks_submitted_total{gpu="'+index+'",result="accepted"}')>=accepted[gpu['index']]
            assert metric(metrics,'krig_miner_blocks_submitted_total{gpu="'+index+'",result="rejected"}')==0
            assert 0<=metric(metrics,'krig_miner_heartbeat_age_seconds{gpu="'+index+'"}')<5
        assert metric(metrics,'krig_miner_pool_connected')==1
        vp=Path('/path/to/operator/work/prl-native-20261003/prl-private-r49/vpn-source-proof.json')
        vraw=vp.read_bytes();vpn=json.loads(vraw)
        if not 0<=time.time()-vpn['checked_epoch']<=300:
            print('Waiting for fresh VPN source verification',flush=True);time.sleep(15);continue
        assert vpn['vpn_only_fail_closed'] is True and vpn['authenticated_socks5'] is True and vpn['direct_outbound_present'] is False
        assert vpn['proxy']=='PROVISION_NETWORK_ENDPOINT:11182' and vpn['target']=='prl-hk.kryptex.network:8048' and vpn['tcp_outbound']=='reality-out/vless' and vpn['final_action']=='reject'
        g=P.guard_live(a.boot_id,a.nonce,20)
        P.validate_pci(P.pci_snapshot(),after=True)
        pci_after=P.pci_readonly_snapshot()
        for target in P.TARGETS:
            link=int(pci_after['devices'][target]['070'],16)
            assert ((link>>16)&15)==1 and (link&3)==0
        logs=P.messages(P.journal(),a.boot_id,g['armed_monotonic']);P.validate_ready_logs(logs);P.reject_faults(logs)
        obs=P.STATE/('address-observation-'+a.boot_id)/'samples.jsonl'
        samples=L.root_bytes(obs).splitlines();last=json.loads(samples[-1])
        assert last['boot_id']==a.boot_id and last['nonce']==a.nonce and 0<=clock()-last['boottime']<=5
        assert int(last['port_readonly']['0x100'],16)==0x1000
        observer=read(obs.parent/'ready.json')
        assert observer['boot_id']==a.boot_id and observer['nonce']==a.nonce and observer['read_only'] is True
        assert last['host_bases']==observer['host_bases']==['0x3a1000000','0x521000000']
        assert set(last['port1_readonly'])=={'0x80','0x100','0x208','0x240','0x244','0x284','0x288','0x28c','0x290','0x800'}
        status1=int(last['port1_readonly']['0x100'],16)
        assert status1==int(observer['initial_port1']['0x100'],16) and status1!=0xffffffff and not status1&((1<<26)|(1<<25)|(1<<23)|(1<<21))
        assert str(L.HERE/'observe-address.py').encode() in Path('/proc/'+str(observer['pid'])+'/cmdline').read_bytes().split(b'\0')
        for n,h in L.PINS.items():assert hashlib.sha256(L.root_bytes(L.MINER/n)).hexdigest()==h
        for base in [L.HERE]:
            for n,h in read(base/'KIT-PINS.json').items():assert hashlib.sha256(L.root_bytes(base/n)).hexdigest()==h
        account=L.extract_account(L.root_bytes(Path('/var/lib/bob-native-prl-r49/account-source.py')))
        rawlog=L.root_bytes(work/'miner.log');log=rawlog.decode(errors='replace')
        for gpu in data['api']['devices']:assert log.count('share accepted: GPU'+str(gpu['index']))>=3
        assert 'connected: '+L.POOL in log and not re.search(r'cuDevicePrimaryCtxRetain|worker failed|CUDA error|retry in',log,re.I)
        assert not (work/'result.json').exists()
        physical_compute=query_compute_contexts(mp,F.device_group(r['device'],config,a.boot_id),r['started_boottime'])
        proof={'physical_compute_contexts':physical_compute,'index_semantics':'physical_identity_slot; API association carried only by api_index_candidates; duplicate short-address counts are conservative lower bounds','boot_id':a.boot_id,'kernel':P.KERNEL,'devices':F.accepted_records(data['api'],r['device'],config,a.boot_id),'nonce':a.nonce,'runtime':r,'api':data['api'],'metrics':metrics,'temperature_c':temp,'observed_boottime':clock(),'port_last_sample':last,'both_controller_pci_config':pci_after,'identity_config':ident,'kernel_faults_absent':True,'kernel_messages_sha256':hashlib.sha256(json.dumps(logs).encode()).hexdigest(),'miner_log_sha256':hashlib.sha256(rawlog).hexdigest(),'redacted_miner_log':log.replace(account,'[KRYPTEX_ACCOUNT]'),'vpn_source_sha256':hashlib.sha256(vraw).hexdigest(),'validated_official_artifacts':L.PINS,'validator_pins':pins}
        proofpath=P.STATE/('official-mining-validation-'+a.boot_id+'.json');P.exclusive_json(proofpath,proof)
        records=F.accepted_records(data['api'],r['device'],config,a.boot_id)
        ack=dict(G.expected(g),phase='official-krig-five-card-mining',devices=records,official_miner_compute_verified=True,approved_boottime=clock(),miner_started_boottime=r['started_boottime'],temperature_c=temp,validation_sha256=hashlib.sha256(proofpath.read_bytes()).hexdigest())
        assert G.mining_ack(ack,g,clock(),[read(P.STATE/('controller-'+str(i)+'-'+a.boot_id+'.json')) for i in (0,1)],config)==G.expected(g)
        assert not (G.RUN/'mining-ack.json').exists();G.atomic(G.RUN/'mining-ack.json',ack)
        end=time.monotonic()+10
        while time.monotonic()<end:
            p=G.STATE/'result.json'
            if p.exists():
                result=read(p)
                if result.get('boot_id')==a.boot_id and result.get('nonce')==a.nonce and result.get('outcome')=='acknowledged':
                    print(json.dumps({'status':'ACTUAL_MINING_ACKNOWLEDGED','ack':ack,'guard_result':result}),flush=True);return
            time.sleep(.25)
        raise RuntimeError('ACK written but guard result not verified')
    raise RuntimeError('Original guard deadline approaching; no extension or fabricated ACK')

if __name__=='__main__':main()
