"""Root-only fresh controller1 identity sealing; no GPU/driver operation."""
import argparse,copy,hashlib,json,os,re
from pathlib import Path
import probe as P
import five_policy as F
import probe_policy as Q

def extract_identity(base,boot,lines,resolve):
 c=copy.deepcopy(base);c['boot_id']=boot
 candidates=[x for x in lines if 'pair-native: phase30 ' in x]
 P.need(len(candidates)==1,'Ambiguous controller1 phase30')
 match=re.search(r'530000000\.apciec: pair-native: phase30 target(0002:06:00\.0) serial(PROVISION_PRIVATE_ID_9) target(0002:03:00\.0) serial([0-9a-f]{16}) ready; audio0301/0601 untouched$',candidates[0])
 P.need(match is not None,'Wrong controller1 phase30 marker')
 bdf,dsn,second,serial=match.groups()
 for route,uid in zip(('1','301'),F.UIDS):
  marker='chain-prepare: route'+route+' UID'+uid.lower()+' identity1 configured1 ready1'
  P.need(len([x for x in lines if marker in x and '501f00000' in x])==1,'Second controller route identity missing')
 c['fourth'].update(bdf=bdf,dsn=dsn,uuid='PROVISION_TARGET_UUID',sysfs_path=resolve(bdf))
 c['fifth'].update(bdf=second,dsn=serial,uuid=None,sysfs_path=resolve(second))
 return c

def main():
 a=argparse.ArgumentParser();a.add_argument('--boot-id',required=True);a.add_argument('--nonce',required=True);a.add_argument('--artifacts',required=True);a.add_argument('--artifacts-sha256',required=True);a=a.parse_args()
 P.need(os.geteuid()==0 and os.uname().release==P.KERNEL,'Wrong root/kernel')
 P.need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==a.boot_id,'Wrong boot')
 P.check_hash(a.artifacts,a.artifacts_sha256);m=P.read_json(a.artifacts)
 P.need(m['schema']==1 and m['kernel']==P.KERNEL,'Wrong artifacts manifest')
 for item in ('module','uvm','kernel_image'):P.trusted(m[item]['path']);P.check_hash(m[item]['path'],m[item]['sha256'])
 P.need(m['module']['path']==str(P.MODULE) and m['uvm']['path']==str(P.MODULE.parent/'nvidia-uvm.ko'),'Wrong module paths')
 g=P.guard_live(a.boot_id,a.nonce,180)
 lines=P.messages(P.journal(),a.boot_id,g['armed_monotonic']);P.reject_faults(lines)
 proofpath=P.STATE/('controller-1-journal-'+a.boot_id+'.json');receipt=P.read_json(P.STATE/('controller-1-'+a.boot_id+'.json'))
 P.need(receipt['boot_id']==a.boot_id and receipt['nonce']==a.nonce and receipt['kernel']==P.KERNEL and receipt['phase']==30 and receipt['status']=='native-ready' and receipt['controller']==1,'Wrong controller1 readiness receipt')
 P.check_hash(proofpath,receipt['journal_sha256']);proof=P.read_json(proofpath, limit=2*1024*1024)
 P.need(proof['boot_id']==a.boot_id and proof['nonce']==a.nonce and proof['kernel']==P.KERNEL and proof['controller']==1,'Wrong controller1 journal')
 base={'schema':2,'boot_id':a.boot_id,'kernel':P.KERNEL,'kernel_sha256':m['kernel_image']['sha256'],'nvidia_sha256':m['module']['sha256'],'uvm_sha256':m['uvm']['sha256'],'phase30_evidence_sha256':None,'power_limit_watts':150,'thermal_stop_c':85,'automatic_retry':False,'fourth':{'host_of_path':F.OF1,'enclosure_uids':F.UIDS,'rid':0x600,'sid':1},'fifth':{'host_of_path':F.OF1,'enclosure_uids':F.UIDS,'rid':0x300,'sid':2}}
 c=extract_identity(base,a.boot_id,lines,lambda b:str((Path('/sys/bus/pci/devices')/b).resolve(strict=True)))
 c['phase30_evidence_sha256']=receipt['journal_sha256']
 P.need(c['fourth']['bdf']==receipt['target_bdf'] and c['fourth']['dsn']==receipt['target_dsn'] and c['fifth']['bdf']==receipt['secondary_bdf'] and c['fifth']['dsn']==receipt['secondary_dsn'],'Current identity differs from retained controller receipt')
 F.endpoint_config(c,a.boot_id);Q.phase30([x[1] for x in proof['rows']],c,a.boot_id)
 P.trusted(P.STATE,directory=True)
 identity=P.STATE/('endpoint-identity-'+a.boot_id+'.json');P.exclusive_json(identity,c)
 m['endpoint_identity']={'path':str(identity),'sha256':P.sha(identity)}
 path=P.STATE/('probe-manifest-'+a.boot_id+'.json');P.exclusive_json(path,m)
 P.bind_identity(m,a.boot_id);P.validate_ready_logs(lines);P.validate_pci(P.pci_snapshot())
 print(json.dumps({'probe_manifest':str(path),'sha256':P.sha(path),'endpoint_identity':m['endpoint_identity']}))
if __name__=='__main__':main()
