"""One UVM load after the sole successful five-GPU NVIDIA probe; no retry/unload."""
import argparse,json,os,stat
from pathlib import Path
import probe as P

def main():
 a=argparse.ArgumentParser();a.add_argument('--boot-id',required=True);a.add_argument('--nonce',required=True);a.add_argument('--kit-sha256',required=True);a=a.parse_args()
 P.need(os.geteuid()==0 and os.uname().release==P.KERNEL,'Wrong root/kernel');P.need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==a.boot_id,'Wrong boot')
 P.check_hash(Path(__file__).parent/'KIT-PINS.json',a.kit_sha256)
 for n,h in P.read_json(Path(__file__).parent/'KIT-PINS.json').items():P.need('/' not in n,'Wrong kit path');P.check_hash(Path(__file__).parent/n,h)
 c=P.identity();g=P.guard_live(a.boot_id,a.nonce,650);kmsg=P.KernelLog()
 def kernel_gate():
  P.reject_faults([x['message'] for x in kmsg.drain() if x['monotonic_microseconds']/1e6>=g['armed_monotonic']])
 kernel_gate()
 result=P.read_json(P.STATE/('native-probe-'+a.boot_id)/'result.json')
 P.need(result['boot_id']==a.boot_id and result['nonce']==a.nonce and result['outcome']=='query-complete-stock-return-mandatory','Five-GPU probe failed')
 P.need({x['bdf'] for x in result['detail']['devices']}==set(P.TARGETS) and result['detail']['native_query_verified'] is True,'Incomplete five-GPU proof')
 P.need(len(result['detail']['devices'])==5,'Duplicate or missing query device')
 P.validate_pci(P.pci_snapshot(),after=True);P.reject_faults(P.messages(P.journal(),a.boot_id,g['armed_monotonic']));kernel_gate()
 P.need(not Path('/sys/module/nvidia_uvm').exists() and not list(Path('/dev').glob('nvidia-uvm*')),'UVM already attempted')
 module=P.MODULE.parent/'nvidia-uvm.ko';P.trusted(module);P.check_hash(module,c['uvm_sha256'])
 P.need(P.command('/usr/sbin/modinfo','-F','vermagic',str(module))==P.KERNEL+' SMP preempt mod_unload aarch64','UVM ABI mismatch')
 P.need(P.command('/usr/sbin/modinfo','-F','name',str(module))=='nvidia_uvm' and P.command('/usr/sbin/modinfo','-F','version',str(module))==P.VERSION,'Wrong UVM module')
 out=P.STATE/('native-uvm-direct-'+a.boot_id);out.mkdir(mode=0o700)
 P.exclusive_json(out/'attempt.json',{'boot_id':a.boot_id,'nonce':a.nonce,'module_sha256':c['uvm_sha256']})
 P.bounded_process(['/usr/sbin/insmod',str(module)],out,'insmod',15,P.ENV)
 P.guard_live(a.boot_id,a.nonce,620);P.reject_faults(P.messages(P.journal(),a.boot_id,g['armed_monotonic']));kernel_gate()
 P.need(Path('/sys/module/nvidia_uvm/version').read_text().strip()==P.VERSION,'UVM version mismatch')
 majors=[x.split() for x in Path('/proc/devices').read_text().splitlines()];found=[x for x in majors if len(x)==2 and x[1]=='nvidia-uvm']
 P.need(len(found)==1 and found[0][0].isdigit(),'UVM character major absent');major=int(found[0][0]);P.need(1<=major<=4095,'Invalid UVM major');p=Path('/dev/nvidia-uvm')
 P.need(not p.exists() and not p.is_symlink(),'Unexpected UVM node');os.mknod(p,stat.S_IFCHR|0o600,os.makedev(major,0));st=p.lstat();P.need(stat.S_ISCHR(st.st_mode) and st.st_rdev==os.makedev(major,0) and st.st_uid==0,'Wrong UVM node')
 P.exclusive_json(out/'uvm-ready.json',{'boot_id':a.boot_id,'nonce':a.nonce,'module_sha256':c['uvm_sha256'],'version':P.VERSION,'device':[major,0]})
 print('UVM verified; owners retained; miner not started')
if __name__=='__main__':main()
