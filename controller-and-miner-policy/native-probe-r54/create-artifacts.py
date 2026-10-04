"""LOCAL manifest generation from actual artifacts; no placeholder hash accepted."""
import argparse,hashlib,json,re
from pathlib import Path
K='7.3.0-rc1-j293-router-r54';V='615.71.09'
def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
 a=argparse.ArgumentParser()
 for name in ('image','image-remote-path','nvidia','uvm','guard-artifacts','guard-source','runtime-receipt','output'):a.add_argument('--'+name,required=True)
 a=a.parse_args();here=Path(__file__).resolve().parent
 if not a.image_remote_path.startswith('/var/lib/bob-kernel-trial/') or '..' in a.image_remote_path:raise ValueError('Exact reviewed kernel image path required')
 # modinfo is read-only and validates actual built module ABI, not filenames.
 import subprocess
 for p in (a.nvidia,a.uvm):
  if subprocess.check_output(['modinfo','-F','vermagic',p],text=True).strip()!=K+' SMP preempt mod_unload aarch64':raise ValueError('Wrong module release')
  if subprocess.check_output(['modinfo','-F','version',p],text=True).strip()!=V:raise ValueError('Wrong NVIDIA module version')
 activation=json.loads(Path(a.guard_artifacts).read_text())
 if activation['kernel']!=K or activation['schema']!=1 or len(activation['controllers'])!=2:raise ValueError('Wrong guard artifacts')
 for key,actual in [('image',digest(a.image)),('nvidia',digest(a.nvidia)),('uvm',digest(a.uvm))]:
  if activation[key]['sha256']!=actual:raise ValueError('Guard artifact differs:'+key)
 if activation['image']['path']!=a.image_remote_path:raise ValueError('Guard image path differs')
 runtime=json.loads(Path(a.runtime_receipt).read_text())
 if runtime['version']!=V:raise ValueError('Wrong installed native runtime')
 m={'schema':1,'kernel':K,'guard_files':{n:digest(Path(a.guard_source)/n) for n in ('arm.py','runtime_guard.py','proven_guard.py','contracts.py','activate_controllers.py','five_policy.py')},'kernel_image':{'path':a.image_remote_path,'sha256':digest(a.image)},'module':{'path':'/usr/local/lib/bob-native-probe-r54/nvidia.ko','sha256':digest(a.nvidia),'version':V,'vermagic':K+' SMP preempt mod_unload aarch64'},'uvm':{'path':'/usr/local/lib/bob-native-probe-r54/nvidia-uvm.ko','sha256':digest(a.uvm)},'runtime':{'path':'/usr/local/lib/bob-native-runtime-615-r40','installation_sha256':digest(a.runtime_receipt),'manifest_sha256':'00eb1c824fd4328ee00dfc7cc32f5c075ce9bd04a1d65c8adf7b478a6408e11b'},'probe_files':{n:digest(here/n) for n in ('probe.py','probe_policy.py','five_policy.py','prepare-manifest.py')}}
 path=Path(a.output)
 with path.open('x') as f:json.dump(m,f,indent=2);f.write('\n')
 print(json.dumps({'path':str(path),'sha256':digest(path)}))
if __name__=='__main__':main()
