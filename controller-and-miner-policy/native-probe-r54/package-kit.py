"""Build local immutable dormant probe/miner kits from reviewed source and modules."""
import argparse,hashlib,json,shutil
from pathlib import Path
PROBE=['probe.py','probe_policy.py','five_policy.py','prepare-manifest.py','prepare-uvm.py']
MINER=['launch.py','admit.py','validate-mining.py','network.py','stream_worker.py','fixed_prl_relay.py','five_policy.py','probe_policy.py','observe-address.py']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 a=argparse.ArgumentParser();a.add_argument('--output',required=True);a.add_argument('--nvidia',required=True);a.add_argument('--uvm',required=True);a=a.parse_args()
 here=Path(__file__).resolve().parent;root=Path(a.output);root.mkdir(exist_ok=False)
 for name,names,src in [('probe',PROBE,here),('miner',MINER,here.parent/'native-prl-r54')]:
  dst=root/name;dst.mkdir()
  for f in names:shutil.copy2(src/f,dst/f)
  if name=='probe':
   shutil.copy2(a.nvidia,dst/'nvidia.ko');shutil.copy2(a.uvm,dst/'nvidia-uvm.ko')
  else:
   # Root validator pins are included in overall KIT pins, no self-reference.
   (dst/'pins.json').write_text(json.dumps({f:sha(dst/f) for f in names},indent=2)+'\n')
  pins={p.name:sha(p) for p in sorted(dst.iterdir())};(dst/'KIT-PINS.json').write_text(json.dumps(pins,indent=2)+'\n')
  for p in dst.iterdir():p.chmod(0o444)
  print(json.dumps({'kit':name,'source':str(dst),'kit_sha256':sha(dst/'KIT-PINS.json')}))
if __name__=='__main__':main()
