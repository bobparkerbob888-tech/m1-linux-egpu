"""Root-only install of an explicitly pinned dormant kit. No service/load/start."""
import argparse,hashlib,json,os,stat
from pathlib import Path
def main():
 a=argparse.ArgumentParser();a.add_argument('--kind',choices=['probe','miner'],required=True);a.add_argument('--source',required=True);a.add_argument('--kit-sha256',required=True);a.add_argument('--boot-id',required=True);a=a.parse_args()
 assert os.geteuid()==0 and Path('/proc/sys/kernel/random/boot_id').read_text().strip()==a.boot_id
 src=Path(a.source);dst=Path('/usr/local/lib/bob-native-'+('probe' if a.kind=='probe' else 'prl')+'-r54')
 raw=(src/'KIT-PINS.json').read_bytes();assert hashlib.sha256(raw).hexdigest()==a.kit_sha256;pins=json.loads(raw)
 assert not dst.exists() and not dst.is_symlink();tmp=dst.with_name(dst.name+'.installing');assert not tmp.exists()
 content={}
 for name,h in pins.items():
  assert name and name not in ('.','..') and '/' not in name and name!='KIT-PINS.json'
  p=src/name;assert stat.S_ISREG(p.lstat().st_mode);data=p.read_bytes();assert hashlib.sha256(data).hexdigest()==h;content[name]=data
 tmp.mkdir(mode=0o755)
 for name,data in dict(content,**{'KIT-PINS.json':raw}).items():
  p=tmp/name
  with p.open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
  p.chmod(0o444)
 tmp.rename(dst)
 print(json.dumps({'installed':str(dst),'kit_sha256':a.kit_sha256,'dormant':True,'boot_id':a.boot_id}))
if __name__=='__main__':main()
