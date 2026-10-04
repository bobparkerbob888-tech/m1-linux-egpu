"""Bounded read-only sampling of both admitted APCIEC host ports, never GPU BARs."""
from pathlib import Path
import argparse,json,mmap,os,struct,sys,time
sys.path.insert(0,'/usr/local/lib/bob-native-probe-r54')
import probe as P
OFFSETS=(0x80,0x100,0x208,0x240,0x244,0x284,0x288,0x28c,0x290,0x800)
HOSTS=(('apciec@3b0000000',0x3a1000000),('apciec@530000000',0x521000000))
ERROR_MASK=(1<<26)|(1<<25)|(1<<23)|(1<<21)
def clock():return time.clock_gettime(time.CLOCK_BOOTTIME)
def sample(mm):return {hex(o):hex(struct.unpack_from('<I',mm,o)[0]) for o in OFFSETS}
def profile_check(raw,base):
 P.need(len(raw)==5*16,'Exact five-region host profile required')
 observed,size=struct.unpack_from('>QQ',raw,2*16)
 P.need(observed==base and size==0x8000,'Wrong host port base/size')
def safe_port1(values):
 P.need(set(values)=={hex(o) for o in OFFSETS},'Incomplete controller1 sample')
 status=int(values['0x100'],16)
 P.need(0<=status<=0xffffffff and status!=0xffffffff and not status&ERROR_MASK,'Controller1 status error')
def main():
 a=argparse.ArgumentParser();a.add_argument('--boot-id',required=True);a.add_argument('--nonce',required=True);a.add_argument('--kit-sha256',required=True);a=a.parse_args()
 P.need(os.geteuid()==0 and os.uname().release==P.KERNEL,'Wrong root/kernel')
 P.need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==a.boot_id,'Wrong boot')
 here=Path(__file__).resolve().parent;P.check_hash(here/'KIT-PINS.json',a.kit_sha256)
 for n,h in P.read_json(here/'KIT-PINS.json').items():P.need('/' not in n,'Wrong kit path');P.check_hash(here/n,h)
 P.identity();g=P.guard_live(a.boot_id,a.nonce,100);P.validate_pci(P.pci_snapshot(),after=True)
 P.validate_ready_logs(P.messages(P.journal(),a.boot_id,g['armed_monotonic']))
 proof=P.read_json(P.STATE/('native-probe-'+a.boot_id)/'result.json')
 P.need(proof['boot_id']==a.boot_id and proof['nonce']==a.nonce and proof['outcome']=='query-complete-stock-return-mandatory','Native query not verified')
 for node,base in HOSTS:profile_check((Path('/sys/firmware/devicetree/base/soc')/node/'reg').read_bytes(),base)
 d=P.STATE/('address-observation-'+a.boot_id);d.mkdir(mode=0o700)
 # The exclusive directory consumes this observer attempt before any mapping.
 fd=os.open('/dev/mem',os.O_RDONLY|os.O_SYNC);maps=[]
 try:
  for node,base in HOSTS:maps.append(mmap.mmap(fd,0x4000,flags=mmap.MAP_SHARED,prot=mmap.PROT_READ,offset=base))
 finally:os.close(fd)
 try:
  with (d/'samples.jsonl').open('x',buffering=1) as f:
   os.fchmod(f.fileno(),0o600);last=None;last_emit=0.;count=0
   while clock()<g['deadline_boottime']-3:
    P.need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==a.boot_id,'Boot changed')
    values=[sample(mm) for mm in maps];safe_port1(values[1]);now=clock();count+=1
    if values!=last or now-last_emit>=1:
     f.write(json.dumps({'boot_id':a.boot_id,'nonce':a.nonce,'boottime':now,'sample':count,'port_readonly':values[0],'port1_readonly':values[1],'host_bases':[hex(b) for _,b in HOSTS]})+'\n');f.flush();os.fsync(f.fileno());last_emit=now
    if last is None:P.exclusive_json(d/'ready.json',{'boot_id':a.boot_id,'nonce':a.nonce,'pid':os.getpid(),'deadline':g['deadline_boottime'],'initial':values[0],'initial_port1':values[1],'host_bases':[hex(b) for _,b in HOSTS],'read_only':True})
    last=values;time.sleep(.05)
 finally:
  for mm in maps:mm.close()
if __name__=='__main__':main()
