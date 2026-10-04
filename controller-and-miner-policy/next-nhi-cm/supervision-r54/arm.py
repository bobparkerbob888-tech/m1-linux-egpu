#!/usr/bin/python3
"""Executed by root on target only after SSH and watchdog verification. Never loads a module."""
import argparse, hashlib, json, os, re, subprocess, sys, time, uuid
from pathlib import Path
import runtime_guard as R
import proven_guard as G
import contracts as C

def check_late_arm(cmd, parameter, chosen):
 for token in ('thunderbolt_apple.external_endpoint_pair=1','pcie_apple_apciec_experimental.endpoint_pair=1'):
  if [x for x in cmd if x.startswith(token.split('=')[0]+'=')]!=[token]:raise RuntimeError('missing exact pair optin')
 if [x for x in cmd if x.startswith('module_blacklist=')] != ['module_blacklist=nouveau,nova_core,nova_drm,nvidia_drm,nvidia_modeset,nvidiafb,i2c_nvidia_gpu']:raise RuntimeError('Wrong GPU module policy')
 if [x for x in cmd if x.startswith('modprobe.blacklist=')] != ['modprobe.blacklist=nouveau,nova_core,nova_drm,nvidia,nvidia_drm,nvidia_modeset,nvidia_uvm,nvidiafb,i2c_nvidia_gpu']:raise RuntimeError('Wrong GPU module policy')
 if [x for x in cmd if x.startswith('rd.driver.blacklist=')] != ['rd.driver.blacklist=nouveau,nova_core,nova_drm,nvidia,nvidia_drm,nvidia_modeset,nvidia_uvm,nvidiafb,i2c_nvidia_gpu']:raise RuntimeError('Wrong GPU module policy')
 if [x for x in cmd if x.startswith('thunderbolt_apple.root_cable_only=')] != ['thunderbolt_apple.root_cable_only=1']:raise RuntimeError('wrong root_cable_only optin')
 if [x for x in cmd if x.startswith('thunderbolt_apple.attached_router_identity=')] != ['thunderbolt_apple.attached_router_identity=1']:raise RuntimeError('wrong attached_router_identity optin')
 if [x for x in cmd if x.startswith('thunderbolt_apple.root_port1_unlock=')] != ['thunderbolt_apple.root_port1_unlock=1']:raise RuntimeError('wrong root_port1_unlock optin')
 if [x for x in cmd if x.startswith('thunderbolt_apple.route1_inventory=')] != ['thunderbolt_apple.route1_inventory=1']:raise RuntimeError('wrong route1_inventory optin')
 if [x for x in cmd if x.startswith('thunderbolt_apple.route1_header_config=')] != ['thunderbolt_apple.route1_header_config=1']:raise RuntimeError('wrong route1_header_config optin')
 if [x for x in cmd if x.startswith('thunderbolt_apple.route1_usb4_ready=')] != ['thunderbolt_apple.route1_usb4_ready=1']:raise RuntimeError('wrong route1_usb4_ready optin')
 if [x for x in cmd if x.startswith('thunderbolt_apple.external_host_prepare=')] != ['thunderbolt_apple.external_host_prepare=1']:raise RuntimeError('wrong external_host_prepare optin')
 if [x for x in cmd if x.startswith('thunderbolt_apple.external_pcie_raw_identity=')] != ['thunderbolt_apple.external_pcie_raw_identity=1']:raise RuntimeError('wrong external_pcie_raw_identity optin')
 if [x for x in cmd if x.startswith('thunderbolt_apple.external_endpoint_resources=')] != ['thunderbolt_apple.external_endpoint_resources=1']:raise RuntimeError('wrong external_endpoint_resources optin')
 if [x for x in cmd if x.startswith('thunderbolt_apple.external_endpoint_memory_assign=')] != ['thunderbolt_apple.external_endpoint_memory_assign=1']:raise RuntimeError('wrong external_endpoint_memory_assign optin')
 if [x for x in cmd if x.startswith('thunderbolt_apple.external_dart_prepare_only=')] != ['thunderbolt_apple.external_dart_prepare_only=0']:raise RuntimeError('wrong external_dart_prepare_only optin')
 if [x for x in cmd if x.startswith('thunderbolt_apple.external_dart_availability_probe=')] != ['thunderbolt_apple.external_dart_availability_probe=0']:raise RuntimeError('wrong external_dart_availability_probe optin')
 if [x for x in cmd if x.startswith('thunderbolt_apple.route1_pcie_tunnel=')] != ['thunderbolt_apple.route1_pcie_tunnel=1']:raise RuntimeError('wrong route1_pcie_tunnel optin')
 if [x for x in cmd if x.startswith('pcie_apple_apciec_experimental.enum_only=')] != ['pcie_apple_apciec_experimental.enum_only=1']:raise RuntimeError('wrong enum_only optin')
 if [x for x in cmd if x.startswith('pcie_apple_apciec_experimental.endpoint_resources=')] != ['pcie_apple_apciec_experimental.endpoint_resources=1']:raise RuntimeError('wrong endpoint_resources optin')
 if [x for x in cmd if x.startswith('pcie_apple_apciec_experimental.endpoint_memory_assign=')] != ['pcie_apple_apciec_experimental.endpoint_memory_assign=1']:raise RuntimeError('wrong endpoint_memory_assign optin')
 if [x for x in cmd if x.startswith('pcie_apple_apciec_experimental.endpoint_pci_register=')] != ['pcie_apple_apciec_experimental.endpoint_pci_register=1']:raise RuntimeError('wrong endpoint_pci_register optin')
 if [x for x in cmd if x.startswith('pcie_apple_apciec_experimental.endpoint_mmio_probe=')] != ['pcie_apple_apciec_experimental.endpoint_mmio_probe=1']:raise RuntimeError('wrong endpoint_mmio_probe optin')
 if [x for x in cmd if x.startswith('pcie_apple_apciec_experimental.endpoint_native_driver=')] != ['pcie_apple_apciec_experimental.endpoint_native_driver=1']:raise RuntimeError('wrong endpoint_native_driver optin')
 if [x for x in cmd if x.startswith('pcie_apple_apciec_experimental.retain_prepare=')] != ['pcie_apple_apciec_experimental.retain_prepare=1']:raise RuntimeError('wrong retain_prepare optin')
 if [x for x in cmd if x.startswith('pcie_apple_apciec_experimental.retain_commit=')] != ['pcie_apple_apciec_experimental.retain_commit=1']:raise RuntimeError('wrong retain_commit optin')

 for token in ('thunderbolt_apple.route_chain_prepare=1','thunderbolt_apple.route_chain_tunnels=1','pcie_apple_apciec_experimental.endpoint_chain_resources=1'):
  if [x for x in cmd if x.startswith(token.split('=')[0]+'=')]!=[token]:raise RuntimeError('missing chain optin')
 if [x for x in cmd if x.startswith('bob_kernel_mode=')] != ['bob_kernel_mode=late-arm-r54-native-driver']:raise RuntimeError('wrong late-arm mode')
 if [x for x in cmd if x.startswith('bob_kernel_trial=')] != ['bob_kernel_trial=oldm1-r54-20261004']:raise RuntimeError('wrong trial')
 if [x for x in cmd if x.startswith('bob_j293_overlay=')] != ['bob_j293_overlay=efi-disabled-r52']:raise RuntimeError('wrong overlay')
 if any(x.startswith(('thunderbolt_apple.root_router_only=','bob_kernel_isolation=','bob_kernel_baseline=')) for x in cmd):raise RuntimeError('old mode forbidden')
 if parameter != 'N':raise RuntimeError('router parameter already armed')
 if chosen != b'disabled-r52\0':raise RuntimeError('wrong EFI overlay provenance')

def check_stock_fallback(env,config):
 wanted='gnulinux-advanced-PROVISION_TARGET_UUID>gnulinux-7.0.0-1001-asahi-arm-advanced-PROVISION_TARGET_UUID'
 saved=[x for x in env if x.startswith('saved_entry=')]
 if saved not in ([],['saved_entry='+wanted]) or any(x.startswith('next_entry=') and x!='next_entry=' for x in env):raise RuntimeError('stock fallback environment rejected')
 if len(re.findall(r'^\s*set default="'+re.escape(wanted)+r'"\s*$',config,re.M))!=1:raise RuntimeError('exact literal stock GRUB default missing')
 return True

def main():
 p=argparse.ArgumentParser();p.add_argument('--boot-id',required=True);p.add_argument('--watchdog-confirmed',action='store_true',required=True);p.add_argument('--artifacts',required=True);a=p.parse_args()
 if os.geteuid()!=0 or R.boot()!=a.boot_id or os.uname().release!=R.KERNEL:raise RuntimeError('wrong root/boot/kernel')
 artifacts=C.artifacts(json.loads(C.secure_bytes(a.artifacts)),a.boot_id,verify=True)
 if any(Path('/sys/module/'+x).exists() for x in ('nvidia','nvidia_uvm','acio_runtime_enable','acio_runtime_enable_port1')):raise RuntimeError('native module already active')
 fallback=subprocess.check_output(['/usr/bin/grub-editenv','/boot/grub/grubenv','list'],text=True,timeout=10).splitlines()
 check_stock_fallback(fallback,C.secure_bytes('/boot/grub/grub.cfg').decode())
 cmd=Path('/proc/cmdline').read_text().split()
 for module,name in (('thunderbolt_apple','external_endpoint_pair'),('pcie_apple_apciec_experimental','endpoint_pair')):
  if Path('/sys/module',module,'parameters',name).read_text().strip()!='Y':raise RuntimeError('inactive pair parameter '+module+'.'+name)
 if Path('/sys/module/thunderbolt_apple/parameters/root_cable_only').read_text().strip()!='Y':raise RuntimeError('inactive root_cable_only')
 if Path('/sys/module/thunderbolt_apple/parameters/attached_router_identity').read_text().strip()!='Y':raise RuntimeError('inactive attached_router_identity')
 if Path('/sys/module/thunderbolt_apple/parameters/root_port1_unlock').read_text().strip()!='Y':raise RuntimeError('inactive root_port1_unlock')
 if Path('/sys/module/thunderbolt_apple/parameters/route1_inventory').read_text().strip()!='Y':raise RuntimeError('inactive route1_inventory')
 if Path('/sys/module/thunderbolt_apple/parameters/route1_header_config').read_text().strip()!='Y':raise RuntimeError('inactive route1_header_config')
 if Path('/sys/module/thunderbolt_apple/parameters/route1_usb4_ready').read_text().strip()!='Y':raise RuntimeError('inactive route1_usb4_ready')
 if Path('/sys/module/thunderbolt_apple/parameters/external_host_prepare').read_text().strip()!='Y':raise RuntimeError('inactive external_host_prepare')
 if Path('/sys/module/thunderbolt_apple/parameters/external_pcie_raw_identity').read_text().strip()!='Y':raise RuntimeError('inactive external_pcie_raw_identity')
 if Path('/sys/module/thunderbolt_apple/parameters/external_endpoint_resources').read_text().strip()!='Y':raise RuntimeError('inactive external_endpoint_resources')
 if Path('/sys/module/thunderbolt_apple/parameters/external_endpoint_memory_assign').read_text().strip()!='Y':raise RuntimeError('inactive external_endpoint_memory_assign')
 if Path('/sys/module/thunderbolt_apple/parameters/external_dart_prepare_only').read_text().strip()!='N':raise RuntimeError('inactive external_dart_prepare_only')
 if Path('/sys/module/thunderbolt_apple/parameters/external_dart_availability_probe').read_text().strip()!='N':raise RuntimeError('inactive external_dart_availability_probe')
 if Path('/sys/module/thunderbolt_apple/parameters/route1_pcie_tunnel').read_text().strip()!='Y':raise RuntimeError('inactive route1_pcie_tunnel')
 if Path('/sys/module/pcie_apple_apciec_experimental/parameters/enum_only').read_text().strip()!='Y':raise RuntimeError('inactive enum_only')
 if Path('/sys/module/pcie_apple_apciec_experimental/parameters/endpoint_resources').read_text().strip()!='Y':raise RuntimeError('inactive endpoint_resources')
 if Path('/sys/module/pcie_apple_apciec_experimental/parameters/endpoint_memory_assign').read_text().strip()!='Y':raise RuntimeError('inactive endpoint_memory_assign')
 if Path('/sys/module/pcie_apple_apciec_experimental/parameters/endpoint_pci_register').read_text().strip()!='Y':raise RuntimeError('inactive endpoint_pci_register')
 if Path('/sys/module/pcie_apple_apciec_experimental/parameters/endpoint_mmio_probe').read_text().strip()!='Y':raise RuntimeError('inactive endpoint_mmio_probe')
 if Path('/sys/module/pcie_apple_apciec_experimental/parameters/endpoint_native_driver').read_text().strip()!='Y':raise RuntimeError('inactive endpoint_native_driver')
 if Path('/sys/module/pcie_apple_apciec_experimental/parameters/retain_prepare').read_text().strip()!='Y':raise RuntimeError('inactive retain_prepare')
 if Path('/sys/module/pcie_apple_apciec_experimental/parameters/retain_commit').read_text().strip()!='Y':raise RuntimeError('inactive retain_commit')

 check_late_arm(cmd,Path('/sys/module/thunderbolt_apple/parameters/root_router_only').read_text().strip(),Path('/sys/firmware/devicetree/base/chosen/bob,j293-efi-overlay').read_bytes())
 for d in (R.RUN,R.STATE):G.prepare_directory(d,0,0,0o700,{0})
 # Exclusive durable per-boot arm record prevents restart from granting time.
 record=R.STATE/('armed-'+a.boot_id+'.json')
 monotonic=time.clock_gettime(time.CLOCK_MONOTONIC);now=R.clock();m=dict(trial_id=R.TRIAL,boot_id=a.boot_id,kernel=R.KERNEL,nonce=uuid.uuid4().hex,armed_boottime=now,armed_monotonic=monotonic,deadline_boottime=now+1200,hardware_watchdog_confirmed=True,artifacts=artifacts)
 with record.open('x') as f:
  os.fchmod(f.fileno(),0o600);json.dump(m,f);f.flush();os.fsync(f.fileno())
 R.atomic(R.MANIFEST,m)
 helper=Path(__file__).resolve().with_name('runtime_guard.py')
 subprocess.run(['/usr/bin/systemd-run','--unit='+R.UNIT,'--service-type=exec','--property=Restart=no','--property=TimeoutStopSec=10','/usr/bin/python3',str(helper)],check=True,timeout=15)
 for _ in range(40):
  ready=G.read_json_file(R.RUN/'ready.json',0)
  active=subprocess.run(['/usr/bin/systemctl','is-active','--quiet',R.UNIT],timeout=5).returncode==0
  if active and ready and all(ready.get(k)==v for k,v in R.expected(m).items()) and R.clock()<m['deadline_boottime']-30:
   print(json.dumps(dict(status='guard-ready',**m)));return 0
  time.sleep(.25)
 raise RuntimeError('guard not confirmed ready: DO NOT INSMOD; arm cannot be retried')
if __name__=='__main__':sys.exit(main())
