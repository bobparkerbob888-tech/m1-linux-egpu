#!/usr/bin/python3
"""One native R54 five-GPU probe under the existing mandatory stock-return guard.

Never arms/acknowledges/stops recovery, unloads a module, retries a GPU, starts
a miner, reads BAR memory, or signals an in-flight kernel operation.
"""
import argparse
import csv
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import copy
import five_policy as F
import probe_policy as Q

KERNEL = '7.3.0-rc1-j293-router-r54'
VERSION = '615.71.09'
TRIAL = 'oldm1-acio-router54-20261004'
BOOT_SHA = 'dea2de33883e45a5b22cd5cf6bfc38f58194a2a3e0eeacede71c31b3df13cfd4'
TARGET = '0001:03:00.0'
HOST = '/sys/devices/platform/soc/3b0000000.apciec/'
TARGET_PATH = HOST + 'pci0001:00/0001:00:00.0/0001:01:00.0/0001:02:00.0/' + TARGET
PORT0_TARGETS = ('0001:03:00.0','0001:06:00.0','0001:09:00.0')
TARGETS = PORT0_TARGETS
IDENTITY = None
RIDS = {'0001:%02x:%02x.%u'%(rid>>8,(rid&255)>>3,rid&7) for rid in
        (0,0x100,0x200,0x300,0x301,0x208,0x210,0x218,0x400,0x500,0x600,0x601,0x508,0x510,0x518,0x700,0x800,0x900,0x901,0x808,0x810,0x818)}

RUN = Path('/run/bob-acio-router54-trial')
STATE = Path('/var/lib/bob-acio-router54-trial')
ROOTKIT = Path('/usr/local/lib/bob-acio-router54-trial')
WORK = Path('/path/to/operator/work/prl-native-20261003/acio-router-r54')
RUNTIME = Path('/usr/local/lib/bob-native-runtime-615-r40')
MODULE = Path('/usr/local/lib/bob-native-probe-r54/nvidia.ko')
OPTIONS = {'NVreg_GpuInitOnProbe': 1, 'NVreg_EnableGpuFirmware': 1,
           'NVreg_EnableResizableBar': 0, 'NVreg_EnableMSI': 1,
           'NVreg_DynamicPowerManagement': 0,
           'NVreg_RegistryDwords': 'RMPcieLinkSpeed=0x800002AA;PCIEPowerControl=0x3'}
FORBIDDEN_MODULES = {'nouveau', 'nova_core', 'nova_drm', 'nvidia', 'nvidia_uvm',
                     'nvidia_drm', 'nvidia_modeset', 'nvidiafb', 'i2c_nvidia_gpu'}
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C'}


class Rejected(RuntimeError):
    pass


def need(condition, reason):
    if not condition:
        raise Rejected(reason)


def clock():
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def trusted(path, directory=False):
    """Root-owned regular file/directory, with no writable or symlink ancestors.

    /lib is Ubuntu's normal usr-merge symlink; resolve it, then verify the
    complete canonical chain. Individual artifact symlinks are forbidden.
    """
    p = Path(path)
    st = p.lstat()
    need(stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode),
         'Unexpected artifact type: ' + str(p))
    for q in (p.resolve(), *p.resolve().parents):
        s = q.lstat()
        need(s.st_uid == 0 and not s.st_mode & 0o022, 'Untrusted path: ' + str(q))
    if not directory:
        need(st.st_nlink == 1, 'Hard-linked artifact: ' + str(p))
    return p


def read_json(path, root=True, limit=262144):
    if root:
        trusted(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_size <= limit, 'Invalid JSON file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(limit + 1)
        need(len(raw) <= limit, 'Oversized JSON file')
        value = json.loads(raw)
        need(isinstance(value, dict), 'JSON object required')
        return value
    finally:
        os.close(fd)


def command(*args, timeout=5):
    return subprocess.check_output(args, text=True, env=ENV, timeout=timeout).strip()


def check_hash(path, digest):
    need(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest), 'Invalid SHA pin')
    need(sha(path) == digest, 'SHA mismatch: ' + str(path))


def validate_guard(m, ready, boot, nonce, now, minimum=90):
    ident = {'trial_id': TRIAL, 'boot_id': boot, 'kernel': KERNEL, 'nonce': nonce}
    need(re.fullmatch('[0-9a-f]{32}', nonce) is not None, 'Invalid activation nonce')
    for obj in (m, ready):
        need(all(obj.get(k) == v for k, v in ident.items()), 'Guard identity mismatch')
    a, d, mono = (m.get(k) for k in ('armed_boottime', 'deadline_boottime', 'armed_monotonic'))
    need(all(type(x) in (int, float) and math.isfinite(x) for x in (a, d, mono, now)),
         'Invalid guard clock')
    need(0 <= mono <= a + .01 and a <= now and abs(d - a - 1200) < 1e-6,
         'Guard is not the reviewed 1200-second mining admission')
    need(m.get('hardware_watchdog_confirmed') is True, 'Watchdog unconfirmed')
    need(ready.get('deadline_boottime') == d, 'Ready deadline mismatch')
    need(type(ready.get('guard_pid')) is int and ready['guard_pid'] > 1, 'Invalid guard PID')
    need(d - now >= minimum, 'Insufficient mandatory guard time remaining')
    return d


def journal():
    raw = command('/usr/bin/journalctl', '-k', '-b', '0', '--no-pager', '-o', 'json', timeout=8)
    return [json.loads(line) for line in raw.splitlines() if line]


def messages(entries, boot, after):
    result = []
    for e in entries:
        need(e.get('_BOOT_ID') == boot.replace('-', ''), 'Journal boot mismatch')
        if int(e['__MONOTONIC_TIMESTAMP']) / 1e6 >= after:
            result.append(str(e.get('MESSAGE', '')))
    return result


def validate_port0_logs(lines):
    identities = [x for x in lines if 'retained-config: bus 03 devfn 00 ' in x]
    need(len(identities) == 1 and
         'id 2d0410de class-rev 030000a1 subsystem 41cd1458 serial PROVISION_PRIVATE_ID_6 command 0000;' in identities[0],
         'Exact GPU DSN/identity proof missing or ambiguous')
    mmio = [x for x in lines if 'retained-mmio-probe: status ' in x]
    need(len(mmio) == 1 and re.search(r'retained-mmio-probe: status 0 phase 18 enabled f ops ([1-9][0-9]*) BOOT0 ', mmio[0]),
         'Successful MMIO phase18 proof missing')
    ready = [x for x in lines if 'retained-native-driver: native-ready ' in x]
    expected = ('retained-native-driver: native-ready phase20 GPU' + TARGET +
                ' DART-SID1 domainDMA 16K MSI-local0..31 AIC738..769; driver pending')
    need(len(ready) == 1 and expected in ready[0], 'Native phase20 readiness missing')
    terminal = [x for x in lines if 'retained-native-driver: terminal status ' in x]
    need(len(terminal) == 1 and 'terminal status 0 phase 22;' in terminal[0],
         'Native outer terminal proof missing')
    need(any('retained-native-driver: outer status 0 phase 20;' in x for x in lines),
         'Native outer ownership proof missing')
    chain=[x for x in lines if 'chain-native: status' in x]
    need(len(chain)==1 and 'chain-native: status0 phase22 steppublished-audit functions22;' in chain[0], 'Three-card native preparation missing')
    for route in ('301','30301'):
        tunnels=[x for x in lines if 'chain-tunnel: route'+route+' ' in x]
        need(len(tunnels)==1 and 'status0 phase5 hops4 PE3' in tunnels[0], 'Adjacent tunnel proof missing')



def reject_faults(lines):
    fatal = re.compile(r'init failed during probe|rm_init_adapter\s*(?:\([^)]*\))?\s*failed|'
                       r'RmInitAdapter.*(?:fail|0x)|\bXid\b|native-config denied|GPU.*(?:lost|fallen off)|'
                       r'\b(?:Oops|BUG):|Kernel panic|Unable to handle kernel|'
                       r'\b(?:dart|iommu)\b.*(?:fault|error|timeout)|'
                       r'\bNVRM\b.*(?:failed|failure|error|timed out|timeout)|'
                       r'native-msi:.*(?:failed|invalid|denied)', re.I)
    bad = [line for line in lines if fatal.search(line)]
    need(not bad, 'Kernel/probe failure: ' + '\n'.join(bad[-8:]))


class KernelLog:
    """Direct printk cursor; a journald delay cannot hide a failed GPU probe."""
    def __init__(self):
        self.fd = os.open('/dev/kmsg', os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        self.next_sequence = None

    def parse(self, raw):
        header, message = raw.split(b';', 1)
        fields = header.split(b',')
        need(len(fields) >= 4, 'Invalid printk header')
        sequence, micros = int(fields[1]), int(fields[2])
        need(self.next_sequence is None or sequence == self.next_sequence, 'Lost printk records')
        self.next_sequence = sequence + 1
        return {'sequence': sequence, 'monotonic_microseconds': micros,
                'message': message.decode('utf-8', errors='replace').rstrip('\n')}

    def drain(self):
        entries, start = [], clock()
        while True:
            need(clock() - start < 3 and len(entries) < 65536, 'Printk capture exceeded bounded drain')
            try:
                raw = os.read(self.fd, 65536)
            except BlockingIOError:
                return entries
            # EPIPE from kernel ring overflow propagates: never skip lost proof.
            need(raw, 'Unexpected printk EOF')
            entries.append(self.parse(raw))


def pci_snapshot():
    result = {}
    for p in Path('/sys/bus/pci/devices').iterdir():
        fields = {n: (p / n).read_text().strip() for n in
                  ('vendor', 'device', 'class', 'revision', 'subsystem_vendor', 'subsystem_device')}
        fields['path'] = str(p.resolve())
        fields['driver'] = str((p / 'driver').resolve()) if (p / 'driver').exists() else None
        fields['iommu_group'] = str((p / 'iommu_group').resolve()) if (p / 'iommu_group').exists() else None
        if fields['path'].startswith((HOST,F.HOST1)):
            fields['resource'] = [[int(v, 16) for v in line.split()]
                                  for line in (p / 'resource').read_text().splitlines()]
            fields['enable'] = (p / 'enable').read_text().strip()
            fields['override'] = (p / 'driver_override').read_text().strip()
        result[p.name] = fields
    return result


def validate_port0_pci(devices, after=False):
    external={k for k,v in devices.items() if v['path'].startswith(HOST)}
    need(external==RIDS,'External PCI topology changed')
    gpus={k for k,v in devices.items() if v['vendor']=='0x10de' and int(v['class'],16)>>16==3}
    need(gpus==set(PORT0_TARGETS),'GPU set is not the three admitted cards')
    paths=[['0001:00:00.0','0001:01:00.0','0001:02:00.0'],
           ['0001:00:00.0','0001:01:00.0','0001:02:01.0','0001:04:00.0','0001:05:00.0'],
           ['0001:00:00.0','0001:01:00.0','0001:02:01.0','0001:04:00.0','0001:05:01.0','0001:07:00.0','0001:08:00.0']]
    active_bridges=set().union(*map(set,paths));groups=set()
    for index,target in enumerate(PORT0_TARGETS):
        d=devices[target]
        identity={'vendor':'0x10de','device':'0x2d04','class':'0x030000','revision':'0xa1',
                  'subsystem_vendor':'0x1458','subsystem_device':'0x41cd',
                  'path':HOST+'pci0001:00/'+'/'.join(paths[index]+[target])}
        need(all(d.get(k)==v for k,v in identity.items()),'GPU sysfs identity/path changed')
        pref=0x400000000+index*0x20000000;mem=0x480000000+index*0x4000000
        expected=[(mem,mem+0x3ffffff,0x200),(pref,pref+0xfffffff,0x10220c),(0,0,0),
                  (pref+0x10000000,pref+0x11ffffff,0x10220c),(0,0,0),(0,0x7f,0x40101),(0,0x7ffff,0x46200)]
        need(len(d['resource'])==13,'Wrong resource table length')
        for bar,want in enumerate(expected):
            got=tuple(d['resource'][bar])
            if bar in (0,1,3):got=(got[0],got[1],got[2]&~0x40000)
            need(got==want,'GPU BAR assignment changed: '+target+':'+str(bar))
        need(all(x==[0,0,0] for x in d['resource'][7:]),'Unexpected GPU resource')
        group=d['iommu_group'];need(group is not None and group not in groups,'GPU DMA domain group is not unique');groups.add(group)
        need(d['override']==('nvidia' if after else 'apple-apciec-native-pending'),'Wrong driver override')
        need(d['driver']==('/sys/bus/pci/drivers/nvidia' if after else None),'Unexpected GPU driver')
        if not after:need(d['enable']=='0','GPU already enabled')
    for name in external-set(PORT0_TARGETS):
        d=devices[name]
        need(d['driver'] is None and d['iommu_group'] is None,'Non-GPU admitted')
        if name not in active_bridges or not after:need(d['enable']=='0','Nonselected function enabled')




def identity():
    global IDENTITY,TARGETS
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if IDENTITY is None:
        IDENTITY=read_json(STATE/('endpoint-identity-'+boot+'.json'))
    F.endpoint_config(IDENTITY,boot)
    TARGETS=PORT0_TARGETS+(IDENTITY['fourth']['bdf'],IDENTITY['fifth']['bdf'])
    return IDENTITY

def bind_identity(manifest,boot):
    global IDENTITY
    record=manifest['endpoint_identity']
    path=STATE/('endpoint-identity-'+boot+'.json')
    need(record['path']==str(path),'Endpoint identity outside exact root state')
    check_hash(path,record['sha256']);IDENTITY=read_json(path)
    c=identity();need(c['kernel']==manifest['kernel'] and c['nvidia_sha256']==manifest['module']['sha256'],'Identity/module pins differ')
    proof=STATE/('controller-1-journal-'+boot+'.json')
    check_hash(proof,c['phase30_evidence_sha256']);p=read_json(proof, limit=2*1024*1024)
    need(p['boot_id']==boot and p['kernel']==KERNEL and p['controller']==1,'Wrong phase20 evidence boot')
    receipt=read_json(STATE/('controller-1-'+boot+'.json'))
    need(receipt['boot_id']==boot and receipt['kernel']==KERNEL and receipt['nonce']==p['nonce'] and receipt['controller']==1 and receipt['phase']==30 and receipt['status']=='native-ready','Wrong controller1 receipt')
    need(receipt['journal_sha256']==c['phase30_evidence_sha256'] and receipt['target_bdf']==c['fourth']['bdf'] and receipt['target_dsn']==c['fourth']['dsn'] and receipt['secondary_bdf']==c['fifth']['bdf'] and receipt['secondary_dsn']==c['fifth']['dsn'],'Controller1 receipt identity differs')
    Q.phase30([row[1] for row in p['rows']],c,boot)
    check_hash(manifest['kernel_image']['path'],c['kernel_sha256'])
    need(manifest['kernel_image']['sha256']==c['kernel_sha256'],'Image pin differs')
    check_hash(manifest['uvm']['path'],c['uvm_sha256'])
    need(manifest['uvm']['sha256']==c['uvm_sha256'],'UVM pin differs')

def validate_ready_logs(lines):
    c=identity()
    # The old exact controller0 validator must not confuse port1 route301 logs.
    validate_port0_logs([x for x in lines if '501f00000' not in x and '530000000.apciec' not in x])
    Q.phase30(lines,c,c['boot_id'])
    for route,uid in zip(('1','301'),F.UIDS):
        marker='chain-prepare: route'+route+' UID'+uid.lower()+' identity1 configured1 ready1'
        hits=[x for x in lines if marker in x and '501f00000' in x]
        need(len(hits)==1,'Exact second-controller routeUID readiness missing')

def validate_pci(devices,after=False):
    c=identity()
    port0={k:v for k,v in devices.items() if not v['path'].startswith(F.HOST1)}
    validate_port0_pci(port0,after)
    Q.pci_pair(devices,c,c['boot_id'],after)


def verify_runtime(runtime, item):
    need(runtime == RUNTIME and item['path'] == str(runtime), 'Unexpected runtime directory')
    for p in (runtime, runtime / 'bin', runtime / 'lib', runtime / 'firmware'):
        trusted(p, directory=True)
    receipt = read_json(runtime / 'INSTALLATION.json')
    check_hash(runtime / 'INSTALLATION.json', item['installation_sha256'])
    original = read_json(runtime / 'MANIFEST.json')
    check_hash(runtime / 'MANIFEST.json', item['manifest_sha256'])
    need(receipt['version'] == original['version'] == VERSION and
         receipt['manifest_sha256'] == item['manifest_sha256'] and
         receipt['gpu_initialized'] is False, 'Wrong runtime installation')
    files = {}
    for name, record in original['files'].items():
        folder = 'firmware' if name.startswith('firmware/') else 'lib' if Path(name).name.startswith('lib') else 'bin'
        path = runtime / folder / Path(name).name
        files[str(path)] = record
        if folder == 'firmware':
            files[str(Path('/lib/firmware/nvidia') / VERSION / Path(name).name)] = record
    need(files == receipt['files'], 'Installation file set differs from payload')
    for name, record in files.items():
        p = trusted(name)
        need(p.stat().st_size == record['bytes'], 'Artifact size mismatch')
        check_hash(p, record['sha256'])
    links = original['soname_links']
    need(links == receipt['soname_links'], 'SONAME receipt mismatch')
    for name, target in links.items():
        need(Path(name).name == name and Path(target).name == target, 'Invalid SONAME path')
        p = runtime / 'lib' / name
        need(p.is_symlink() and p.lstat().st_uid == 0 and os.readlink(p) == target, 'SONAME link mismatch')
    for folder in ('bin', 'lib', 'firmware'):
        expected = {Path(n).name for n in files if Path(n).parent == runtime / folder}
        if folder == 'lib':
            expected |= set(links)
        need({p.name for p in (runtime / folder).iterdir()} == expected, 'Unpinned runtime file')
    need((runtime / 'bin/nvidia-smi').is_file() and
         'libnvidia-ml.so.1' in links and 'libcuda.so.1' in links, 'Missing query runtime')
    return receipt



def guard_contracts():
    import sys
    sys.dont_write_bytecode=True
    sys.path.insert(0,str(ROOTKIT))
    trusted(ROOTKIT/'contracts.py')
    spec=importlib.util.spec_from_file_location('r54_guard_contracts',ROOTKIT/'contracts.py')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    return mod

def guard_live(boot, nonce, minimum):
    m, ready = read_json(RUN / 'manifest.json'), read_json(RUN / 'ready.json')
    validate_guard(m, ready, boot, nonce, clock(), minimum)
    need(read_json(STATE / ('armed-' + boot + '.json')) == m, 'Durable arm state mismatch')
    C=guard_contracts();C.artifacts(m['artifacts'],boot)
    receipts=[read_json(STATE/('controller-'+str(i)+'-'+boot+'.json')) for i in (0,1)]
    need(C.receipts_ok(receipts,m),'Both retained controller readiness receipts required')
    for i,r in enumerate(receipts):check_hash(STATE/('controller-'+str(i)+'-journal-'+boot+'.json'),r['journal_sha256'])
    need(command('/usr/bin/systemctl', 'is-active', 'bob-acio-router54-trial.service') == 'active', 'Guard not active')
    need(command('/usr/bin/systemctl', 'show', '--property=MainPID', '--value',
                 'bob-acio-router54-trial.service') == str(ready['guard_pid']), 'Guard PID mismatch')
    cmd = Path('/proc', str(ready['guard_pid']), 'cmdline').read_bytes().split(b'\0')
    need(str(ROOTKIT / 'runtime_guard.py').encode() in cmd, 'Wrong guard process')
    need(not (RUN / 'ack.json').exists(), 'Unexpected runtime acknowledgement')
    result = STATE / 'result.json'
    if result.exists():
        previous = read_json(result)
        need(previous.get('boot_id') != boot, 'Runtime guard already terminal')
    need(any(os.readlink(p) in ('/dev/watchdog0', '/dev/watchdog') for p in Path('/proc/1/fd').iterdir()),
         'PID1 hardware watchdog absent')
    need(command('/usr/bin/systemctl', 'show', '--property=RuntimeWatchdogUSec', '--value') == '1min',
         'Hardware watchdog changed')
    validate_guard(m, ready, boot, nonce, clock(), minimum)
    return m


def verify_modules_absent():
    names = {p.name for p in Path('/sys/module').iterdir()}
    need(not names & FORBIDDEN_MODULES, 'GPU driver module already present')
    need(not Path('/sys/bus/pci/drivers/nvidia').exists(), 'NVIDIA driver already registered')
    need(not Path('/proc/driver/nvidia').exists(), 'NVIDIA proc nodes already present')
    need(not list(Path('/dev').glob('nvidia*')), 'NVIDIA device nodes already present')


def check_active_trial(cmd, parameter, chosen):
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

 if [x for x in cmd if x.startswith('bob_kernel_mode=')] != ['bob_kernel_mode=late-arm-r54-native-driver']:raise RuntimeError('wrong late-arm mode')
 if [x for x in cmd if x.startswith('bob_kernel_trial=')] != ['bob_kernel_trial=oldm1-r54-20261004']:raise RuntimeError('wrong trial')
 if [x for x in cmd if x.startswith('bob_j293_overlay=')] != ['bob_j293_overlay=efi-disabled-r52']:raise RuntimeError('wrong overlay')
 if any(x.startswith(('thunderbolt_apple.root_router_only=','bob_kernel_isolation=','bob_kernel_baseline=')) for x in cmd):raise RuntimeError('old mode forbidden')
 if parameter != 'Y':raise RuntimeError('router parameter not armed')
 if chosen != b'disabled-r52\0':raise RuntimeError('wrong EFI overlay provenance')
 for key in ('thunderbolt_apple.route_chain_prepare','thunderbolt_apple.route_chain_tunnels','pcie_apple_apciec_experimental.endpoint_chain_resources'):
     if [x for x in cmd if x.split('=',1)[0]==key]!=[key+'=1']:raise RuntimeError('Missing exact chain opt-in: '+key)


def preflight(args):
    need(os.geteuid() == 0 and os.uname().release == KERNEL and os.uname().machine == 'aarch64',
         'Wrong user, kernel or architecture')
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    need(boot == args.boot_id and re.fullmatch('[0-9a-f-]{36}', boot), 'Wrong boot')
    trusted(args.manifest)
    check_hash(args.manifest, args.manifest_sha256)
    manifest = read_json(args.manifest)
    need(manifest['schema'] == 1 and manifest['kernel'] == KERNEL, 'Wrong manifest schema/kernel')
    bind_identity(manifest,boot)
    for name,digest in manifest['probe_files'].items():
        need('/' not in name,'Unexpected probe file name');check_hash(Path(__file__).parent/name,digest)
    check_hash('/boot/efi/m1n1/boot.bin', BOOT_SHA)
    need(set(manifest['guard_files'])=={'arm.py','runtime_guard.py','proven_guard.py','contracts.py','activate_controllers.py','five_policy.py'},'Incomplete guard source pins')
    for name,digest in manifest['guard_files'].items():trusted(ROOTKIT/name);check_hash(ROOTKIT/name,digest)
    check_active_trial(Path('/proc/cmdline').read_text().split(),
                       Path('/sys/module/thunderbolt_apple/parameters/root_router_only').read_text().strip(),
                       Path('/sys/firmware/devicetree/base/chosen/bob,j293-efi-overlay').read_bytes())
    need(Path('/sys/module/pcie_apple_apciec_experimental/parameters/endpoint_native_driver').read_text().strip() == 'Y',
         'Native promotion parameter inactive')
    for module,name in (('thunderbolt_apple','external_endpoint_pair'),('pcie_apple_apciec_experimental','endpoint_pair')):
     if Path('/sys/module',module,'parameters',name).read_text().strip()!='Y':raise RuntimeError('inactive pair parameter '+module+'.'+name)
    prior = read_json('/var/lib/bob-kernel-router54-trial/result.json')
    need(prior.get('boot_id') == boot and prior.get('kernel') == KERNEL and
         prior.get('trial_id') == 'oldm1-r54-20261004' and prior.get('outcome') == 'acknowledged',
         'Kernel SSH trial not acknowledged')
    need(Path('/sys/module/acio_runtime_enable').exists() and Path('/sys/module/acio_runtime_enable_port1').exists(), 'One of two controller modules absent')
    state = guard_live(boot, args.activation_nonce, 90)
    guard_contracts().artifacts(state['artifacts'],boot,verify=True)
    for name,key in [('kernel_image','image'),('module','nvidia'),('uvm','uvm')]:
        need(manifest[name]['path']==state['artifacts'][key]['path'] and manifest[name]['sha256']==state['artifacts'][key]['sha256'],'Probe artifacts differ from guard: '+key)
    entries = journal()
    lines = messages(entries, boot, state['armed_monotonic'])
    validate_ready_logs(lines)
    reject_faults(lines)
    devices = pci_snapshot()
    validate_pci(devices)
    for target in TARGETS:
        group=Path(devices[target]['iommu_group'])
        need({p.name for p in (group/'devices').iterdir()}=={target},'IOMMU group is not per-GPU')
    verify_modules_absent()
    runtime = verify_runtime(Path(args.runtime), manifest['runtime'])
    module = manifest['module']
    need(module['path'] == str(MODULE) and module['version'] == VERSION and
         module['vermagic'] == KERNEL + ' SMP preempt mod_unload aarch64', 'Wrong module metadata')
    trusted(MODULE)
    check_hash(MODULE, module['sha256'])
    for field in ('vermagic', 'version'):
        need(command('/usr/sbin/modinfo', '-F', field, str(MODULE)) == module[field], 'Module ' + field + ' mismatch')
    need(command('/usr/sbin/modinfo', '-F', 'name', str(MODULE)) == 'nvidia', 'Wrong module name')
    parms = command('/usr/sbin/modinfo', '-F', 'parmtype', str(MODULE)).splitlines()
    need(all(any(p.startswith(k + ':') for p in parms) for k in OPTIONS), 'Required module parameter absent')
    return manifest, state, {'journal': entries, 'pci': devices, 'runtime_version': runtime['version']}


def exclusive_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def bounded_process(argv, out, prefix, seconds, env):
    """Bound the observer's wait; retain an in-flight child for guard recovery."""
    with (out / (prefix + '.stdout')).open('xb') as stdout, (out / (prefix + '.stderr')).open('xb') as stderr:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                 env=env, start_new_session=True)
        try:
            rc = child.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            exclusive_json(out / (prefix + '-timeout.json'),
                           {'pid': child.pid, 'boottime': clock(), 'seconds': seconds,
                            'action': 'No signal, retry or release; mandatory stock guard retains recovery'})
            raise Rejected(prefix + ' remains in flight; stock guard owns recovery')
    need(rc == 0, prefix + ' returned ' + str(rc))



def pci_readonly_snapshot():
    """Read standard config/AER on the exact five-device path, never BAR MMIO.

    O_RDONLY + pread only. No status clear, mask change, reset or initialization.
    The caller checks the original guard before and after the bounded snapshot.
    """
    result = {'boottime': clock(), 'devices': {}, 'read_only': True}
    entries=[('0001:%02x:00.0'%j,HOST,j in (3,6,9),j==0) for j in range(10)]
    f=identity()['fourth'];domain=f['bdf'][:4]
    entries += [(domain+':'+s,F.HOST1,s in ('03:00.0','06:00.0'),s=='00:00.0') for s in ('00:00.0','01:00.0','02:00.0','03:00.0','02:01.0','04:00.0','05:00.0','06:00.0')]
    for bdf,host,is_gpu,is_root in entries:
        p = Path('/sys/bus/pci/devices') / bdf
        need(str(p.resolve()).startswith(host), 'Snapshot escaped exact host')
        expected = 0x2d0410de if is_gpu else (0x1010106b if is_root else 0x57868086)
        aer = 0x1b8 if is_gpu else 0x100
        express = 0x60 if is_gpu else (0x70 if is_root else 0xc0)
        pm = 0x40 if is_gpu or is_root else 0x80
        offsets = sorted(set(list(range(0, 0x34, 4)) +
                             [pm, pm + 4, express, express + 4, express + 8, express + 0xc, express + 0x10, express + 0x2c, express + 0x30, aer] +
                             list(range(aer + 4, aer + 0x2c, 4))))
        fd = os.open(p / 'config', os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            data = {}
            for off in offsets:
                raw = os.pread(fd, 4, off)
                need(len(raw) == 4, 'Short PCI configuration read')
                data['%03x' % off] = '%08x' % int.from_bytes(raw, 'little')
                if off == 0:
                    need(int.from_bytes(raw, 'little') == expected, 'Snapshot PCI identity changed')
        finally:
            os.close(fd)
        need(int(data['%03x' % express], 16) & 0xff == 0x10, 'PCIe capability moved')
        need(int(data['%03x' % aer], 16) & 0xffff == 1, 'AER capability moved')
        result['devices'][bdf] = data
    result['finished_boottime'] = clock()
    return result


def validate_query(text):
    rows = list(csv.reader(text.strip().splitlines()))
    need(len(rows) == 1 and len(rows[0]) == 7, 'Unexpected query row count/format')
    row = [x.strip() for x in rows[0]]
    need(row[0].lower() in (TARGET, '00000001:03:00.0') and row[1].startswith('GPU-') and
         row[2] == VERSION and '5060 Ti' in row[3], 'Query returned another GPU/driver')
    need(row[4].isdigit() and 0 <= int(row[4]) <= 85, 'Invalid or excessive GPU temperature')
    need(row[6] == VERSION, 'GSP firmware version mismatch')
    return dict(zip(('pci_bus_id', 'uuid', 'driver_version', 'name', 'temperature_gpu',
                     'power_draw_watts', 'gsp_firmware_version'), row))


def validate_query_proc(text, info):
    rows = list(csv.reader(text.strip().splitlines()))
    need(len(rows) == 1 and len(rows[0]) == 6, 'Unexpected six-field query row')
    firmware = re.findall(r'^GPU Firmware:\s+(\S+)\s*$', info, re.M)
    need(firmware == [VERSION], 'Actual proc GPU Firmware mismatch')
    import io
    out = io.StringIO()
    csv.writer(out).writerow(rows[0] + firmware)
    return validate_query(out.getvalue())


def validate_group_query(rows,information):
    c=identity()
    return Q.query_five(rows,information,c,c['boot_id'])


class LiveProbe:
    def __init__(self, args, manifest, state):
        self.args, self.manifest, self.state = args, manifest, state
        self.out = STATE / ('native-probe-' + args.boot_id)
        self.start = clock()
        self.monotonic = time.clock_gettime(time.CLOCK_MONOTONIC)
        self.kmsg = KernelLog()

    def budget(self, minimum):
        need(clock() - self.start <= 180, 'Native observer 180-second budget exhausted')
        need(self.state['deadline_boottime'] - clock() >= minimum,
             'Insufficient fresh guard reserve before action')

    def checkpoint(self, minimum=30):
        self.budget(minimum)
        guard_live(self.args.boot_id, self.args.activation_nonce, minimum)
        self.budget(minimum)

    def kernel_gate(self, initial=False):
        entries = self.kmsg.drain()
        if self.out.is_dir():
            with (self.out / 'kernel-records.jsonl').open('a') as stream:
                for entry in entries:
                    stream.write(json.dumps(entry) + '\n')
                stream.flush()
                os.fsync(stream.fileno())
        after = self.state['armed_monotonic'] if initial else self.monotonic
        reject_faults([x['message'] for x in entries if x['monotonic_microseconds'] / 1e6 >= after])
        return entries

    def consume(self, evidence):
        self.checkpoint(150)
        verify_modules_absent()
        validate_pci(pci_snapshot())
        check_hash(MODULE, self.manifest['module']['sha256'])
        trusted(STATE, directory=True)
        evidence['direct_kernel_before_load'] = self.kernel_gate(initial=True)
        self.budget(150)
        # The durable per-boot O_EXCL marker is created before any override/load.
        exclusive_json(STATE / ('native-probe-attempt-' + self.args.boot_id + '.json'),
                       {'boot_id': self.args.boot_id, 'nonce': self.args.activation_nonce,
                        'manifest_sha256': self.args.manifest_sha256,
                        'observed_boottime': clock(), 'module_sha256': self.manifest['module']['sha256']})
        self.out.mkdir(mode=0o700)
        exclusive_json(self.out / 'preflight.json', evidence)

    def load(self):
        self.checkpoint(150)
        exclusive_json(self.out / 'pci-config-before-load.json', pci_readonly_snapshot())
        self.checkpoint(150)
        for target in TARGETS:
            Path('/sys/bus/pci/devices',target,'driver_override').write_text('nvidia\n')
            need(Path('/sys/bus/pci/devices',target,'driver_override').read_text().strip()=='nvidia','Override readback mismatch')
        self.budget(150)
        bounded_process(['/usr/sbin/insmod', str(MODULE), *[k + '=' + str(v) for k, v in OPTIONS.items()]],
                        self.out, 'insmod', 90, ENV)
        # insmod has returned, so this cannot overlap an in-flight load.
        # Preserve the original failure state before post_load rejects it.
        self.checkpoint(30)
        exclusive_json(self.out / 'pci-config-after-load.json', pci_readonly_snapshot())
        self.checkpoint(30)

    def post_load(self):
        self.checkpoint()
        self.kernel_gate()
        entries=journal();exclusive_json(self.out/'post-load-journal.json',{'entries':entries})
        reject_faults(messages(entries,self.args.boot_id,self.monotonic))
        need(Path('/sys/module/nvidia/version').read_text().strip()==VERSION,'Driver version mismatch')
        for key,value in OPTIONS.items():
            actual=Path('/sys/module/nvidia/parameters',key).read_text().strip()
            need(actual==value if isinstance(value,str) else int(actual,0)==value,'Driver parameter mismatch: '+key)
        root=Path('/proc/driver/nvidia/gpus')
        need(root.is_dir() and {x.name for x in root.iterdir()}==set(TARGETS),'Not all five probes completed')
        records={};minors=set();all_irqs=set();controller_irqs={0:set(),1:set()}
        for target in TARGETS:
            info=(root/target/'information').read_text()
            minor=re.findall(r'^Device Minor:\s+([0-4])\s*$',info,re.M)
            need(len(minor)==1 and int(minor[0]) not in minors,'Missing/duplicate device minor')
            minors.add(int(minor[0]));records[target]={'information':info,'minor':int(minor[0])}
            irqroot=Path('/sys/bus/pci/devices',target,'msi_irqs')
            irqs=list(irqroot.iterdir()) if irqroot.is_dir() else []
            need(1<=len(irqs)<=32 and all(x.name.isdigit() and x.read_text().strip() in ('msi','msix') for x in irqs),'GPU IRQ allocation missing')
            current={x.name for x in irqs};need(not current&all_irqs,'Duplicate GPU interrupt allocation');all_irqs|=current
            controller_irqs[0 if target in PORT0_TARGETS else 1]|=current
        need(minors=={0,1,2,3,4} and all(0<len(v)<=32 for v in controller_irqs.values()),'Invalid per-controller GPU/interrupt inventory')
        snapshot=pci_snapshot();exclusive_json(self.out/'post-load-pci.json',snapshot);validate_pci(snapshot,after=True)
        names={x.name for x in Path('/sys/module').iterdir()}
        need(not names&(FORBIDDEN_MODULES-{'nvidia'}),'Unexpected GPU module autoload')
        majors=[x.split() for x in Path('/proc/devices').read_text().splitlines()]
        need([x for x in majors if len(x)==2 and x[1]=='nvidia']==[['195','nvidia']],'Wrong NVIDIA major')
        for name,minor in [('nvidia0',0),('nvidia1',1),('nvidia2',2),('nvidia3',3),('nvidia4',4),('nvidiactl',255)]:
            path=Path('/dev')/name
            if not path.exists() and not path.is_symlink():os.mknod(path,stat.S_IFCHR|0o600,os.makedev(195,minor))
            st=path.lstat();need(stat.S_ISCHR(st.st_mode) and st.st_rdev==os.makedev(195,minor) and st.st_uid==0,'Wrong character device')
        need({x.name for x in Path('/dev').glob('nvidia*')}=={'nvidia0','nvidia1','nvidia2','nvidia3','nvidia4','nvidiactl'},'Unexpected NVIDIA nodes')
        link=pci_readonly_snapshot();exclusive_json(self.out/'pcie-link-after-load.json',link)
        for target in TARGETS:
            value=int(link['devices'][target]['070'],16)
            need(((value>>16)&15)==1 and (value&3)==0,'Gen1/ASPM-off not observed: '+target)
        need(Path('/sys/module/nvidia/parameters/NVreg_EnablePCIeGen3').read_text().strip()=='0','Conflicting link policy')
        exclusive_json(self.out/'probe-information.json',{'devices':records,'options':OPTIONS,'pcie_gen_observed':1,'aspm_observed_off':True})



    def query(self):
        self.checkpoint(35);self.kernel_gate()
        reject_faults(messages(journal(),self.args.boot_id,self.monotonic))
        argv=[str(RUNTIME/'bin/nvidia-smi'),'--query-gpu=pci.bus_id,uuid,driver_version,name,temperature.gpu,power.draw','--format=csv,noheader,nounits']
        self.budget(35);bounded_process(argv,self.out,'nvidia-smi',15,dict(ENV,LD_LIBRARY_PATH=str(RUNTIME/'lib')))
        rows=list(csv.reader((self.out/'nvidia-smi.stdout').read_text().strip().splitlines()))
        info={target:(Path('/proc/driver/nvidia/gpus')/target/'information').read_text() for target in TARGETS}
        result=validate_group_query(rows,info)
        self.kernel_gate();entries=journal();exclusive_json(self.out/'post-query-journal.json',{'entries':entries})
        reject_faults(messages(entries,self.args.boot_id,self.monotonic));self.checkpoint(20)
        c=copy.deepcopy(identity());c['fifth']['uuid']=result['fifth_uuid_observed']
        F.mining_config(c,self.args.boot_id)
        sealed=STATE/('mining-identity-'+self.args.boot_id+'.json');exclusive_json(sealed,c)
        result['identity_config']={'path':str(sealed),'sha256':sha(sealed)}
        return result



    def finish(self, outcome, detail):
        if self.out.is_dir():
            if outcome.startswith('stopped'):
                # Preserve failed-load evidence too; errors here never cause
                # another device action or replace the original failure.
                try:
                    self.kernel_gate()
                except Exception:
                    pass
                try:
                    exclusive_json(self.out / 'failure-journal.json', {'entries': journal()})
                except Exception:
                    pass
            exclusive_json(self.out / 'result.json', {'outcome': outcome, 'detail': detail,
                           'boot_id': self.args.boot_id, 'nonce': self.args.activation_nonce,
                           'observed_boottime': clock(), 'deadline_boottime': self.state['deadline_boottime'],
                           'runtime_ack': False, 'owners_retained': True, 'mining_started': False})


def perform(probe, evidence):
    """Single forward path; dependency-injected tests cannot touch hardware."""
    try:
        probe.consume(evidence)
        probe.load()
        probe.post_load()
        result = probe.query()
        probe.finish('query-complete-stock-return-mandatory', result)
        return 0
    except Exception as error:
        probe.finish('stopped-stock-return-mandatory', str(error))
        raise


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest', required=True)
    p.add_argument('--manifest-sha256', required=True)
    p.add_argument('--boot-id', required=True)
    p.add_argument('--activation-nonce', required=True)
    p.add_argument('--runtime', required=True)
    args = p.parse_args()
    try:
        manifest, state, evidence = preflight(args)
        return perform(LiveProbe(args, manifest, state), evidence)
    except Exception as error:
        print('Native probe stopped: ' + str(error) + '; mandatory stock guard remains in charge.', flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
