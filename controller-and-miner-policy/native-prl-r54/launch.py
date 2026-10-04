#!/usr/bin/env python3
"""Official KRig: five admitted native GPUs, one mining attempt, fixed VPN path, 85C stop."""
import argparse, ast, csv, hashlib, io, json, math, os, re, select, signal, stat
import subprocess, sys, time
from pathlib import Path
import network as N
import five_policy as F

if not __debug__:
    raise RuntimeError('Python optimization disables required admission assertions')

HERE = Path(__file__).resolve().parent
RUNTIME = Path('/usr/local/lib/bob-native-runtime-615-r40')
MINER = Path('/usr/local/lib/bob-native-prl-miner-1.5.6')
LATCH = Path('/run/bob-native-prl-attempt.once')
POOL = 'stratum+ssl://prl-hk.kryptex.network:8048'
PINS = {'krig-miner': 'be4c7b85071ff7b73f95d8fe7e75d2f2c7dd98463fa0d261b16444df9dd27e1c',
        'libpearl_gemm_capi.so': 'eeb061eae2310fd36e1cb524f97998ca4f5bc2884d0bf0909ec7c091ae30a1c4',
        'libpearl_mining_capi.so': '94e69218cbb535bb75a991635b7f9d206855faa88b140c2e46fd102a36bd494e'}
ACCOUNT_SHA = 'cd14d31efe8482820caef25a06a2bf0577dc8b9dd0ba092ae72263f5fc66e585'
RUNTIME_MANIFEST_SHA = '00eb1c824fd4328ee00dfc7cc32f5c075ce9bd04a1d65c8adf7b478a6408e11b'
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
       'LD_LIBRARY_PATH': str(RUNTIME / 'lib') + ':' + str(MINER)}
sha = lambda data: hashlib.sha256(data).hexdigest()
RETAINED_QUERIES = []

def private_fd(fd, limit=131072):
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
        raise ValueError('Private root-owned regular input required')
    os.lseek(fd, 0, os.SEEK_SET)
    raw = os.read(fd, limit + 1)
    if len(raw) > limit: raise ValueError('Input exceeds bound')
    return raw

def root_bytes(path):
    p = Path(path)
    if p.is_symlink(): raise ValueError('Symlink artifact refused')
    st = p.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise ValueError('Root-owned non-writable artifact required')
    return p.read_bytes()

def extract_account(raw):
    if sha(raw) != ACCOUNT_SHA: raise ValueError('Unreviewed account source')
    found = set()
    for node in ast.walk(ast.parse(raw)):
        if isinstance(node, (ast.List, ast.Tuple)):
            for a, b in zip(node.elts, node.elts[1:]):
                if isinstance(a, ast.Constant) and a.value == '--wallet' and isinstance(b, ast.Constant) and isinstance(b.value, str):
                    found.add(b.value)
    if len(found) != 1: raise ValueError('Ambiguous account')
    return found.pop()

def manifest_check(m, boot, now):
    if m.get('schema') != 2 or m.get('boot_id') != boot or m.get('stage') != 'native-prl-five-card-official-trial':
        raise ValueError('Wrong admitted group stage or boot')
    d = m.get('device', {})
    identity=m.get('identity_config',{})
    if not re.fullmatch('[0-9a-f]{64}',identity.get('sha256','')) or not Path(identity.get('path','')).is_absolute():
        raise ValueError('Explicit root-owned five-card identity required')
    raw=root_bytes(identity['path'])
    if sha(raw)!=identity['sha256']:raise ValueError('Identity configuration pin changed')
    config=json.loads(raw)
    F.device_group(d,config,boot)
    for key in ['driver_proof','vpn_proof','owner_proof']:
        r=m.get(key,{})
        if not re.fullmatch('[0-9a-f]{64}',r.get('sha256','')) or not Path(r.get('path','')).is_absolute():
            raise ValueError('Missing admitted proof pin')
    age=now-m.get('approved_boottime',-1e99)
    if not math.isfinite(age) or not 0<=age<=300: raise ValueError('Stale group admission')
    nodes=m.get('device_nodes',{})
    if set(nodes)!={'/dev/nvidia0','/dev/nvidia1','/dev/nvidia2','/dev/nvidia3','/dev/nvidia4','/dev/nvidiactl','/dev/nvidia-uvm'}:
        raise ValueError('Wrong device-node set')
    for minor in range(5):
        if nodes['/dev/nvidia'+str(minor)]!=[195,minor]:raise ValueError('Wrong GPU character identity')
    if nodes['/dev/nvidiactl']!=[195,255]:raise ValueError('Wrong NVIDIA control node')
    if not isinstance(nodes['/dev/nvidia-uvm'],list) or len(nodes['/dev/nvidia-uvm'])!=2 or any(type(x)is not int or x<0 for x in nodes['/dev/nvidia-uvm']):
        raise ValueError('Invalid UVM identity')
    if not 1<=nodes['/dev/nvidia-uvm'][0]<=4095 or nodes['/dev/nvidia-uvm'][1]!=0:
        raise ValueError('Invalid UVM character identity')
    return d



def proof_check(kind, proof, m, now):
    if proof.get('approved') is not True or proof.get('boot_id') != m['boot_id']:
        raise ValueError('Proof not admitted for current boot')
    raw=root_bytes(m['identity_config']['path'])
    if sha(raw)!=m['identity_config']['sha256']:raise ValueError('Identity pin changed')
    config=json.loads(raw);F.device_group(m['device'],config,m['boot_id'])
    if kind in ('driver_proof','owner_proof'):
        for key in ('kernel_sha256','nvidia_sha256','uvm_sha256','phase30_evidence_sha256'):
            if proof.get(key)!=config[key]:raise ValueError('Proof artifact/phase20 identity differs: '+key)
    if kind == 'driver_proof':
        if proof.get('device') != m['device'] or proof.get('native_query_verified') is not True:
            raise ValueError('Actual native NVIDIA query proof required')
    elif kind == 'owner_proof':
        if proof.get('device') != m['device'] or proof.get('native_host_retained') is not True or proof.get('mining_lifetime_admitted') is not True or proof.get('guard_reconciled_by_root') is not True:
            raise ValueError('Native host/boot lifetime not admitted')
    elif kind == 'vpn_proof':
        age = now - proof.get('validated_boottime', -1e99)
        if not math.isfinite(age) or not 0 <= age <= 300 or proof.get('proxy') != 'PROVISION_NETWORK_ENDPOINT:11182' or proof.get('target') != 'prl-hk.kryptex.network:8048' or proof.get('authenticated_socks5') is not True or proof.get('vpn_only_fail_closed') is not True:
            raise ValueError('Fresh authenticated VPN-only proof required')

def parse_one_temperature(text, d):
    rows = list(csv.reader(io.StringIO(text.strip())))
    if len(rows) != 1 or len(rows[0]) != 3: raise ValueError('Missing GPU telemetry')
    uuid, bdf, raw = [x.strip() for x in rows[0]]
    parts = bdf.lower().split(':')
    if len(parts) != 3 or not re.fullmatch(r'[0-9a-f]{4}(?:[0-9a-f]{4})?', parts[0]): raise ValueError('Invalid PCI domain')
    bdf = f'{int(parts[0],16):04x}:' + ':'.join(parts[1:])
    if uuid != d['uuid'] or bdf != d['bdf'] or not re.fullmatch(r'\d{1,3}', raw):
        raise ValueError('Invalid GPU telemetry')
    value = int(raw)
    if not 0 <= value <= 125: raise ValueError('Invalid temperature')
    return value


def parse_temperature(text,d):
    rows=list(csv.reader(io.StringIO(text.strip())))
    if len(rows)!=5 or any(len(row)!=3 for row in rows):raise ValueError('Missing group telemetry')
    expected={x['uuid']:x for x in d['devices']};seen=set();temps=[]
    for row in rows:
        uid=row[0].strip()
        if uid not in expected or uid in seen:raise ValueError('Wrong or duplicate GPU telemetry')
        out=io.StringIO();csv.writer(out).writerow(row)
        temps.append(parse_one_temperature(out.getvalue(),expected[uid]));seen.add(uid)
    if seen!=set(expected):raise ValueError('Incomplete group telemetry')
    return max(temps)



def query_temperature(d):
    started = time.monotonic()
    p = subprocess.Popen([str(RUNTIME / 'bin/nvidia-smi'),
         '--query-gpu=uuid,pci.bus_id,temperature.gpu', '--format=csv,noheader,nounits'],
         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=ENV)
    try: stdout = p.communicate(timeout=3)[0]
    except subprocess.TimeoutExpired:
        # Never signal a potentially in-flight driver call. Stop mining; root
        # retains all owners and handles a stuck query with normal recovery.
        RETAINED_QUERIES.append(p)
        raise RuntimeError('Telemetry deadline exceeded; query retained') from None
    if p.returncode != 0 or not 0 <= time.monotonic() - started < 3:
        raise ValueError('Unavailable or stale telemetry')
    return parse_temperature(stdout.decode(), d)

def temperature_gate(d, query=query_temperature):
    temp = query(d)
    if type(temp) is not int or not 0 <= temp < 85: raise ValueError('Thermal preflight refused')

def launch_owned(argv, *, pass_fds=(), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, drop=False, env=None):
    parent = os.getpid()
    def prepare():
        if drop: N.drop_privileges(parent)
        else: N.bind_parent(parent)
    p = subprocess.Popen(argv, pass_fds=pass_fds, stdin=stdin, stdout=stdout,
                         stderr=stderr, close_fds=True, env=env or ENV,
                         cwd='/', preexec_fn=prepare)
    try: return p, os.pidfd_open(p.pid)
    except BaseException:
        p.kill()
        p.wait(timeout=10)
        raise

def stop_owned(owned, clock=time.monotonic):
    errors = {}
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for _, p, fd in owned:
            if p.poll() is None:
                try: signal.pidfd_send_signal(fd, sig)
                except ProcessLookupError: pass
                except OSError: errors[fd] = True
        end = clock() + 10
        for _, p, _ in owned:
            if p.poll() is None and clock() < end:
                try: p.wait(timeout=max(0, end - clock()))
                except subprocess.TimeoutExpired: pass
    return [{'role': role, 'returncode': p.poll(), 'exit_unconfirmed': p.poll() is None,
             'signal_failed': errors.get(fd, False)} for role, p, fd in owned]

def monitor(owned, d, query=query_temperature, sleep=time.sleep):
    while True:
        if any(p.poll() is not None for _, p, _ in owned): return 'owned-process-exited'
        try: value = query(d)
        except Exception: return 'telemetry-failed'
        if type(value) is not int or not 0 <= value <= 125: return 'telemetry-failed'
        if value >= 85: return 'thermal-stop'
        sleep(1)

def miner_argv(account, d):
    return [str(MINER / 'krig-miner'), '--coin', 'pearl', '--no-rocm', '--url', POOL,
            '--user', account + '/MacGPU' + str(d['slot']),
            '--gpu-no-reset-oc', '--no-tui', '--api-host', 'PROVISION_NETWORK_ENDPOINT', '--api-port', '12002']

def static_preflight(m, kit_sha):
    assert os.geteuid() == 0 and os.uname().machine == 'aarch64'
    assert os.uname().release == '7.3.0-rc1-j293-router-r54' and os.sysconf('SC_PAGE_SIZE') == 16384
    assert len(list(Path('/proc/self/task').iterdir())) == 1
    assert not any(p.read_text().strip() == 'krig-miner' for p in Path('/proc').glob('[0-9]*/comm') if p.exists())
    assert not os.environ.get('LD_PRELOAD') and not os.environ.get('LD_AUDIT')
    raw = root_bytes(HERE / 'KIT-PINS.json')
    assert sha(raw) == kit_sha
    for name, digest in json.loads(raw).items(): assert sha(root_bytes(HERE / name)) == digest
    assert sha(root_bytes(RUNTIME / 'MANIFEST.json')) == RUNTIME_MANIFEST_SHA
    runtime = json.loads(root_bytes(RUNTIME / 'MANIFEST.json'))
    for name, rec in runtime['files'].items():
        if name.startswith('lib'): assert sha(root_bytes(RUNTIME / 'lib' / name)) == rec['sha256']
    assert sha(root_bytes(RUNTIME / 'bin/nvidia-smi')) == runtime['files']['nvidia-smi']['sha256']
    for name, digest in PINS.items(): assert sha(root_bytes(MINER / name)) == digest
    for name, value in {'GpuInitOnProbe': '1', 'EnableGpuFirmware': '1', 'EnableResizableBar': '0', 'EnableMSI': '1', 'DynamicPowerManagement': '0'}.items():
        assert Path('/sys/module/nvidia/parameters/NVreg_' + name).read_text().strip() == value
    assert Path('/sys/module/nvidia_uvm').is_dir()
    gpus = [p for p in Path('/sys/bus/pci/devices').iterdir()
            if (p / 'vendor').read_text().strip() == '0x10de' and int((p / 'class').read_text(), 16) >> 16 == 3]
    assert {p.name for p in gpus} == {d['bdf'] for d in m['device']['devices']}
    for p in gpus:
        assert (p / 'driver').resolve().name == 'nvidia'
        for key,value in {'device':'0x2d04','subsystem_vendor':'0x1458','subsystem_device':'0x41cd'}.items():
            assert (p/key).read_text().strip()==value
    assert Path('/sys/module/nvidia/parameters/NVreg_RegistryDwords').read_text().strip()=='RMPcieLinkSpeed=0x800002AA;PCIEPowerControl=0x3'

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--manifest-fd', type=int, required=True)
    ap.add_argument('--account-source-fd', type=int, required=True)
    ap.add_argument('--socks-credentials-fd', type=int, required=True)
    ap.add_argument('--kit-sha256', required=True)
    a = ap.parse_args()
    descriptor_inputs = [a.manifest_fd, a.account_source_fd, a.socks_credentials_fd]
    if len(set(descriptor_inputs)) != 3 or min(descriptor_inputs) < 3:
        raise ValueError('Three distinct private descriptors >=3 required')
    m = json.loads(private_fd(a.manifest_fd))
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    now = time.clock_gettime(time.CLOCK_BOOTTIME)
    d = manifest_check(m, boot, now)
    static_preflight(m, a.kit_sha256)
    for kind in ['driver_proof', 'owner_proof', 'vpn_proof']:
        raw = root_bytes(m[kind]['path'])
        if sha(raw) != m[kind]['sha256']: raise ValueError('Proof digest mismatch')
        proof_check(kind, json.loads(raw), m, now)
    account = extract_account(private_fd(a.account_source_fd))
    # Validate proxy credentials privately before claiming an attempt; worker
    # uses the original descriptor and never places credentials in argv/logs.
    import fixed_prl_relay as R
    assert R.credentials_from_fd(a.socks_credentials_fd)
    fd = os.open(LATCH, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.write(fd, (boot + '\n').encode()); os.fsync(fd); os.close(fd)
    work = Path('/run/bob-native-prl-' + boot)
    work.mkdir(mode=0o700, exist_ok=False)
    receipt = work / 'result.json'
    owned, close_fds = [], []
    reason = 'prelaunch-refused'
    listener = None
    def add(role, pair):
        p, fd = pair; owned.append((role, p, fd)); return p
    def stop_signal(signum, frame): raise InterruptedError()
    signal.signal(signal.SIGTERM, stop_signal); signal.signal(signal.SIGINT, stop_signal)
    stage = 'temperature-preflight'
    try:
        temperature_gate(d)
        stage = 'relay-setup'
        to_read, to_write = os.pipe(); from_read, from_write = os.pipe(); ready_read, ready_write = os.pipe()
        close_fds.extend([to_read, to_write, from_read, from_write, ready_read, ready_write])
        parent = str(os.getpid())
        relay = add('relay', launch_owned(['/usr/bin/python3', str(HERE / 'stream_worker.py'), 'relay',
              '--parent', parent, '--credentials-fd', str(a.socks_credentials_fd), '--ready-fd', str(ready_write)],
              stdin=to_read, stdout=from_write, pass_fds=(a.socks_credentials_fd, ready_write)))
        os.close(ready_write); close_fds.remove(ready_write)
        if not select.select([ready_read], [], [], 12)[0] or os.read(ready_read, 1) != b'R' or relay.poll() is not None:
            raise ValueError('Authenticated fixed relay unavailable')
        stage = 'network-isolation'
        listener = N.isolate(work, m['device_nodes'])
        add('forwarder', launch_owned(['/usr/bin/python3', str(HERE / 'stream_worker.py'), 'forward',
             '--parent', parent, '--listener-fd', str(listener.fileno())], stdin=from_read, stdout=to_write,
             pass_fds=(listener.fileno(),)))
        listener.close(); listener = None
        for fd in close_fds: os.close(fd)
        close_fds.clear()
        temperature_gate(d)
        if any(p.poll() is not None for _, p, _ in owned): raise ValueError('Relay exited before mining')
        stage = 'official-miner-launch'
        with (work / 'miner.log').open('xb') as log:
            os.fchmod(log.fileno(), 0o600)
            miner_env=dict(ENV, CUDA_DEVICE_ORDER='PCI_BUS_ID', CUDA_VISIBLE_DEVICES=','.join(x['uuid'] for x in d['devices']))
            miner = add('miner', launch_owned(miner_argv(account, d), drop=True, stdout=log, stderr=subprocess.STDOUT, env=miner_env))
        (work / 'running.json').write_text(json.dumps({'boot_id': boot, 'supervisor_pid': os.getpid(), 'started_boottime': time.clock_gettime(time.CLOCK_BOOTTIME), 'device': d, 'miner_pid': miner.pid, 'children': {role: p.pid for role, p, _ in owned}, 'network_namespace': os.readlink('/proc/self/ns/net'), 'cutoff_c': 85, 'identity_config': m['identity_config'], 'cuda_visible_devices': ','.join(x['uuid'] for x in d['devices'])}) + '\n')
        (work / 'running.json').chmod(0o600)
        del account
        stage = 'mining-monitor'
        reason = monitor(owned, d)
    except BaseException:
        reason = 'launch-or-supervisor-failed'
        raise
    finally:
        if listener is not None: listener.close()
        for fd in close_fds: os.close(fd)
        stopped = stop_owned(owned)
        for _, _, fd in owned: os.close(fd)
        result = {'boot_id': boot, 'reason': reason, 'stage': stage, 'cutoff_c': 85, 'auto_resume': False,
                  'children': stopped, 'native_host_owners_retained': True, 'gpu_cleanup_proven': False,
                  'no_reset_or_module_operation': True, 'credentials_recorded': False,
                  'retained_query_pids': [p.pid for p in RETAINED_QUERIES]}
        with receipt.open('x') as f: json.dump(result, f, indent=2); f.flush(); os.fsync(f.fileno())
        receipt.chmod(0o600)

if __name__ == '__main__':
    try: main()
    except BaseException:
        print('Native PRL supervisor refused or stopped; inspect private receipt and retain host owners', file=sys.stderr)
        sys.exit(1)
