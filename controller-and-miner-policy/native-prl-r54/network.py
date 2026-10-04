"""Private per-process Linux network/mount setup. Inert on import."""
import ctypes, fcntl, os, re, socket, stat, struct
from pathlib import Path

if not __debug__:
    raise RuntimeError('Python optimization disables required namespace assertions')

LIBC = ctypes.CDLL(None, use_errno=True)
CLONE_NEWNS, CLONE_NEWNET = 0x20000, 0x40000000
MS_BIND, MS_REC, MS_PRIVATE, MS_REMOUNT, MS_RDONLY = 4096, 16384, 262144, 32, 1
UID = GID = 65534
POOL_HOST = 'prl-hk.kryptex.network'

def checked(result):
    if result != 0: raise OSError(ctypes.get_errno(), 'Private namespace setup failed')

def mount(source, target, flags):
    checked(LIBC.mount(None if source is None else os.fsencode(source), os.fsencode(target), None,
                       ctypes.c_ulong(flags), None))

def bind_readonly(source, target):
    mount(source, target, MS_BIND)
    mount(None, target, MS_BIND | MS_REMOUNT | MS_RDONLY)

def validate_private_network(interfaces, route_text):
    if [name for _, name in interfaces] != ['lo']:
        raise ValueError('Unexpected network interface')
    if len(route_text.strip().splitlines()) != 1:
        raise ValueError('Unexpected IPv4 route')

def files_only_hosts_nss(original):
    lines = original.splitlines()
    found = False
    for index, line in enumerate(lines):
        if re.match(r'^\s*hosts\s*:', line):
            lines[index] = 'hosts: files'
            found = True
    if not found: lines.append('hosts: files')
    return '\n'.join(lines) + '\n'

def isolate(work, node_devices):
    """Only this supervisor and later children move; earlier relay stays outside."""
    assert os.geteuid() == 0
    work = Path(work)
    assert work.is_dir() and work.stat().st_uid == 0 and not work.stat().st_mode & 0o077
    checked(LIBC.unshare(CLONE_NEWNS | CLONE_NEWNET))
    mount(None, '/', MS_REC | MS_PRIVATE)
    # glibc NSS may contact host resolver services over filesystem UNIX
    # sockets, which a network namespace does not isolate. Force hosts lookup
    # through this namespace's hosts file, and hide glibc's nscd socket parent.
    nss = work / 'nsswitch.conf'
    nss.write_text(files_only_hosts_nss(Path('/etc/nsswitch.conf').read_text()))
    nss.chmod(0o644)
    bind_readonly(nss, '/etc/nsswitch.conf')
    nscd = Path('/var/run/nscd')
    if nscd.exists():
        if not nscd.is_dir(): raise ValueError('Unexpected nscd socket parent')
        empty = work / 'empty-nscd'
        empty.mkdir(mode=0o755)
        bind_readonly(empty, nscd.resolve())
    hosts = work / 'hosts'
    hosts.write_text('PROVISION_NETWORK_ENDPOINT localhost ' + POOL_HOST + '\n::1 localhost\n')
    hosts.chmod(0o644)
    bind_readonly(hosts, '/etc/hosts')
    resolv = work / 'resolv.conf'
    resolv.write_text('nameserver PROVISION_NETWORK_ENDPOINT\noptions attempts:1 timeout:1\n')
    resolv.chmod(0o644)
    bind_readonly(resolv, '/etc/resolv.conf')
    # Private aliases preserve the host's existing device node ownership/mode.
    assert set(node_devices) == {'/dev/nvidia0', '/dev/nvidia1', '/dev/nvidia2', '/dev/nvidia3', '/dev/nvidia4', '/dev/nvidiactl', '/dev/nvidia-uvm'}
    for index, (target, expected) in enumerate(sorted(node_devices.items())):
        st = os.stat(target)
        assert stat.S_ISCHR(st.st_mode) and [os.major(st.st_rdev), os.minor(st.st_rdev)] == expected
        node = work / ('device-' + str(index))
        os.mknod(node, stat.S_IFCHR | 0o600, st.st_rdev)
        os.chown(node, UID, GID)
        mount(node, target, MS_BIND)
        # /run commonly has nodev. Clear that flag on this private bind only;
        # otherwise the alias cannot be opened despite its correct mode.
        mount(None, target, MS_BIND | MS_REMOUNT | 2 | 8)  # nosuid,noexec
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        request = struct.pack('16sH22x', b'lo', 0)
        flags = struct.unpack('16sH22x', fcntl.ioctl(s.fileno(), 0x8913, request))[1]
        fcntl.ioctl(s.fileno(), 0x8914, struct.pack('16sH22x', b'lo', flags | 1))
    validate_private_network(socket.if_nameindex(), Path('/proc/net/route').read_text())
    assert socket.getaddrinfo(POOL_HOST, 8048, family=socket.AF_INET, type=socket.SOCK_STREAM)[0][4] == ('PROVISION_NETWORK_ENDPOINT', 8048)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(('PROVISION_NETWORK_ENDPOINT', 8048))
    listener.listen(1)
    return listener

def bind_parent(parent):
    if LIBC.prctl(1, 9, 0, 0, 0) != 0 or os.getppid() != parent:
        os._exit(126)

def drop_privileges(parent):
    os.setgroups([])
    os.setgid(GID)
    os.setuid(UID)
    checked(LIBC.prctl(38, 1, 0, 0, 0))  # no_new_privs
    # UID/GID changes clear PDEATHSIG; restore it after dropping privileges.
    bind_parent(parent)
