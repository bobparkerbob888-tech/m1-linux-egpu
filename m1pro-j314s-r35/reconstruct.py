#!/usr/bin/env python3
"""Verify public files and reconstruct a review tree; never install or boot it."""
from pathlib import Path,PurePosixPath
import argparse,hashlib,json,tarfile,shutil
D=Path(__file__).resolve().parent

def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def safe(name):
 p=PurePosixPath(name)
 if p.is_absolute() or '..' in p.parts or '\\' in name:raise ValueError('Unsafe path')
 return p
def verify():
 manifest=json.loads((D/'MANIFEST.json').read_text())
 for name,h in manifest['files'].items():
  safe(name);p=D/name
  if p.is_symlink() or not p.is_file() or sha(p)!=h:raise ValueError('Checksum mismatch: '+name)
 return len(manifest['files'])
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--component',choices=['kernel','nvidia']);p.add_argument('--upstream-tar',type=Path);p.add_argument('--output',type=Path);a=p.parse_args();print('Verified files:',verify())
 if not a.component:return
 if not a.upstream_tar or not a.output:p.error('--upstream-tar and --output required')
 ref=json.loads((D/'UPSTREAM.json').read_text())[a.component]
 if sha(a.upstream_tar)!=ref['archive_sha256']:raise ValueError('Wrong upstream archive')
 if a.output.exists():raise ValueError('Output must not exist')
 a.output.mkdir(mode=0o700)
 with tarfile.open(a.upstream_tar,'r:gz') as tf:
  for m in tf:
   safe(m.name)
   if not (m.isfile() or m.isdir() or m.issym()):raise ValueError('Unexpected archive member')
   tf.extract(m,a.output,filter='data')
 roots=[x for x in a.output.iterdir() if x.is_dir()]
 if len(roots)!=1:raise ValueError('Unexpected archive root')
 tree=roots[0]
 for f in (D/(a.component+'-overlay')).rglob('*'):
  if f.is_file():
   q=tree/f.relative_to(D/(a.component+'-overlay'));q.parent.mkdir(parents=True,exist_ok=True)
   if q.is_symlink():raise ValueError('Overlay symlink refused')
   shutil.copyfile(f,q)
 print('Review source:',tree)
 print('Identity provisioning required. This tool did not install, initialize or boot anything.')
if __name__=='__main__':main()
