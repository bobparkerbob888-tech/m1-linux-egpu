from pathlib import Path
import shutil
B=Path(__file__).resolve().parent.parent
M=B/'native-prl-r54';P=B/'native-probe-r54';G=B/'next-nhi-cm/supervision-r54'
P.mkdir(exist_ok=True);G.mkdir(exist_ok=True)
def base(t):return t.replace('r53','r54').replace('R53','R54').replace('router53','router54').replace('four_policy','five_policy')
def edit(t,a,b):
 assert a in t,a
 return t.replace(a,b)
for n in ('launch.py','admit.py','network.py','fixed_prl_relay.py','stream_worker.py','observe-address.py'):
 t=base((B/'native-prl-r53'/n).read_text())
 t=t.replace('four-card','five-card').replace('four admitted','five admitted').replace('phase20_evidence_sha256','phase30_evidence_sha256')
 if n in ('launch.py','admit.py'):
  t=t.replace("'/dev/nvidia3','/dev/nvidiactl'","'/dev/nvidia3','/dev/nvidia4','/dev/nvidiactl'").replace('range(4)','range(5)').replace('len(rows)!=4','len(rows)!=5')
 if n=='admit.py':
  t=t.replace("config['fourth']['uuid']==cr['fourth_uuid_observed']","config['fifth']['uuid']==cr['fifth_uuid_observed']")
  t=t.replace("if k!='fourth'","if k!='fifth'").replace("config['fourth'][k]==endpoint['fourth'][k] for k in endpoint['fourth']","config['fifth'][k]==endpoint['fifth'][k] for k in endpoint['fifth']")
  t=t.replace("'endpoint_chain_resources']","'endpoint_chain_resources','endpoint_pair']")
 (M/n).write_text(t)
for n in ('prepare-uvm.py','create-artifacts.py','install-kit.py','package-kit.py'):
 (P/n).write_text(base((B/'native-probe-r53'/n).read_text()))
t=base((B/'native-probe-r53/probe.py').read_text())
t=t.replace('four-GPU','five-GPU').replace('four-device','five-device').replace('all four probes','all five probes')
t=edit(t,"TARGETS=PORT0_TARGETS+(IDENTITY['fourth']['bdf'],)","TARGETS=PORT0_TARGETS+(IDENTITY['fourth']['bdf'],IDENTITY['fifth']['bdf'])")
t=t.replace('phase20_evidence_sha256','phase30_evidence_sha256').replace('Q.phase20(','Q.phase30(').replace('Q.pci_fourth(','Q.pci_pair(').replace('Q.query_four(','Q.query_five(')
t=edit(t,"receipt['phase']==20","receipt['phase']==30")
t=edit(t,"receipt['target_bdf']==c['fourth']['bdf'] and receipt['target_dsn']==c['fourth']['dsn']","receipt['target_bdf']==c['fourth']['bdf'] and receipt['target_dsn']==c['fourth']['dsn'] and receipt['secondary_bdf']==c['fifth']['bdf'] and receipt['secondary_dsn']==c['fifth']['dsn']")
t=edit(t,"s=='06:00.0'","s in ('03:00.0','06:00.0')")
t=edit(t,"('00:00.0','01:00.0','02:01.0','04:00.0','05:00.0','06:00.0')","('00:00.0','01:00.0','02:00.0','03:00.0','02:01.0','04:00.0','05:00.0','06:00.0')")
t=t.replace('[0-3]','[0-4]').replace('minors=={0,1,2,3}','minors=={0,1,2,3,4}').replace("('nvidia3',3),('nvidiactl',255)","('nvidia3',3),('nvidia4',4),('nvidiactl',255)").replace("'nvidia3','nvidiactl'","'nvidia3','nvidia4','nvidiactl'")
t=edit(t,"c['fourth']['uuid']=result['fourth_uuid_observed']","c['fifth']['uuid']=result['fifth_uuid_observed']")
(P/'probe.py').write_text(t)
for n in ('five_policy.py','probe_policy.py'):shutil.copyfile(M/n,P/n)
# Independent admission guard namespace; same1200s budget and sole-reboot policy.
for n in ('arm.py','runtime_guard.py','proven_guard.py','contracts.py','activate_controllers.py'):
 t=base((B/'next-nhi-cm/supervision-r53'/n).read_text())
 t=t.replace('four-card','five-card').replace('four-card/two','five-card/two')
 if n=='runtime_guard.py':
  t=t.replace('len(devices)!=4','len(devices)!=5').replace('0<=idx<4','0<=idx<5')
  t=edit(t,"expected_devices[f['bdf']]=(f['uuid'],f['dsn'])","expected_devices[f['bdf']]=(f['uuid'],f['dsn']);f=seal['fifth'];expected_devices[f['bdf']]=(f['uuid'],f['dsn'])")
 if n=='contracts.py':
  t=t.replace('(22 if i==0 else 20)','(22 if i==0 else 30)')
  t=t[:t.index('def seal_ok(')]+'''def seal_ok(seal,m,receipt):
 try:
  import five_policy as F
  F.mining_config(seal,m['boot_id'])
  for k,a in [('kernel_sha256','image'),('nvidia_sha256','nvidia'),('uvm_sha256','uvm')]:
   if seal[k]!=m['artifacts'][a]['sha256']:return False
  if seal['phase30_evidence_sha256']!=receipt['journal_sha256']:return False
  for key,b,s in [('fourth','target_bdf','target_dsn'),('fifth','secondary_bdf','secondary_dsn')]:
   if seal[key]['bdf']!=receipt[b] or seal[key]['dsn']!=receipt[s]:return False
  return True
 except (ValueError,TypeError,KeyError):return False
'''
 (G/n).write_text(t)
shutil.copyfile(M/'five_policy.py',G/'five_policy.py')
print('Local R54 initial kits generated; not yet deployable; activation/manifest/validator/tests need completion')
