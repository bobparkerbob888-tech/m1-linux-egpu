from pathlib import Path
import re
B=Path(__file__).resolve().parent.parent;M=B/'native-prl-r54';P=B/'native-probe-r54';G=B/'next-nhi-cm/supervision-r54'
def base(t):return t.replace('r53','r54').replace('R53','R54').replace('router53','router54').replace('four_policy','five_policy')
t=(G/'activate_controllers.py').read_text();a=t.index(' outer_native=');z=t.index('\ndef journal(',a)
t=t[:a]+''' outer_native=matches(r'pair-native-driver: outer status0 native-audit0 tunnel-proof0 phase30; targets0600\\+0300 only')
 terminal_native=matches(r'retained-controller1-pair: terminal status 0 phase 30; targets0600\\+0300 only; audio0301/0601 excluded')
 if len(outer_native)!=1 or len(terminal_native)!=1:return None
 native=matches(r'530000000\\.apciec: pair-native: phase30 target(0002:06:00\\.0) serial(PROVISION_PRIVATE_ID_9) target(0002:03:00\\.0) serial([0-9a-f]{16}) ready; audio0301/0601 untouched')
 if len(native)!=1:return None
 b,d,b2,d2=native[0][1].groups()
 if int(d2,16) in (0,2**64-1) or d2 in [d,*[v[1] for v in C.FIRST.values()]]:return None
 if not starts[0][0]<native[0][0]<outer_native[0][0]<terminal_native[0][0]:return None
 return {'phase':30,'target_bdf':b,'target_dsn':d,'secondary_bdf':b2,'secondary_dsn':d2}
''' +t[z:];(G/'activate_controllers.py').write_text(t)
t=base((B/'native-probe-r53/prepare-manifest.py').read_text());a=t.index('def extract_identity(');z=t.index('\ndef main(',a)
t=t[:a]+'''def extract_identity(base,boot,lines,resolve):
 c=copy.deepcopy(base);c['boot_id']=boot
 candidates=[x for x in lines if 'pair-native: phase30 ' in x]
 P.need(len(candidates)==1,'Ambiguous controller1 phase30')
 match=re.search(r'530000000\\.apciec: pair-native: phase30 target(0002:06:00\\.0) serial(PROVISION_PRIVATE_ID_9) target(0002:03:00\\.0) serial([0-9a-f]{16}) ready; audio0301/0601 untouched$',candidates[0])
 P.need(match is not None,'Wrong controller1 phase30 marker')
 bdf,dsn,second,serial=match.groups()
 for route,uid in zip(('1','301'),F.UIDS):
  marker='chain-prepare: route'+route+' UID'+uid.lower()+' identity1 configured1 ready1'
  P.need(len([x for x in lines if marker in x and '501f00000' in x])==1,'Second controller route identity missing')
 c['fourth'].update(bdf=bdf,dsn=dsn,uuid='PROVISION_TARGET_UUID',sysfs_path=resolve(bdf))
 c['fifth'].update(bdf=second,dsn=serial,uuid=None,sysfs_path=resolve(second))
 return c
''' +t[z:]
t=t.replace("receipt['phase']==20","receipt['phase']==30").replace('phase20_evidence_sha256','phase30_evidence_sha256').replace('Q.phase20(','Q.phase30(')
t=t.replace("base={'schema':1","base={'schema':2")
t=t.replace("'rid':0x600,'sid':1}}","'rid':0x600,'sid':1},'fifth':{'host_of_path':F.OF1,'enclosure_uids':F.UIDS,'rid':0x300,'sid':2}}")
t=t.replace("c['fourth']['dsn']==receipt['target_dsn']","c['fourth']['dsn']==receipt['target_dsn'] and c['fifth']['bdf']==receipt['secondary_bdf'] and c['fifth']['dsn']==receipt['secondary_dsn']")
(P/'prepare-manifest.py').write_text(t)
t=base((B/'native-acceptance-r53c/validate-mining.py').read_text())
t=t.replace('len(r[\'device\'][\'devices\'])==4','len(r[\'device\'][\'devices\'])==5').replace('official-krig-four-card-mining','official-krig-five-card-mining')
t=t.replace('duplicate short-address counts','duplicate short-address counts')
(M/'validate-mining.py').write_text(t)
print('Prepared exact pair receipt parser, identity sealing and five acceptance; local only')
