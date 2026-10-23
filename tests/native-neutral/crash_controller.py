#!/usr/bin/env python3
"""Bounded task-owned native Orka leaf qualification; NOT public Kaimahi."""
import base64,hashlib,json,os,pathlib,subprocess,sys,time,struct
R=pathlib.Path(os.environ['ENFORCEMENT_POC_WORKSPACE']).resolve(strict=True);root=pathlib.Path('/tmp')/('poc-'+sys.argv[1])
root.mkdir(mode=0o755,parents=True,exist_ok=False)
import shutil
shutil.copyfile(R/'evidence/orka-acp-exec-helper',root/'orka-acp-exec-helper');(root/'orka-acp-exec-helper').chmod(0o755)
cg=pathlib.Path('/sys/fs/cgroup/poc-orka-'+root.name);cg.mkdir()
pins=pathlib.Path('/sys/fs/bpf/poc-orka-'+root.name);pins.mkdir()
conf=dict(socket=str(root/'provider.sock'),state=str(root/'provider.db'),pins=str(pins),object=str(R/'evidence/network.bpf.o'))
(root/'provider.json').write_text(json.dumps(conf));(root/'provider.json').chmod(0o600)
(root/'backend.json').write_text(json.dumps(dict(Socket=conf['socket'],Name='local-complete',Revision='v1',CgroupRoot=str(cg),StateRoot=str(root/'associations'))));(root/'backend.json').chmod(0o600)
raw=json.dumps(dict(version='agentsuite.policy/v2',network=dict(egressAllow=[dict(address='127.0.0.1',port=p,protocol='TCP') for p in [28181,28182,28184]]),requiredCapabilities=['network/egress-allow/v1']),sort_keys=True,separators=(',',':')).encode()
req=dict(format='agentsuite.policy/v2',policyBytes=base64.b64encode(raw).decode(),payloadDigest='sha256:'+hashlib.sha256(b'agentsuite-effective-policy\0v1\0'+struct.pack('>Q',len(raw))+raw).hexdigest(),requiredCapabilities=['network/egress-allow/v1'])
frame=b'orka.execution-requirement\0v1\0'
for v in [req['format'].encode(),raw,req['payloadDigest'].encode(),b'network/egress-allow/v1']:frame+=struct.pack('>Q',len(v))+v
req['identity']='sha256:'+hashlib.sha256(frame).hexdigest();(root/'requirement.json').write_text(json.dumps(req))
log=open(root/'provider.log','wb');daemon=None
try:
 env=dict(os.environ,PYTHONPATH=str(R/'sources/guardd/src'))
 daemon=subprocess.Popen([str(R/'venv/bin/python'),'-m','agentsuite_guardd.cli','--config',str(root/'provider.json'),'serve-enforcement'],env=env,stdout=log,stderr=subprocess.STDOUT)
 print('DAEMON',daemon.pid,flush=True)
 deadline=time.monotonic()+20
 while not pathlib.Path(conf['socket']).exists():
  if daemon.poll() is not None:raise RuntimeError('daemon exited '+str(daemon.returncode))
  if time.monotonic()>deadline:raise TimeoutError('daemon startup')
  time.sleep(.1)
 env.update(ORKA_REAL_NETWORK_ROOT=str(root),ORKA_NETWORK_REQUIREMENT=str(root/'requirement.json'),ORKA_NEUTRAL_EXEC_HELPER=str(root/'orka-acp-exec-helper'))
 # Clear supplementary groups: inherited historical fixture needed this too.
 env['ORKA_TEST_DAEMON_LOSS']='1'
 child=subprocess.Popen([str(R/'evidence/orka-neutral-supervisor.test'),'-test.run','^TestNeutralSuiteNativeSupervisor$','-test.v','-test.timeout=110s'],env=env,extra_groups=[])
 try:
  deadline=time.monotonic()+60
  while not (root/'ready-for-loss').exists():
   if child.poll() is not None:raise RuntimeError('native test exited before loss boundary')
   if time.monotonic()>deadline:raise TimeoutError('loss boundary')
   time.sleep(.1)
  # Exact Popen child owned by this controller; never signal a pattern.
  daemon.kill();daemon.wait(timeout=10)
  print('EXACT_DAEMON_LOSS_EXIT',daemon.returncode,flush=True)
  daemon=subprocess.Popen([str(R/'venv/bin/python'),'-m','agentsuite_guardd.cli','--config',str(root/'provider.json'),'serve-enforcement'],env=env,stdout=log,stderr=subprocess.STDOUT)
  time.sleep(.5)
  if daemon.poll() is not None:raise RuntimeError('restart failed')
  (root/'loss-completed').write_text('exact daemon restarted; restrictions never removed')
  code=child.wait(timeout=100)
  class Result:pass
  result=Result();result.returncode=code
 finally:
  if child.poll() is None:
   child.terminate()
   try:child.wait(timeout=8)
   except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
 print('TEST_EXIT',result.returncode,flush=True)
 if result.returncode:raise RuntimeError('native leaf test failed')
finally:
 if daemon is not None:
  if daemon.poll() is None:
   daemon.terminate()
   try:daemon.wait(timeout=10)
   except subprocess.TimeoutExpired:daemon.kill();daemon.wait(timeout=5)
  print('DAEMON_EXIT',daemon.returncode,flush=True)
 log.close()
 # No uncertain enforcement restriction is removed to reset the experiment.
 for path in [cg,pins]:
  try:path.rmdir();print('EMPTY_ROOT_REMOVED',str(path),flush=True)
  except OSError as e:print('RETAINED_EXACT_ROOT',str(path),repr(e),flush=True)
