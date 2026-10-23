# Neutral native supervisor qualification

Run only as a bounded isolated privileged test, never as deployment.
Build supervisor tests with `go test -c` as evidence/orka-neutral-supervisor.test
and the ACP exec helper as evidence/orka-acp-exec-helper. Prerequisites: task
venv with Guardd, Suite policy module, native Codex ACP adapter and codex CLI,
network.bpf.o, root cgroup-v2/BPF access and independent free loopback ports
28181-28184. Controller paths are explicitly task-scoped; inspect before reuse.
`controller.py NEW_RUN_ID` authors a complete ordinary network-v2 policy,
starts the neutral enforcement daemon and actual supervisor, then runs native
Codex inference + exec tool. `crash_controller.py NEW_RUN_ID` SIGKILLs its exact
Popen-owned daemon after activation and restarts it without changing pins.
Both require real allowed arrival and denied receiver absence, EPERM for
unlisted TCP/UDP/IPv6/packet operations, exact session deletion, empty cgroup,
no activation association and no BPF residue. No hidden endpoint grants.
These qualify native Orka supervisor, NOT public Kaimahi evaluation/cluster
controller provisioning or model quality. Cleanup-only native recovery test
requires explicit ORKA_NATIVE_RECOVER_ROOT and uses only its exact journals.
Never remove pin or cgroup trees by pattern or treat graceful stop as crash.
