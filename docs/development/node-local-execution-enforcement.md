# Opt-in node-local execution enforcement (Linux Pod lane)

This is trusted operator configuration for the generic complete-requirement
seam. Orka does not interpret policy bytes, select a concrete policy engine or
invoke provider-specific commands. Policy-free sessions do not call the peer.
The peer is a privileged host trust boundary, not a workload sidecar.

Before enabling, explicitly provision a dedicated runtime namespace with
`pod-security.kubernetes.io/enforce=privileged`. HostPath and supervisor
SYS_PTRACE are incompatible with baseline admission; Orka refuses missing or
baseline namespaces for this opt-in lane and never relabels one. The workload
container itself is not privileged. This namespace is a trusted operator
boundary, not a general untrusted Pod namespace.

Provision every selected node with a protected root-owned
local directory containing `config.json`, the peer Unix SEQPACKET socket and
retained state. Configuration, socket and state must not be workload-writable.
Do not erase state, replace a live socket or stop uncertain restrictions to
reset a run. Independently configure the peer's exact state/pin ownership.

Normal controller flags (all omitted preserves existing Pod configuration):

```
--acp-enforcer-directory=/var/lib/execution-enforcer
--acp-enforcer-seccomp-profile=orka/held.json
--acp-enforcer-node-labels=example.org/execution-enforcer=v1
```

The directory must already exist. The controller mounts it at
`/run/orka-enforcement`, projects `/sys/fs/cgroup` at `/run/orka-cgroups`, adds
supervisor `SYS_PTRACE` for different-UID held-helper namespace inspection,
and selects an explicitly installed **Localhost** seccomp profile. There is
no automatic Unconfined profile, host PID namespace or privileged container.
The profile must permit clone3 for atomic CLONE_INTO_CGROUP; ordinary
RuntimeDefault can return ENOSYS. Start from the node runtime's pinned default
profile, preserve its other denials, and explicitly permit clone3. Installing
that profile and a peer is an operator prerequisite, not automatic package
installation by Orka. Node labels attest setup, not activation readiness.

Protected `config.json` example (neutral peer names are operator choices):

```json
{"Socket":"/run/orka-enforcement/socket","Name":"complete-policy-peer","Revision":"v1","CgroupMount":"/run/orka-cgroups","StateRoot":"/run/orka-enforcement/associations","NamespaceState":true}
```

`CgroupMount` and explicit `CgroupRoot` are mutually exclusive. With a mount,
the supervisor resolves the exact current cgroup namespace root by kernel
device/inode, verifies its own membership, and creates `orka-executions` below
that root. It never selects an unrelated host sibling. A bounded discovery
failure refuses startup. With `NamespaceState`, the immutable downward-API
Pod UID isolates durable journals. The old explicit-root configuration remains
available for an independently provisioned native host supervisor.

The namespace root and peer can have different PID/mount namespace views.
A supporting peer must validate actual transferred pidfd/cgroup/netns handles,
not adopt caller-local numeric PIDs in its own procfs. The runtime retains
its exact immutable target and operation for retry/cleanup. The trusted helper
is held before adapter initialization; governed children are non-root,
capability-free, no-new-privileges and syscall-fenced. Only verified exact
activation permits the runtime's release. Config mount availability, assessment,
node labels and healthy socket are not authority to release.

Retain state across supervisor/container restart. Changed target identity is
cleanup uncertainty, never permission to authorize a replacement. Restart must
finish exact retained cleanup or refuse. A deleted Pod's unresolved state must
be handled by its exact cleanup owner; creating a new Pod UID does not transfer
ownership or establish that the old owner was retired. This Pod-only option
refuses external workspace placement rather than silently projecting host
paths into a native/remote backend. Existing external backend configuration is
unchanged with these flags omitted.

Qualification is explicitly separate: rendering/config tests and a real Pod
kernel activation/retirement test do not prove normal controller readiness,
public Kaimahi result, or all policy traffic classes. Those require integrated
qualification of the selected final source trees and exact policy.

## Explicit model proxy endpoint

For strict policies, the normally ephemeral supervisor model proxy may be pinned
with `--acp-enforcer-model-proxy-listen-address=127.0.0.1:28295`. Only a nonzero
literal IPv4 loopback port is accepted. This sets the existing supervisor
listener configuration and changes the Pod revision; it does **not** add policy
rules. The complete authored policy must include that exact endpoint. The
proxy's upstream is a separately disclosed host-mediated trust boundary, not
claimed as sandbox-contained network traffic. With this option omitted, the
existing ephemeral listener behavior remains unchanged. A policy which does not
include the actual listener will deny model traffic rather than infer a grant.

## Boot enrollment and restart

Native boot enrollment snapshots the exact trusted node-local configuration in
its immutable witness. Only that exact HostPath, mount, downward-API environment,
node selection, inspection capability and Localhost profile are recognized by
boot topology validation; the original complete PodSpec digest remains pinned.
Other host mounts, additional capabilities or altered projections fail closed.
This does not relax the shared AgentRuntime recovery boundary.

A template enrollment marker is intent, not a committed witness. If a restart
rotates credentials before initial enrollment, normal authenticated quiescent
drain can retire that never-enrolled boot using the existing task-cleanup path.
An existing preparation, retention annotation or Pod finalizer blocks this
fallback. No boot witness, activation authority or physical-death receipt is
fabricated. Uncertain state continues to require the original cleanup owner.
