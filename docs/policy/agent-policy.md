# Agent policy admission (v1alpha1)

`AgentPolicy` contains the bounded, enforceable rule subset; immutable `AgentPolicyBinding` pins policy UIDs and canonical digests to AgentSuite identity. The binding controller re-resolves every source using the uncached API reader and publishes the deterministic effective policy only after UID, digest, capability, validity-window, and bound checks pass.

A Task opts in with immutable `spec.policyBindingRef`. The Task controller then fails closed before every pending execution route. Missing configuration, lookup failures, UID/digest drift, expiration, rejection, or stale Task identity fail the Task. Incomplete activation evidence requeues without dispatch. Dispatch requires a current `PolicyReady=True` condition whose observed generation matches the Task and whose message binds runtime-session and attachment-receipt digests.

This API does not claim enforcement on its own. A harness-v2 runtime starts the
provider stopped, moves it into an exact child cgroup, asks node-local guardd to
attach the policy, verifies and durably persists guardd's signed receipt, and
only then releases execution. guardd is the sole privileged IG actuator; Orka
mounts only its Unix socket, an authorization private key, the receipt public
key, an Orka-only receipt directory, and the host cgroup tree. The node identity
is the runtime Pod's `spec.nodeName`. Missing or partial guardd configuration,
host files, receipt persistence, or receipt verification fail closed. Legacy
Tasks without `policyBindingRef` retain their existing behavior.

The current Kaimahi-to-Orka contract is write-only. Network rules, network quarantine, read confinement, and executable policy authoring are not accepted by this API. The guardd runtime has a separate exact-executable capability, but this integration does not silently derive executable rules from write rules.
