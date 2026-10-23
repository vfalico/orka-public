package controller

import (
	"context"
	core "github.com/orka-agents/orka/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"reflect"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"strings"
	"testing"
)

func TestNodeLocalEnforcerConfigurationAndRendering(t *testing.T) {
	valid := RuntimePoolEnforcement{Directory: "/var/lib/neutral-enforcer", SeccompProfile: "orka/held.json", NodeSelector: map[string]string{"example.test/enforcer": "v1"}}
	for _, tc := range []struct {
		name string
		c    RuntimePoolEnforcement
		bad  bool
	}{
		{"disabled", RuntimePoolEnforcement{}, false}, {"valid", valid, false},
		{"relative", RuntimePoolEnforcement{Directory: "relative", SeccompProfile: "held", NodeSelector: valid.NodeSelector}, true},
		{"root", RuntimePoolEnforcement{Directory: "/", SeccompProfile: "held", NodeSelector: valid.NodeSelector}, true},
		{"missing-profile", RuntimePoolEnforcement{Directory: valid.Directory, NodeSelector: valid.NodeSelector}, true},
		{"traversal", RuntimePoolEnforcement{Directory: valid.Directory, SeccompProfile: "../held", NodeSelector: valid.NodeSelector}, true},
		{"no-placement", RuntimePoolEnforcement{Directory: valid.Directory, SeccompProfile: valid.SeccompProfile}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if e := tc.c.Validate(); (e != nil) != tc.bad {
				t.Fatalf("validation %v", e)
			}
		})
	}
	pool := &core.RuntimePool{}
	r := &RuntimePoolReconciler{Enforcement: valid}
	if e := r.validateRuntimePoolEnforcement(pool); e != nil {
		t.Fatal(e)
	}
	pool.Spec.ExecutionWorkspace = &core.RuntimePoolExecutionWorkspaceSpec{}
	if e := r.validateRuntimePoolEnforcement(pool); e == nil {
		t.Fatal("Pod-only config entered external workspace")
	}
	base := corev1.PodTemplateSpec{Spec: corev1.PodSpec{NodeSelector: map[string]string{"kubernetes.io/os": "linux"}, Containers: []corev1.Container{{Name: "runtime", SecurityContext: &corev1.SecurityContext{Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}}}}}
	before := runtimePoolPodTemplateRevision(base)
	valid.apply(&base)
	if runtimePoolPodTemplateRevision(base) == before {
		t.Fatal("configuration not revision bound")
	}
	if base.Spec.HostPID || base.Spec.HostNetwork {
		t.Fatal("host namespaces exposed")
	}
	c := base.Spec.Containers[0]
	if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
		t.Fatal("privileged runtime")
	}
	if c.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeLocalhost || *c.SecurityContext.SeccompProfile.LocalhostProfile != valid.SeccompProfile {
		t.Fatal("missing explicit profile")
	}
	if base.Spec.NodeSelector["example.test/enforcer"] != "v1" || len(base.Spec.Volumes) != 2 || len(c.VolumeMounts) != 2 {
		t.Fatal("missing boundary wiring")
	}
	if len(c.Env) != 1 || c.Env[0].Value != "/run/orka-enforcement/config.json" {
		t.Fatal("config env missing")
	}
	for _, v := range base.Spec.Volumes {
		if v.HostPath == nil || *v.HostPath.Type != corev1.HostPathDirectory {
			t.Fatal("silently created host directory")
		}
	}
	for _, e := range c.Env {
		if strings.Contains(strings.ToLower(e.Name), "guardd") {
			t.Fatal("concrete provider coupling")
		}
	}
	disabled := base.DeepCopy()
	RuntimePoolEnforcement{}.apply(disabled)
	if runtimePoolPodTemplateRevision(*disabled) != runtimePoolPodTemplateRevision(base) {
		t.Fatal("disabled configuration changes Pod")
	}
}

// Normal renderer, not only the standalone projection helper: proves the flags'
// reconciler field reaches delivered Pod construction and immutable revision.
func TestRuntimePoolNormalRendererCarriesGenericEnforcement(t *testing.T) {
	pool := runtimePoolTestObject(1)
	r := runtimePoolTestReconciler(t, runtimePoolTestScheme(t), nil, pool)
	cfg, err := r.runtimePoolConfig(pool)
	if err != nil {
		t.Fatal(err)
	}
	selector := map[string]string{runtimePoolKeyLabel: cfg.labels[runtimePoolKeyLabel]}
	before := r.runtimePoolPodTemplate(pool, cfg, selector, "auth", "provider")
	r.Enforcement = RuntimePoolEnforcement{Directory: "/var/lib/execution-enforcer", SeccompProfile: "orka/held.json", NodeSelector: map[string]string{"example.org/execution-enforcer": "v1"}}
	cfg, err = r.runtimePoolConfig(pool)
	if err != nil {
		t.Fatal(err)
	}
	after := r.runtimePoolPodTemplate(pool, cfg, selector, "auth", "provider")
	if before.Annotations[runtimePoolTemplateRevisionAnnotation] == after.Annotations[runtimePoolTemplateRevisionAnnotation] {
		t.Fatal("normal renderer omitted enforcer identity")
	}
	found := false
	for _, e := range after.Spec.Containers[0].Env {
		if e.Name == "ORKA_ACP_ENFORCER_CONFIG_FILE" && e.Value == "/run/orka-enforcement/config.json" {
			found = true
		}
	}
	if !found {
		t.Fatal("normal renderer omitted generic loader")
	}
	if after.Spec.Containers[0].SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeLocalhost {
		t.Fatal("normal renderer omitted compatible explicit profile")
	}
	if len(after.Spec.Volumes) != len(before.Spec.Volumes)+2 {
		t.Fatal("boundary volumes missing")
	}
	r.Enforcement.SeccompProfile = ""
	if _, err = r.runtimePoolConfig(pool); err == nil {
		t.Fatal("invalid operator config was ignored")
	}
}

func TestNodeLocalEnforcerRequiresExplicitNamespaceAdmission(t *testing.T) {
	pool := runtimePoolTestObject(1)
	r := runtimePoolTestReconciler(t, runtimePoolTestScheme(t), nil, pool)
	r.Enforcement = RuntimePoolEnforcement{Directory: "/var/lib/peer", SeccompProfile: "held.json", NodeSelector: map[string]string{"example.org/peer": "v1"}}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "explicit-node-local-runtime", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "baseline"}}}
	cfg := runtimePoolConfig{namespace: ns.Name}
	if err := r.ensureRuntimePoolNamespace(context.Background(), cfg); err == nil {
		t.Fatal("created an unapproved namespace")
	}
	if err := r.Create(context.Background(), ns); err != nil {
		t.Fatal(err)
	}
	if err := r.ensureRuntimePoolNamespace(context.Background(), cfg); err == nil {
		t.Fatal("baseline admission cannot host required boundary")
	}
	var got corev1.Namespace
	if err := r.Get(context.Background(), client.ObjectKeyFromObject(ns), &got); err != nil {
		t.Fatal(err)
	}
	if got.Labels["pod-security.kubernetes.io/enforce"] != "baseline" {
		t.Fatal("silently relabeled namespace")
	}
	got.Labels["pod-security.kubernetes.io/enforce"] = "privileged"
	if err := r.Update(context.Background(), &got); err != nil {
		t.Fatal(err)
	}
	if err := r.ensureRuntimePoolNamespace(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
}

func TestNodeLocalModelProxyExplicitPortWithoutPolicyGrant(t *testing.T) {
	c := RuntimePoolEnforcement{Directory: "/var/lib/peer", SeccompProfile: "held.json", NodeSelector: map[string]string{"example.org/peer": "v1"}}
	for _, address := range []string{"127.0.0.1:0", "0.0.0.0:28295", "localhost:28295", "[::1]:28295", "127.0.0.1:65536"} {
		c.ModelProxyListenAddress = address
		if c.Validate() == nil {
			t.Fatalf("invalid listener %q", address)
		}
	}
	c.ModelProxyListenAddress = "127.0.0.1:28295"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	base := corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{SecurityContext: &corev1.SecurityContext{Capabilities: &corev1.Capabilities{}}}}}}
	c.apply(&base)
	found := false
	for _, e := range base.Spec.Containers[0].Env {
		if e.Name == "ORKA_ACP_PROVIDER_PROXY_LISTEN_ADDRESS" && e.Value == c.ModelProxyListenAddress {
			found = true
		}
	}
	if !found {
		t.Fatal("explicit port omitted")
	}
}

func TestNodeLocalEnforcerBootTopologyIsExactAndRetained(t *testing.T) {
	pool := runtimePoolTestObject(1)
	r := runtimePoolTestReconciler(t, runtimePoolTestScheme(t), nil, pool)
	c := RuntimePoolEnforcement{Directory: "/var/lib/peer", SeccompProfile: "held.json", NodeSelector: map[string]string{"example.org/peer": "v1"}, ModelProxyListenAddress: "127.0.0.1:28295"}
	r.Enforcement = c
	cfg, err := r.runtimePoolConfig(pool)
	if err != nil {
		t.Fatal(err)
	}
	template := r.runtimePoolPodTemplate(pool, cfg, map[string]string{runtimePoolKeyLabel: cfg.labels[runtimePoolKeyLabel]}, "auth", "provider")
	retained := c.retained()
	c.NodeSelector["example.org/peer"] = "changed"
	if retained.NodeSelector["example.org/peer"] != "v1" {
		t.Fatal("retained configuration aliased mutable source")
	}
	original := template.DeepCopy()
	validate := func(spec corev1.PodSpec, config *RuntimePoolEnforcement) error {
		topology, e := runtimePoolEnforcedBootTopologySpec(spec, config)
		if e != nil {
			return e
		}
		return validateAgentRuntimeRecoveryPodSpec(topology, runtimePoolBootContainerName, cfg.profile.ProviderKind)
	}
	if err := validate(template.Spec, retained); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(original, template.DeepCopy()) {
		t.Fatal("normalization mutated actual Pod")
	}
	if validate(template.Spec, nil) == nil {
		t.Fatal("unconfigured admission accepted host privileges")
	}
	changes := map[string]func(*corev1.PodSpec){
		"host-root": func(s *corev1.PodSpec) {
			for i := range s.Volumes {
				if s.Volumes[i].Name == "execution-enforcer" {
					s.Volumes[i].HostPath.Path = "/"
				}
			}
		},
		"other-hostpath": func(s *corev1.PodSpec) {
			s.Volumes = append(s.Volumes, corev1.Volume{Name: "foreign", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/"}}})
		},
		"extra-capability": func(s *corev1.PodSpec) {
			s.Containers[0].SecurityContext.Capabilities.Add = append(s.Containers[0].SecurityContext.Capabilities.Add, "SYS_ADMIN")
		},
		"mount-destination": func(s *corev1.PodSpec) {
			for i := range s.Containers[0].VolumeMounts {
				if s.Containers[0].VolumeMounts[i].Name == "execution-enforcer" {
					s.Containers[0].VolumeMounts[i].MountPath = "/foreign"
				}
			}
		},
		"unconfined": func(s *corev1.PodSpec) {
			s.Containers[0].SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}
		},
		"host-pid":     func(s *corev1.PodSpec) { s.HostPID = true },
		"foreign-node": func(s *corev1.PodSpec) { s.NodeSelector["example.org/peer"] = "foreign" },
		"duplicate-config": func(s *corev1.PodSpec) {
			s.Containers[0].Env = append(s.Containers[0].Env, corev1.EnvVar{Name: "ORKA_ACP_ENFORCER_CONFIG_FILE", Value: "/foreign"})
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			s := template.Spec.DeepCopy()
			change(s)
			if validate(*s, retained) == nil {
				t.Fatal("foreign projection accepted")
			}
		})
	}
}
