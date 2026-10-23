// Copyright (c) 2026. MIT License - see LICENSE file for details.
package controller

import (
	"fmt"
	core "github.com/orka-agents/orka/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"net"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

// RuntimePoolEnforcement is operator configuration, not a requirement schema.
// Directory contains root-owned config.json, the neutral Unix socket and retained
// state; operators provision it on every selected node before enabling the lane.
// The peer implementation is deliberately opaque to Orka.
type RuntimePoolEnforcement struct {
	Directory               string
	SeccompProfile          string
	NodeSelector            map[string]string
	ModelProxyListenAddress string
}

func (c RuntimePoolEnforcement) Validate() error {
	if c.Directory == "" && c.SeccompProfile == "" && len(c.NodeSelector) == 0 && c.ModelProxyListenAddress == "" {
		return nil
	}
	if !filepath.IsAbs(c.Directory) || filepath.Clean(c.Directory) != c.Directory || c.Directory == "/" {
		return fmt.Errorf("protected absolute enforcer directory required")
	}
	if c.SeccompProfile == "" || filepath.IsAbs(c.SeccompProfile) || filepath.Clean(c.SeccompProfile) != c.SeccompProfile || strings.HasPrefix(c.SeccompProfile, "..") {
		return fmt.Errorf("explicit Localhost seccomp profile required")
	}
	if c.ModelProxyListenAddress != "" {
		host, port, err := net.SplitHostPort(c.ModelProxyListenAddress)
		n, parseErr := strconv.Atoi(port)
		if err != nil || parseErr != nil || host != "127.0.0.1" || n < 1 || n > 65535 {
			return fmt.Errorf("explicit nonzero literal-loopback model proxy listener required")
		}
	}
	if len(c.NodeSelector) == 0 {
		return fmt.Errorf("enforcer-capable node selection required")
	}
	if os, ok := c.NodeSelector["kubernetes.io/os"]; ok && os != "linux" {
		return fmt.Errorf("held native lane requires Linux")
	}
	for k, v := range c.NodeSelector {
		if len(validation.IsQualifiedName(k)) != 0 || len(validation.IsValidLabelValue(v)) != 0 || strings.TrimSpace(v) == "" {
			return fmt.Errorf("exact node selection required")
		}
	}
	return nil
}
func (r *RuntimePoolReconciler) validateRuntimePoolEnforcement(pool *core.RuntimePool) error {
	if err := r.Enforcement.Validate(); err != nil {
		return err
	}
	if r.Enforcement.Directory != "" && pool.Spec.ExecutionWorkspace != nil {
		return fmt.Errorf("node-local enforcement configuration supports Pod runtime only")
	}
	return nil
}
func (c RuntimePoolEnforcement) apply(t *corev1.PodTemplateSpec) {
	if c.Directory == "" {
		return
	}
	// Preserve private Pod PID namespaces. Node-local peer resolves transferred
	// pidfds in its own namespace, never by trusting a caller's numeric PID.
	container := &t.Spec.Containers[0]
	container.Env = append(container.Env, corev1.EnvVar{Name: "ORKA_ACP_ENFORCER_CONFIG_FILE", Value: "/run/orka-enforcement/config.json"})
	if c.ModelProxyListenAddress != "" {
		container.Env = append(container.Env, corev1.EnvVar{Name: "ORKA_ACP_PROVIDER_PROXY_LISTEN_ADDRESS", Value: c.ModelProxyListenAddress})
	}

	container.VolumeMounts = append(container.VolumeMounts, corev1.VolumeMount{Name: "execution-enforcer", MountPath: "/run/orka-enforcement"}, corev1.VolumeMount{Name: "execution-cgroups", MountPath: "/run/orka-cgroups"})
	directory := corev1.HostPathDirectory
	t.Spec.Volumes = append(t.Spec.Volumes, corev1.Volume{Name: "execution-enforcer", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: c.Directory, Type: &directory}}}, corev1.Volume{Name: "execution-cgroups", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/cgroup", Type: &directory}}})
	if t.Spec.NodeSelector == nil {
		t.Spec.NodeSelector = map[string]string{}
	}
	for k, v := range c.NodeSelector {
		t.Spec.NodeSelector[k] = v
	}
	container.SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeLocalhost, LocalhostProfile: &c.SeccompProfile}
	// The root supervisor must inspect the exact different-UID held helper's
	// namespace. Governed children drop capabilities and install their own fence.
	container.SecurityContext.Capabilities.Add = append(container.SecurityContext.Capabilities.Add, "SYS_PTRACE")
}

// retained snapshots trusted operator configuration into the immutable boot
// witness. A later controller flag change cannot rewrite old cleanup ownership.
func (c RuntimePoolEnforcement) retained() *RuntimePoolEnforcement {
	if c.Directory == "" {
		return nil
	}
	copy := c
	copy.NodeSelector = map[string]string{}
	for k, v := range c.NodeSelector {
		copy.NodeSelector[k] = v
	}
	return &copy
}

// runtimePoolEnforcedBootTopologySpec removes only an EXACT explicitly opted-in
// node-local projection from a COPY before applying the unchanged shared Pod
// recovery validator. The original PodSpec digest still pins every removed
// byte. This is not general HostPath or SYS_PTRACE recovery permission.
func runtimePoolEnforcedBootTopologySpec(spec corev1.PodSpec, c *RuntimePoolEnforcement) (corev1.PodSpec, error) {
	topology, err := runtimePoolBootTopologySpec(spec)
	if err != nil {
		return corev1.PodSpec{}, err
	}
	if c == nil {
		return topology, nil
	}
	if c.Directory == "" {
		return corev1.PodSpec{}, fmt.Errorf("empty retained enforcer configuration")
	}
	if err = c.Validate(); err != nil {
		return corev1.PodSpec{}, err
	}
	if len(topology.Containers) != 1 {
		return corev1.PodSpec{}, fmt.Errorf("enforced boot requires exact single supervisor")
	}
	actual := &topology.Containers[0]
	expected := corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{SecurityContext: &corev1.SecurityContext{Capabilities: &corev1.Capabilities{}}}}}}
	c.apply(&expected)
	projected := expected.Spec.Containers[0]
	for _, v := range expected.Spec.Volumes {
		count := 0
		for _, a := range topology.Volumes {
			if a.Name == v.Name {
				count++
				if !reflect.DeepEqual(a, v) {
					return corev1.PodSpec{}, fmt.Errorf("enforcer host volume changed")
				}
			}
		}
		if count != 1 {
			return corev1.PodSpec{}, fmt.Errorf("enforcer host volume missing or duplicated")
		}
	}
	for _, v := range projected.VolumeMounts {
		count := 0
		for _, a := range actual.VolumeMounts {
			if a.Name == v.Name {
				count++
				if !reflect.DeepEqual(a, v) {
					return corev1.PodSpec{}, fmt.Errorf("enforcer mount changed")
				}
			}
		}
		if count != 1 {
			return corev1.PodSpec{}, fmt.Errorf("enforcer mount missing or duplicated")
		}
	}
	for _, v := range projected.Env {
		count := 0
		for _, a := range actual.Env {
			if a.Name == v.Name {
				count++
				if !reflect.DeepEqual(a, v) {
					return corev1.PodSpec{}, fmt.Errorf("enforcer environment changed")
				}
			}
		}
		if count != 1 {
			return corev1.PodSpec{}, fmt.Errorf("enforcer environment missing or duplicated")
		}
	}
	for k, v := range c.NodeSelector {
		if topology.NodeSelector[k] != v {
			return corev1.PodSpec{}, fmt.Errorf("enforcer node selection changed")
		}
	}
	if actual.SecurityContext == nil || actual.SecurityContext.Capabilities == nil || !reflect.DeepEqual(actual.SecurityContext.SeccompProfile, projected.SecurityContext.SeccompProfile) {
		return corev1.PodSpec{}, fmt.Errorf("enforcer supervisor security profile changed")
	}
	count := 0
	for _, cap := range actual.SecurityContext.Capabilities.Add {
		if cap == "SYS_PTRACE" {
			count++
		}
	}
	if count != 1 {
		return corev1.PodSpec{}, fmt.Errorf("enforcer inspection capability missing or duplicated")
	}
	actual.SecurityContext.Capabilities.Add = slices.DeleteFunc(actual.SecurityContext.Capabilities.Add, func(c corev1.Capability) bool { return c == "SYS_PTRACE" })
	actual.SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}
	topology.Volumes = slices.DeleteFunc(topology.Volumes, func(v corev1.Volume) bool { return v.Name == "execution-enforcer" || v.Name == "execution-cgroups" })
	actual.VolumeMounts = slices.DeleteFunc(actual.VolumeMounts, func(v corev1.VolumeMount) bool {
		return v.Name == "execution-enforcer" || v.Name == "execution-cgroups"
	})
	actual.Env = slices.DeleteFunc(actual.Env, func(v corev1.EnvVar) bool {
		return v.Name == "ORKA_ACP_ENFORCER_CONFIG_FILE" || (c.ModelProxyListenAddress != "" && v.Name == "ORKA_ACP_PROVIDER_PROXY_LISTEN_ADDRESS")
	})
	return topology, nil
}
