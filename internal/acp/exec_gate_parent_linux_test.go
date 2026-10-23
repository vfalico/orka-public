//go:build linux

package acp

import "testing"

func TestReleasedHelperParentIncludesNamespaceInit(t *testing.T) {
	for _, tc := range []struct {
		name               string
		expected, observed int
		ok                 bool
	}{
		{"pod supervisor PID one", 1, 1, true}, {"ordinary supervisor", 123, 123, true},
		{"adopted by init", 123, 1, false}, {"different supervisor", 123, 124, false},
		{"invalid parent", 0, 0, false}, {"negative parent", -1, -1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyReleasedHelperParent(tc.expected, tc.observed)
			if (err == nil) != tc.ok {
				t.Fatalf("verify(%d,%d)=%v", tc.expected, tc.observed, err)
			}
		})
	}
}
