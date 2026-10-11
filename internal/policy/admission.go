package policy

import (
	"errors"
	"fmt"
	core "github.com/orka-agents/orka/api/v1alpha1"
	apiMeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const ConditionPolicyReady = "PolicyReady"

type TaskAdmission struct {
	BindingName             string
	BindingUID              types.UID
	BindingDigest           string
	EffectiveDigest         string
	TaskUID                 types.UID
	TaskGeneration          int64
	RuntimeSessionID        string
	AttachmentReceiptDigest string
}

func AdmitTask(task *core.Task, b *core.AgentPolicyBinding, a TaskAdmission) error {
	if task == nil || b == nil {
		return errors.New("task and binding are required")
	}
	if b.Name != a.BindingName || b.UID != a.BindingUID {
		return errors.New("binding identity drift")
	}
	bd, e := BindingDigest(b.Spec)
	if e != nil || bd != a.BindingDigest {
		return errors.New("binding digest drift")
	}
	if b.Status.Phase != core.PolicyBindingAccepted || b.Status.EffectivePolicy == nil || b.Status.EffectivePolicy.Digest != a.EffectiveDigest {
		return errors.New("binding is not accepted at requested effective digest")
	}
	if task.UID != a.TaskUID || task.Generation != a.TaskGeneration {
		return errors.New("task identity drift")
	}
	if a.RuntimeSessionID == "" || a.AttachmentReceiptDigest == "" {
		return errors.New("runtime session and attachment receipt are required")
	}
	c := apiMeta.FindStatusCondition(task.Status.Conditions, ConditionPolicyReady)
	if c == nil || c.Status != metav1.ConditionTrue || c.ObservedGeneration != task.Generation || c.Reason != "PolicyActivated" || c.Message != fmt.Sprintf("%s/%s", a.RuntimeSessionID, a.AttachmentReceiptDigest) {
		return errors.New("durable PolicyReady evidence is absent or stale")
	}
	return nil
}
