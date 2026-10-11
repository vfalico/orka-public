package controller

import (
	"context"
	"errors"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/artifactcap"
	"github.com/orka-agents/orka/internal/labels"
	"github.com/orka-agents/orka/internal/publisher"
	publisherservice "github.com/orka-agents/orka/internal/publisher/service"
	"github.com/orka-agents/orka/internal/store"
)

func TestDeletingACPTaskDefersPromptAttemptReclamationWhenStoreIsNotReady(t *testing.T) {
	task, attempt := promptAttemptReclaimFinalizerFixture(t)
	controlStore := &promptAttemptReclaimControlStore{attempt: attempt, reclaimErr: store.ErrNotReady}
	reconciler := &TaskReconciler{
		DurableControlStore:    controlStore,
		ControllerEpochManager: readyPromptAttemptReclaimEpochManager(),
	}

	ready, err := reconciler.retireACPArtifactIdentities(context.Background(), task)
	if err != nil {
		t.Fatalf("retireACPArtifactIdentities() error = %v", err)
	}
	if ready {
		t.Fatal("retireACPArtifactIdentities() reported ready while PromptAttempt reclamation was deferred")
	}
	if len(controlStore.reclaimRequests) != 1 {
		t.Fatalf("reclaim requests = %#v, want one", controlStore.reclaimRequests)
	}
}

func TestDeletingACPTaskReclaimsPromptAttemptsAfterFinalizationBarriers(t *testing.T) {
	task, attempt := promptAttemptReclaimFinalizerFixture(t)
	controlStore := &promptAttemptReclaimControlStore{attempt: attempt, reclaimed: 2}
	epochs := readyPromptAttemptReclaimEpochManager()
	reconciler := &TaskReconciler{DurableControlStore: controlStore, ControllerEpochManager: epochs}

	ready, err := reconciler.retireACPArtifactIdentities(context.Background(), task)
	if err != nil {
		t.Fatalf("retireACPArtifactIdentities() error = %v", err)
	}
	if !ready {
		t.Fatal("retireACPArtifactIdentities() did not complete after PromptAttempt reclamation")
	}
	if len(controlStore.reclaimRequests) != 1 {
		t.Fatalf("reclaim requests = %#v, want one", controlStore.reclaimRequests)
	}
	request := controlStore.reclaimRequests[0]
	if request.Namespace != task.Namespace || request.TaskUID != string(task.UID) ||
		request.FinalPromptAttemptID != attempt.ID ||
		request.TerminalProjectionID != standaloneTaskTerminalProjectionID(task, task.Status.Execution.Attempt) ||
		request.Fence.Name != store.DefaultControllerEpochName || request.Fence.Epoch != 7 || request.Fence.HolderID != "reclaim-controller" {
		t.Fatalf("reclaim request = %#v, want exact Task/final-attempt/projection/epoch binding", request)
	}
}

func TestDeletingRestoredACPTaskUsesFrozenSourceIdentityForCleanup(t *testing.T) {
	task, attempt := promptAttemptReclaimFinalizerFixture(t)
	sourceUID := task.UID
	restoredUID := types.UID("99999999-8888-7777-6666-555555555555")
	task.UID = restoredUID
	task.Finalizers = []string{labels.TaskFinalizer}
	binding := testACPExecuteBindingForDispatcher()
	binding.Task.UID = sourceUID
	task.Status.AgentExecutionBinding = binding
	task.Status.Phase = corev1alpha1.TaskPhaseFailed
	task.Status.Execution.State = corev1alpha1.TaskExecutionStateOutcomeUnknown
	task.Status.Execution.Outcome = corev1alpha1.TaskExecutionOutcomeOutcomeUnknown
	task.Status.Execution.Reason = corev1alpha1.TaskExecutionReason(acpRestoreIdentityChangedReason)
	task.Status.Execution.RuntimeInstanceID = "runtime-instance"
	task.Status.Execution.RuntimeSessionUID = "runtime-session"
	task.Status.Execution.RuntimeSessionGeneration = 1
	cleanupDigest, err := taskScopedRuntimeSessionCleanupDigest(
		sourceUID,
		task.Status.Execution.Attempt,
		task.Status.Execution.RuntimeInstanceID,
		task.Status.Execution.RuntimeSessionUID,
		task.Status.Execution.RuntimeSessionGeneration,
	)
	if err != nil {
		t.Fatal(err)
	}
	task.Status.Execution.RuntimeSessionCleanupDigest = cleanupDigest
	if !taskScopedRuntimeSessionCleanupComplete(task) {
		t.Fatal("restored Task did not recognize the source-bound RuntimeSession cleanup receipt")
	}
	attempt.BindingDigest = binding.BindingDigest
	attempt.SnapshotDigest = binding.Snapshot.Digest

	sourcePublicationID := publicationIDForTaskUID(task, sourceUID)
	sourceProjectionID := standaloneTaskTerminalProjectionIDForUID(task.Namespace, sourceUID, task.Status.Execution.Attempt)
	task.Status.Delivery.PublicationID = sourcePublicationID
	publication := &store.Publication{
		ID: sourcePublicationID, Namespace: task.Namespace, Generation: 1, State: store.PublicationVerifiedExact,
	}
	controlStore := &promptAttemptReclaimControlStore{
		attempt: attempt, publication: publication,
		projection: &store.OutboxProjection{ID: sourceProjectionID, State: store.OutboxProjectionDelivered},
		reclaimed:  1,
	}
	attemptObject := &corev1alpha1.PromptAttempt{
		ObjectMeta: metav1.ObjectMeta{Namespace: task.Namespace, Name: "restored-source-attempt"},
		Spec: corev1alpha1.PromptAttemptSpec{
			ID: attempt.ID, TaskUID: string(sourceUID), Attempt: int64(task.Status.Execution.Attempt), PromptID: task.Status.Execution.PromptID,
		},
		Status: corev1alpha1.PromptAttemptStatus{
			ExecutionState: corev1alpha1.PromptAttemptExecutionState(store.PromptExecutionSucceeded),
			DeliveryState:  corev1alpha1.PromptAttemptDeliveryState(store.PromptDeliveryVerifiedExact),
		},
	}
	publicationObject := &corev1alpha1.Publication{
		ObjectMeta: metav1.ObjectMeta{Namespace: task.Namespace, Name: "restored-source-publication"},
		Spec: corev1alpha1.PublicationSpec{
			ID: sourcePublicationID, Generation: 1, TaskUID: string(sourceUID), Attempt: int64(task.Status.Execution.Attempt),
		},
		Status: corev1alpha1.PublicationStatus{State: corev1alpha1.PublicationControlState(store.PublicationVerifiedExact)},
	}
	reconciler := newUnitReconciler(newTestScheme(), task, attemptObject, publicationObject)
	reconciler.DurableControlStore = controlStore
	reconciler.ControllerEpochManager = readyPromptAttemptReclaimEpochManager()

	ready, err := reconciler.acpTaskDeletionReady(context.Background(), task)
	if err != nil || !ready {
		t.Fatalf("restored Task deletion readiness = %v, %v", ready, err)
	}
	request, err := reconciler.acpPromptAttemptReclamationRequest(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	if request.TaskUID != string(sourceUID) || request.FinalPromptAttemptID != attempt.ID ||
		request.TerminalProjectionID != sourceProjectionID ||
		len(request.RelatedExternalEffectAggregateIDs) != 2 ||
		request.RelatedExternalEffectAggregateIDs[0] != task.Status.Execution.RuntimeSessionUID ||
		request.RelatedExternalEffectAggregateIDs[1] != sourcePublicationID {
		t.Fatalf("restored reclamation request = %#v", request)
	}
	identities, ready, err := reconciler.acpArtifactRetirementIdentities(context.Background(), task)
	if err != nil || !ready {
		t.Fatalf("restored artifact identities readiness = %v, %v", ready, err)
	}
	wantIdentities := []artifactcap.Identity{
		{Namespace: task.Namespace, TaskID: string(sourceUID)},
		{Namespace: task.Namespace, PublicationID: sourcePublicationID},
	}
	if !identitySlicesEqual(identities, wantIdentities) {
		t.Fatalf("restored artifact identities = %#v, want %#v", identities, wantIdentities)
	}
}

func TestDeletingACPTaskRejectsUnvalidatedMismatchedBindingUID(t *testing.T) {
	task, attempt := promptAttemptReclaimFinalizerFixture(t)
	foreignUID := types.UID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	binding := testACPExecuteBindingForDispatcher()
	binding.Task.UID = foreignUID
	task.Status.AgentExecutionBinding = binding
	controlStore := &promptAttemptReclaimControlStore{attempt: attempt}
	reconciler := &TaskReconciler{DurableControlStore: controlStore}

	if got := acpTaskControlUID(task); got != task.UID {
		t.Fatalf("unvalidated control UID = %q, want live Task UID %q", got, task.UID)
	}
	ready, err := reconciler.acpTaskDeletionReady(context.Background(), task)
	if ready || !errors.Is(err, store.ErrConflict) {
		t.Fatalf("unvalidated mismatch deletion readiness = %v, %v, want false/ErrConflict", ready, err)
	}
	if len(controlStore.getAttemptIDs) != 0 {
		t.Fatalf("unvalidated mismatch read foreign PromptAttempt IDs: %#v", controlStore.getAttemptIDs)
	}
}

func TestDeletingACPTaskStillUsesDurableCleanupStoreWhenACPAdmissionDisabled(t *testing.T) {
	task, attempt := promptAttemptReclaimFinalizerFixture(t)
	controlStore := &promptAttemptReclaimControlStore{attempt: attempt, reclaimed: 1}
	reconciler := &TaskReconciler{
		DurableControlStore:    controlStore,
		ControllerEpochManager: readyPromptAttemptReclaimEpochManager(),
		ACPRuntimeEnabled:      false,
	}

	ready, err := reconciler.retireACPArtifactIdentities(context.Background(), task)
	if err != nil {
		t.Fatalf("retireACPArtifactIdentities() error = %v", err)
	}
	if !ready {
		t.Fatal("retireACPArtifactIdentities() did not complete with ACP admission disabled")
	}
	if len(controlStore.reclaimRequests) != 1 {
		t.Fatalf("reclaim requests = %#v, want one cleanup request", controlStore.reclaimRequests)
	}
}

func TestDeletingACPTaskUsesStandaloneProjectionBeforeSessionBinding(t *testing.T) {
	task, attempt := promptAttemptReclaimFinalizerFixture(t)
	task.Spec.SessionRef = &corev1alpha1.SessionReference{Name: "unbound-session", Create: true, Append: true}
	attempt.ExecutionState = store.PromptExecutionCancelled
	attempt.DeliveryState = store.PromptDeliveryNotRequested
	controlStore := &promptAttemptReclaimControlStore{attempt: attempt, reclaimed: 1}
	reconciler := &TaskReconciler{
		DurableControlStore: controlStore, ControllerEpochManager: readyPromptAttemptReclaimEpochManager(),
	}

	ready, err := reconciler.retireACPArtifactIdentities(context.Background(), task)
	if err != nil {
		t.Fatalf("retireACPArtifactIdentities() error = %v", err)
	}
	if !ready || len(controlStore.reclaimRequests) != 1 {
		t.Fatalf("reclamation ready=%v requests=%#v", ready, controlStore.reclaimRequests)
	}
	if got, want := controlStore.reclaimRequests[0].TerminalProjectionID, standaloneTaskTerminalProjectionID(task, task.Status.Execution.Attempt); got != want {
		t.Fatalf("terminal projection ID = %q, want %q", got, want)
	}
}

func TestACPTaskTimeoutRequiresAuthoritativeAttemptDiscovery(t *testing.T) {
	task := &corev1alpha1.Task{Status: corev1alpha1.TaskStatus{
		Phase: corev1alpha1.TaskPhaseCancelled,
		Execution: &corev1alpha1.TaskExecutionStatus{
			State: corev1alpha1.TaskExecutionStateCancelled, Outcome: corev1alpha1.TaskExecutionOutcomeCancelled,
			Reason: corev1alpha1.TaskExecutionReason("TaskTimeout"),
		},
		Delivery: &corev1alpha1.TaskDeliveryStatus{
			State: corev1alpha1.TaskDeliveryStateNotRequested, Outcome: corev1alpha1.TaskDeliveryOutcomeNotRequested,
		},
	}}
	if acpTaskTerminalBeforeDurableAttempt(task) {
		t.Fatal("pre-queue Task timeout was incorrectly classified as proven before durable attempt creation")
	}
	if !acpTaskRequiresAuthoritativeAttemptDiscovery(task) {
		t.Fatal("pre-queue Task timeout did not require authoritative PromptAttempt discovery")
	}
}

func TestACPNoAttemptReclamationIgnoresUnboundSessionReference(t *testing.T) {
	task := artifactRetentionTask()
	task.Spec.SessionRef = &corev1alpha1.SessionReference{Name: "never-bound", Create: true, Append: true}
	task.Status.Execution = &corev1alpha1.TaskExecutionStatus{
		State: corev1alpha1.TaskExecutionStateFailed, Outcome: corev1alpha1.TaskExecutionOutcomeFailed,
		Reason: corev1alpha1.TaskExecutionReason("InvalidWorkspace"),
	}
	task.Status.Delivery = &corev1alpha1.TaskDeliveryStatus{
		State: corev1alpha1.TaskDeliveryStateNotRequested, Outcome: corev1alpha1.TaskDeliveryOutcomeNotRequested,
	}
	reconciler := &TaskReconciler{
		DurableControlStore:    &promptAttemptReclaimControlStore{},
		ControllerEpochManager: readyPromptAttemptReclaimEpochManager(),
	}
	request, err := reconciler.acpPromptAttemptReclamationRequest(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	if request.Mode != store.PromptAttemptReclamationNoAttempt || !request.ContinuitySession || request.FinalContinuitySession {
		t.Fatalf("request = %#v, want NoAttempt with Task history but no final continuity binding", request)
	}
}

func TestACPQueuedTimeoutPreservesTerminalProjectionBarrier(t *testing.T) {
	task, attempt := promptAttemptReclaimFinalizerFixture(t)
	task.Status.Execution.State = corev1alpha1.TaskExecutionStateCancelled
	task.Status.Execution.Outcome = corev1alpha1.TaskExecutionOutcomeCancelled
	task.Status.Execution.Reason = corev1alpha1.TaskExecutionReason("TaskTimeout")
	task.Status.Execution.RuntimePoolName = "pool"
	task.Status.Execution.RuntimePoolUID = "pool-uid"
	task.Status.Execution.RuntimeInstanceID = ""
	task.Status.Execution.RuntimeSessionUID = ""
	task.Status.Execution.RuntimeSessionGeneration = 0
	task.Status.Delivery = &corev1alpha1.TaskDeliveryStatus{
		State: corev1alpha1.TaskDeliveryStateNotRequested, Outcome: corev1alpha1.TaskDeliveryOutcomeNotRequested,
	}
	task.Spec.Workspace = nil
	attempt.ExecutionState = store.PromptExecutionCancelled
	attempt.DeliveryState = store.PromptDeliveryNotRequested
	projectionID := standaloneTaskTerminalProjectionID(task, task.Status.Execution.Attempt)
	controlStore := &promptAttemptReclaimControlStore{
		attempt:    attempt,
		projection: &store.OutboxProjection{ID: projectionID, State: store.OutboxProjectionPending},
	}
	reconciler := &TaskReconciler{
		DurableControlStore: controlStore, ControllerEpochManager: readyPromptAttemptReclaimEpochManager(),
	}
	request, err := reconciler.acpPromptAttemptReclamationRequest(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	if request.Mode != store.PromptAttemptReclamationProjected || request.TerminalProjectionID != projectionID {
		t.Fatalf("request = %#v, want projected reclamation barrier", request)
	}
}

func TestDeletingACPTaskRetiredBeforeDurableAttemptUsesNoAttemptReclamation(t *testing.T) {
	task, attempt := promptAttemptReclaimFinalizerFixture(t)
	task.Finalizers = []string{labels.TaskFinalizer}
	task.Spec.Workspace = &corev1alpha1.WorkspaceConfig{Intent: corev1alpha1.WorkspaceIntentRead}
	task.Status.Phase = corev1alpha1.TaskPhasePending
	task.Status.Execution.State = corev1alpha1.TaskExecutionStatePlanned
	task.Status.Execution.Outcome = ""
	task.Status.Execution.Reason = ""
	task.Status.Execution.RuntimePoolName = "pool"
	task.Status.Execution.RuntimePoolUID = "pool-uid"
	task.Status.Execution.RuntimeInstanceID = "runtime-instance"
	task.Status.Execution.RuntimeSessionUID = "runtime-session"
	task.Status.Execution.RuntimeSessionGeneration = 2
	task.Status.Delivery = &corev1alpha1.TaskDeliveryStatus{
		State: corev1alpha1.TaskDeliveryStateNotRequested, Outcome: corev1alpha1.TaskDeliveryOutcomeNotRequested,
	}
	cleanupDigest, err := taskScopedRuntimeSessionCleanupDigest(
		task.UID, task.Status.Execution.Attempt, task.Status.Execution.RuntimeInstanceID,
		task.Status.Execution.RuntimeSessionUID, task.Status.Execution.RuntimeSessionGeneration,
	)
	if err != nil {
		t.Fatal(err)
	}
	task.Status.Execution.RuntimeSessionCleanupDigest = cleanupDigest
	controlStore := &promptAttemptReclaimControlStore{}
	reconciler := newUnitReconciler(newTestScheme(), task)
	reconciler.DurableControlStore = controlStore
	reconciler.ControllerEpochManager = readyPromptAttemptReclaimEpochManager()

	ready, err := reconciler.acpTaskDeletionReady(context.Background(), task)
	if err != nil || !ready {
		t.Fatalf("retired pre-attempt Task deletion readiness = %v, %v", ready, err)
	}
	request, err := reconciler.acpPromptAttemptReclamationRequest(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	if request.Mode != store.PromptAttemptReclamationNoAttempt || request.FinalPromptAttemptID != "" || request.TerminalProjectionID != "" {
		t.Fatalf("request = %#v, want no-attempt reclamation", request)
	}

	controlStore.attempt = attempt
	attempt.ExecutionState = store.PromptExecutionPlanned
	if ready, err := reconciler.acpTaskDeletionReady(context.Background(), task); err != nil || ready {
		t.Fatalf("Task with a nonterminal durable attempt became deletion-ready: %v, %v", ready, err)
	}
	task.Status.Execution.RuntimeSessionCleanupDigest = ""
	controlStore.attempt = nil
	if ready, err := reconciler.acpTaskDeletionReady(context.Background(), task); err != nil || ready {
		t.Fatalf("Task without exact runtime retirement proof became deletion-ready: %v, %v", ready, err)
	}
}

func TestDeletingACPTaskSettlesBoundPlannedAttemptBeforeReclamation(t *testing.T) {
	task, attempt := retiredBeforeDispatchFixture(t)
	controlStore := &promptAttemptReclaimControlStore{attempt: attempt}
	reconciler := newUnitReconciler(newTestScheme(), task)
	reconciler.APIReader = reconciler.Client
	reconciler.DurableControlStore = controlStore
	reconciler.ControllerEpochManager = readyPromptAttemptReclaimEpochManager()

	settled, err := reconciler.settleRetiredBeforeDispatchACPTask(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	if settled {
		t.Fatal("retired-before-dispatch settlement reported ready before terminal projection delivery")
	}
	if controlStore.attempt.ExecutionState != store.PromptExecutionCancelled ||
		controlStore.attempt.DeliveryState != store.PromptDeliveryNotRequested ||
		controlStore.attempt.TerminalReason != string(acpRetiredBeforeDispatchReason) ||
		controlStore.attempt.OutcomeMarker != acpRetiredBeforeDispatchMessage {
		t.Fatalf("settled attempt = %#v", controlStore.attempt)
	}
	if controlStore.projection == nil ||
		controlStore.projection.ID != standaloneTaskTerminalProjectionID(task, task.Status.Execution.Attempt) ||
		controlStore.projection.State != store.OutboxProjectionPending {
		t.Fatalf("terminal projection = %#v", controlStore.projection)
	}
	stored := &corev1alpha1.Task{}
	if err := reconciler.Get(context.Background(), client.ObjectKeyFromObject(task), stored); err != nil {
		t.Fatal(err)
	}
	if stored.Status.Phase != corev1alpha1.TaskPhaseCancelled || stored.Status.Execution == nil ||
		stored.Status.Execution.State != corev1alpha1.TaskExecutionStateCancelled ||
		stored.Status.Execution.Outcome != corev1alpha1.TaskExecutionOutcomeCancelled ||
		stored.Status.Execution.Reason != acpRetiredBeforeDispatchReason ||
		stored.Status.Execution.RuntimeInstanceID != task.Status.Execution.RuntimeInstanceID ||
		stored.Status.Execution.RuntimeSessionUID != task.Status.Execution.RuntimeSessionUID {
		t.Fatalf("terminal Task status = %#v", stored.Status)
	}

	// A crash after the attempt transition but before observing the projected
	// Task retries the same immutable operation and projection.
	if settled, err := reconciler.settleRetiredBeforeDispatchACPTask(context.Background(), task); err != nil || settled {
		t.Fatalf("idempotent settlement retry = %v, %v", settled, err)
	}
}

func TestDeletingACPTaskRetiredBeforeDispatchRejectsContradictoryEvidence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*corev1alpha1.Task, *store.PromptAttempt, *promptAttemptReclaimControlStore) client.Object
	}{
		{
			name: "attempt identity drift",
			mutate: func(_ *corev1alpha1.Task, attempt *store.PromptAttempt, _ *promptAttemptReclaimControlStore) client.Object {
				attempt.RequestDigest = testControlDigestForDispatcher("different-request")
				return nil
			},
		},
		{
			name: "publication exists",
			mutate: func(task *corev1alpha1.Task, _ *store.PromptAttempt, control *promptAttemptReclaimControlStore) client.Object {
				control.publication = &store.Publication{ID: publicationIDForTask(task)}
				return nil
			},
		},
		{
			name: "external effect exists",
			mutate: func(task *corev1alpha1.Task, _ *store.PromptAttempt, _ *promptAttemptReclaimControlStore) client.Object {
				return &corev1alpha1.ExternalEffect{
					ObjectMeta: metav1.ObjectMeta{Namespace: task.Namespace, Name: "effect"},
					Spec: corev1alpha1.ExternalEffectSpec{
						AggregateID: string(task.UID),
					},
				}
			},
		},
		{
			name: "session turn exists",
			mutate: func(_ *corev1alpha1.Task, attempt *store.PromptAttempt, control *promptAttemptReclaimControlStore) client.Object {
				control.turn = &store.SessionTurn{
					ID: "turn", Key: store.SessionTurnKey{
						SessionUID: attempt.SessionUID, LeaseGeneration: attempt.SessionLeaseGeneration,
						TaskUID: attempt.Key.TaskUID, Attempt: attempt.Key.Attempt, PromptID: attempt.Key.PromptID,
					},
				}
				return nil
			},
		},
		{
			name: "runtime session control exists",
			mutate: func(task *corev1alpha1.Task, _ *store.PromptAttempt, _ *promptAttemptReclaimControlStore) client.Object {
				return &corev1alpha1.RuntimeSessionControl{
					ObjectMeta: metav1.ObjectMeta{Namespace: task.Namespace, Name: "session-control"},
					Spec: corev1alpha1.RuntimeSessionControlSpec{
						SessionName: "session", SessionUID: "session-uid",
						RequestDigest: testControlDigestForDispatcher("session-control"),
						Owner:         corev1alpha1.ControlRecordOwner{Kind: "Task", UID: string(task.UID)},
					},
				}
			},
		},
		{
			name: "runtime session control matches frozen session",
			mutate: func(task *corev1alpha1.Task, _ *store.PromptAttempt, _ *promptAttemptReclaimControlStore) client.Object {
				return &corev1alpha1.RuntimeSessionControl{
					ObjectMeta: metav1.ObjectMeta{Namespace: task.Namespace, Name: "frozen-session-control"},
					Spec: corev1alpha1.RuntimeSessionControlSpec{
						SessionName: "session", SessionUID: task.Status.Execution.RuntimeSessionUID,
						RequestDigest: testControlDigestForDispatcher("frozen-session-control"),
						Owner:         corev1alpha1.ControlRecordOwner{Kind: "Session", UID: "other-owner"},
					},
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			task, attempt := retiredBeforeDispatchFixture(t)
			controlStore := &promptAttemptReclaimControlStore{attempt: attempt}
			extra := test.mutate(task, attempt, controlStore)
			objects := []client.Object{task}
			if extra != nil {
				objects = append(objects, extra)
			}
			reconciler := newUnitReconciler(newTestScheme(), objects...)
			reconciler.APIReader = reconciler.Client
			reconciler.DurableControlStore = controlStore
			reconciler.ControllerEpochManager = readyPromptAttemptReclaimEpochManager()

			if settled, err := reconciler.settleRetiredBeforeDispatchACPTask(context.Background(), task); err == nil || settled {
				t.Fatalf("contradictory settlement = %v, %v, want false/error", settled, err)
			}
			if controlStore.transitionCalls != 0 || controlStore.projection != nil {
				t.Fatalf("contradictory evidence mutated attempt/projection: transitions=%d projection=%#v",
					controlStore.transitionCalls, controlStore.projection)
			}
		})
	}
}

func TestDeletingACPTaskRetiredBeforeDispatchUsesAuthoritativeContradictionReader(t *testing.T) {
	task, attempt := retiredBeforeDispatchFixture(t)
	controlStore := &promptAttemptReclaimControlStore{attempt: attempt}
	reconciler := newUnitReconciler(newTestScheme(), task)
	reconciler.APIReader = newUnitReconciler(
		newTestScheme(),
		task.DeepCopy(),
		&corev1alpha1.ExternalEffect{
			ObjectMeta: metav1.ObjectMeta{Namespace: task.Namespace, Name: "authoritative-effect"},
			Spec:       corev1alpha1.ExternalEffectSpec{AggregateID: string(task.UID)},
		},
	).Client
	reconciler.DurableControlStore = controlStore
	reconciler.ControllerEpochManager = readyPromptAttemptReclaimEpochManager()

	if settled, err := reconciler.settleRetiredBeforeDispatchACPTask(context.Background(), task); err == nil || settled {
		t.Fatalf("authoritative contradiction settlement = %v, %v, want false/error", settled, err)
	}
	if controlStore.transitionCalls != 0 || controlStore.projection != nil {
		t.Fatalf("authoritative contradiction mutated attempt/projection: transitions=%d projection=%#v",
			controlStore.transitionCalls, controlStore.projection)
	}
}

func TestDeletingACPTaskRetiredBeforeDispatchCASPreservesValidatedDeliveryState(t *testing.T) {
	task, attempt := retiredBeforeDispatchFixture(t)
	controlStore := &promptAttemptReclaimControlStore{attempt: attempt, raceBeforeTransition: true}
	reconciler := newUnitReconciler(newTestScheme(), task)
	reconciler.APIReader = reconciler.Client
	reconciler.DurableControlStore = controlStore
	reconciler.ControllerEpochManager = readyPromptAttemptReclaimEpochManager()

	if settled, err := reconciler.settleRetiredBeforeDispatchACPTask(context.Background(), task); err == nil || settled {
		t.Fatalf("raced settlement = %v, %v, want false/error", settled, err)
	}
	if controlStore.attempt.ExecutionState != store.PromptExecutionPlanned ||
		controlStore.attempt.DeliveryState != store.PromptDeliveryValidating ||
		controlStore.projection != nil {
		t.Fatalf("raced attempt/projection = %#v / %#v", controlStore.attempt, controlStore.projection)
	}
}

func retiredBeforeDispatchFixture(t *testing.T) (*corev1alpha1.Task, *store.PromptAttempt) {
	t.Helper()
	task, attempt := promptAttemptReclaimFinalizerFixture(t)
	task.Finalizers = []string{labels.TaskFinalizer}
	task.Spec.Workspace = &corev1alpha1.WorkspaceConfig{Intent: corev1alpha1.WorkspaceIntentRead}
	task.Status.AgentExecutionBinding = testACPExecuteBindingForDispatcher()
	task.Status.AgentExecutionBinding.Task.UID = task.UID
	task.Status.Phase = corev1alpha1.TaskPhasePending
	task.Status.Execution.State = corev1alpha1.TaskExecutionStatePlanned
	task.Status.Execution.Outcome = ""
	task.Status.Execution.Reason = ""
	task.Status.Execution.RequestDigest = testControlDigestForDispatcher("retired-before-dispatch-request")
	task.Status.Execution.RuntimePoolName = "pool"
	task.Status.Execution.RuntimePoolUID = "pool-uid"
	task.Status.Execution.RuntimeInstanceID = "runtime-instance"
	task.Status.Execution.RuntimeSessionUID = "runtime-session"
	task.Status.Execution.RuntimeSessionGeneration = 2
	task.Status.Delivery = &corev1alpha1.TaskDeliveryStatus{
		State: corev1alpha1.TaskDeliveryStateNotRequested, Outcome: corev1alpha1.TaskDeliveryOutcomeNotRequested,
	}
	cleanupDigest, err := taskScopedRuntimeSessionCleanupDigest(
		task.UID, task.Status.Execution.Attempt, task.Status.Execution.RuntimeInstanceID,
		task.Status.Execution.RuntimeSessionUID, task.Status.Execution.RuntimeSessionGeneration,
	)
	if err != nil {
		t.Fatal(err)
	}
	task.Status.Execution.RuntimeSessionCleanupDigest = cleanupDigest
	attempt.ExecutionState = store.PromptExecutionPlanned
	attempt.DeliveryState = store.PromptDeliveryNotRequested
	attempt.RequestDigest = task.Status.Execution.RequestDigest
	attempt.BindingDigest = task.Status.AgentExecutionBinding.BindingDigest
	attempt.SnapshotDigest = task.Status.AgentExecutionBinding.Snapshot.Digest
	attempt.RuntimeInstanceID = task.Status.Execution.RuntimeInstanceID
	attempt.SessionUID = task.Status.Execution.RuntimeSessionUID
	attempt.SessionLeaseGeneration = task.Status.Execution.RuntimeSessionGeneration
	attempt.Version = 4
	return task, attempt
}

func TestDeletingACPTaskReclaimsPublisherCacheBeforeDurableArtifactsAndRetries(t *testing.T) {
	task, attempt := promptAttemptReclaimFinalizerFixture(t)
	task.Finalizers = []string{labels.TaskFinalizer}
	publicationID := publicationIDForTask(task)
	task.Status.Delivery.PublicationID = publicationID
	publication := &store.Publication{ID: publicationID, Namespace: task.Namespace, Generation: 1, State: store.PublicationVerifiedExact}
	projection := &store.OutboxProjection{
		ID: standaloneTaskTerminalProjectionID(task, task.Status.Execution.Attempt), State: store.OutboxProjectionDelivered,
	}
	attemptObject := &corev1alpha1.PromptAttempt{
		ObjectMeta: metav1.ObjectMeta{Namespace: task.Namespace, Name: "publisher-reclaim-attempt"},
		Spec: corev1alpha1.PromptAttemptSpec{
			ID: attempt.ID, TaskUID: string(task.UID), Attempt: int64(task.Status.Execution.Attempt), PromptID: task.Status.Execution.PromptID,
		},
		Status: corev1alpha1.PromptAttemptStatus{
			ExecutionState: corev1alpha1.PromptAttemptExecutionState(store.PromptExecutionSucceeded),
			DeliveryState:  corev1alpha1.PromptAttemptDeliveryState(store.PromptDeliveryVerifiedExact),
		},
	}
	publicationObject := &corev1alpha1.Publication{
		ObjectMeta: metav1.ObjectMeta{Namespace: task.Namespace, Name: "publisher-reclaim-publication"},
		Spec: corev1alpha1.PublicationSpec{
			ID: publicationID, Generation: publication.Generation, TaskUID: string(task.UID), Attempt: int64(task.Status.Execution.Attempt),
		},
		Status: corev1alpha1.PublicationStatus{State: corev1alpha1.PublicationControlState(store.PublicationVerifiedExact)},
	}

	events := []string{}
	controlStore := &promptAttemptReclaimControlStore{
		attempt: attempt, publication: publication, projection: projection, reclaimed: 1, events: &events,
	}
	reclaimer := &recordingPublicationReclaimer{failures: 1, events: &events}
	reconciler := newUnitReconciler(newTestScheme(), task, attemptObject, publicationObject)
	reconciler.DurableControlStore = controlStore
	reconciler.ControllerEpochManager = readyPromptAttemptReclaimEpochManager()
	reconciler.ACPPublicationReclaimer = reclaimer

	if _, err := reconciler.handleDeletion(context.Background(), task); err == nil {
		t.Fatal("first handleDeletion() error = nil, want Publisher reclaim retry")
	}
	if len(events) != 1 || events[0] != "publisher" {
		t.Fatalf("first deletion events = %v, want Publisher only", events)
	}
	var stored corev1alpha1.Task
	if err := reconciler.Get(context.Background(), types.NamespacedName{Namespace: task.Namespace, Name: task.Name}, &stored); err != nil {
		t.Fatalf("get Task after failed Publisher reclaim: %v", err)
	}
	if !controllerutil.ContainsFinalizer(&stored, labels.TaskFinalizer) {
		t.Fatal("Task finalizer removed before Publisher reclaim succeeded")
	}

	if _, err := reconciler.handleDeletion(context.Background(), task); err != nil {
		t.Fatalf("retry handleDeletion(): %v", err)
	}
	wantEvents := []string{"publisher", "publisher", "prepare-prompt-reclaim", "prompt-reclaim"}
	if len(events) != len(wantEvents) {
		t.Fatalf("retry deletion events = %v, want %v", events, wantEvents)
	}
	for index := range wantEvents {
		if events[index] != wantEvents[index] {
			t.Fatalf("retry deletion events = %v, want %v", events, wantEvents)
		}
	}
	if len(reclaimer.requests) != 2 || reclaimer.requests[0] != reclaimer.requests[1] {
		t.Fatalf("Publisher reclaim requests = %#v, want identical crash-safe retry", reclaimer.requests)
	}
	request := reclaimer.requests[1]
	if request.Metadata.PublicationID != publicationID || request.Request.PublicationID != publicationID ||
		request.Request.PublicationGeneration != publication.Generation {
		t.Fatalf("Publisher reclaim request = %#v, want exact publication identity", request)
	}
	if err := reconciler.Get(context.Background(), types.NamespacedName{Namespace: task.Namespace, Name: task.Name}, &stored); !apierrors.IsNotFound(err) && (err != nil || controllerutil.ContainsFinalizer(&stored, labels.TaskFinalizer)) {
		t.Fatalf("Task finalizer remains after successful ordered cleanup: %v, %#v", err, stored.Finalizers)
	}
}

type recordingPublicationReclaimer struct {
	requests []publisherservice.PublicationReclaimRequest
	failures int
	events   *[]string
}

func (r *recordingPublicationReclaimer) ReclaimPublication(
	_ context.Context, request publisherservice.PublicationReclaimRequest,
) (publisherservice.PublicationReclaimResponse, error) {
	r.requests = append(r.requests, request)
	if r.events != nil {
		*r.events = append(*r.events, "publisher")
	}
	if r.failures > 0 {
		r.failures--
		return publisherservice.PublicationReclaimResponse{}, errors.New("temporary Publisher reclaim failure")
	}
	return publisherservice.PublicationReclaimResponse{
		OperationID: request.Metadata.OperationID,
		Result: publisher.ReclaimResult{
			PublicationID: request.Request.PublicationID, PublicationGeneration: request.Request.PublicationGeneration, Reclaimed: true,
		},
	}, nil
}

func promptAttemptReclaimFinalizerFixture(t *testing.T) (*corev1alpha1.Task, *store.PromptAttempt) {
	t.Helper()
	task := artifactRetentionTask()
	now := metav1.Now()
	task.DeletionTimestamp = &now
	meta.SetStatusCondition(&task.Status.Conditions, metav1.Condition{
		Type: conditionTypeACPArtifactsRetired, Status: metav1.ConditionTrue,
		Reason: "ArtifactReferencesReleased", LastTransitionTime: now,
	})
	key := store.PromptAttemptKey{
		Namespace: task.Namespace, TaskUID: string(task.UID), Attempt: int64(task.Status.Execution.Attempt), PromptID: task.Status.Execution.PromptID,
	}
	id, err := key.CanonicalID()
	if err != nil {
		t.Fatal(err)
	}
	return task, &store.PromptAttempt{
		ID: id, Key: key, ExecutionState: store.PromptExecutionSucceeded, DeliveryState: store.PromptDeliveryVerifiedExact,
	}
}

type promptAttemptReclaimControlStore struct {
	store.DurableControlStore
	attempt              *store.PromptAttempt
	getAttemptIDs        []string
	reclaimed            int
	reclaimErr           error
	reclaimRequests      []store.ReclaimPromptAttemptsRequest
	projection           *store.OutboxProjection
	publication          *store.Publication
	turn                 *store.SessionTurn
	transitionCalls      int
	raceBeforeTransition bool
	events               *[]string
}

func (s *promptAttemptReclaimControlStore) GetOutboxProjection(_ context.Context, id string) (*store.OutboxProjection, error) {
	if s.projection == nil || s.projection.ID != id {
		return nil, store.ErrNotFound
	}
	copy := *s.projection
	return &copy, nil
}

func (s *promptAttemptReclaimControlStore) EnqueueOutboxProjection(
	_ context.Context,
	projection *store.OutboxProjection,
	_ store.ControllerEpochFence,
) (*store.OutboxProjection, error) {
	if s.projection != nil {
		if s.projection.ID != projection.ID || s.projection.PayloadDigest != projection.PayloadDigest {
			return nil, store.ErrConflict
		}
		copy := *s.projection
		return &copy, nil
	}
	copy := *projection
	copy.State = store.OutboxProjectionPending
	copy.Version = 1
	s.projection = &copy
	return projection, nil
}

func (s *promptAttemptReclaimControlStore) PreparePromptAttemptReclamation(context.Context, store.ReclaimPromptAttemptsRequest) error {
	if s.events != nil {
		*s.events = append(*s.events, "prepare-prompt-reclaim")
	}
	return nil
}

func (s *promptAttemptReclaimControlStore) GetPromptAttempt(_ context.Context, id string) (*store.PromptAttempt, error) {
	s.getAttemptIDs = append(s.getAttemptIDs, id)
	if s.attempt == nil || s.attempt.ID != id {
		return nil, store.ErrNotFound
	}
	copy := *s.attempt
	return &copy, nil
}

func (s *promptAttemptReclaimControlStore) TransitionPromptAttemptExecution(
	_ context.Context,
	transition store.PromptAttemptExecutionTransition,
) (*store.PromptAttempt, error) {
	if s.raceBeforeTransition {
		s.raceBeforeTransition = false
		s.attempt.DeliveryState = store.PromptDeliveryValidating
		s.attempt.Version++
	}
	if s.attempt == nil || s.attempt.ID != transition.ID ||
		s.attempt.Version != transition.ExpectedVersion || s.attempt.ExecutionState != transition.ExpectedState {
		return nil, store.ErrConflict
	}
	s.transitionCalls++
	s.attempt.ExecutionState = transition.NewState
	s.attempt.TerminalReason = transition.TerminalReason
	s.attempt.OutcomeMarker = transition.OutcomeMarker
	s.attempt.LastOperationID = transition.OperationID
	s.attempt.LastOperationDigest = transition.OperationDigest
	s.attempt.Version++
	s.attempt.ControllerEpoch = transition.Fence.Epoch
	s.attempt.UpdatedAt = transition.UpdatedAt
	copy := *s.attempt
	return &copy, nil
}

func (s *promptAttemptReclaimControlStore) GetSessionTurn(_ context.Context, id string) (*store.SessionTurn, error) {
	if s.turn == nil {
		return nil, store.ErrNotFound
	}
	expected, err := s.turn.Key.CanonicalID()
	if err != nil || expected != id {
		return nil, store.ErrNotFound
	}
	copy := *s.turn
	return &copy, nil
}

func (s *promptAttemptReclaimControlStore) GetPublication(_ context.Context, id string) (*store.Publication, error) {
	if s.publication == nil || s.publication.ID != id {
		return nil, store.ErrNotFound
	}
	copy := *s.publication
	return &copy, nil
}

func (s *promptAttemptReclaimControlStore) ReclaimPromptAttempts(_ context.Context, request store.ReclaimPromptAttemptsRequest) (int, error) {
	s.reclaimRequests = append(s.reclaimRequests, request)
	if s.events != nil {
		*s.events = append(*s.events, "prompt-reclaim")
	}
	if s.reclaimErr != nil {
		return 0, s.reclaimErr
	}
	return s.reclaimed, nil
}

func readyPromptAttemptReclaimEpochManager() *ControllerEpochManager {
	epochs := NewControllerEpochManager(nil, "reclaim-controller")
	epochs.current = &store.ControllerEpoch{Name: store.DefaultControllerEpochName, Epoch: 7, HolderID: "reclaim-controller"}
	close(epochs.ready)
	return epochs
}
