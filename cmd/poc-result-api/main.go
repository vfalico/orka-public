package main

import (
	"context"
	"encoding/json"
	"fmt"
	core "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/api"
	"github.com/orka-agents/orka/internal/controller"
	"github.com/orka-agents/orka/internal/executionmode"
	"github.com/orka-agents/orka/internal/store/sqlite"
	auth "k8s.io/api/authentication/v1"
	kcore "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"os"
	"os/signal"
	"path/filepath"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"syscall"
	"time"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	root := os.Getenv("ORKA_LIVE_ROOT")
	cfg, e := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	if e != nil {
		panic(e)
	}
	scheme := runtime.NewScheme()
	core.AddToScheme(scheme)
	kcore.AddToScheme(scheme)
	auth.AddToScheme(scheme)
	c, e := client.New(cfg, client.Options{Scheme: scheme})
	if e != nil {
		panic(e)
	}
	db, e := sqlite.NewDB(filepath.Join(root, "live.db"))
	if e != nil {
		panic(e)
	}
	defer db.Close()
	p := sqlite.NewStore(db, "live-api")
	ks, e := kubernetes.NewForConfig(cfg)
	if e != nil {
		panic(e)
	}
	s := api.NewServer(c, controller.NewSessionManager(p), api.ServerConfig{Port: 28286, WatchNamespace: "orka-system", ExecutionMode: executionmode.HarnessV2, ResultStore: p, SessionStore: p, PlanStore: p, MessageStore: p, ExecutionEventStore: p, APIReader: c, Clientset: ks})
	go func() {
		if e := s.Start(ctx); e != nil {
			fmt.Fprintln(os.Stderr, e)
			cancel()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
			var ts core.TaskList
			if e = c.List(ctx, &ts, client.InNamespace("orka-system")); e != nil {
				fmt.Fprintln(os.Stderr, e)
				continue
			}
			if len(ts.Items) > 0 {
				raw, _ := json.Marshal(ts)
				os.WriteFile(filepath.Join(root, "api-task-observation.json"), raw, 0600)
			}
		}
	}
}
