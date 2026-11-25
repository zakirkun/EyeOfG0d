package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestTransportTimeoutsExceedOperationBudgets guards a bug that shipped once
// already: the HTTP transport timeouts were 30s (read) and 60s (write) while
// the install handler legitimately runs for four minutes and accepts a 256 MiB
// body. The handler's own context was never reached, because net/http severed
// the connection first, and the failure surfaced as a generic transport error
// rather than a timeout the caller could interpret.
//
// It asserts on the real server the binary serves with, not a copy, and checks
// the relation rather than the literal numbers, so budgets can be tuned without
// weakening the guarantee.
func TestTransportTimeoutsExceedOperationBudgets(t *testing.T) {
	budgets := map[string]time.Duration{
		"install":  installTimeout,
		"launch":   launchTimeout,
		"logs":     logsTimeout,
		"packages": packagesTimeout,
	}
	for name, budget := range budgets {
		if maxRequestBudget < budget {
			t.Errorf("maxRequestBudget %s is below the %s budget %s", maxRequestBudget, name, budget)
		}
	}

	srv := newHTTPServer(http.NewServeMux())
	if srv.ReadTimeout <= maxRequestBudget {
		t.Errorf("ReadTimeout %s does not exceed maxRequestBudget %s; an upload would be severed", srv.ReadTimeout, maxRequestBudget)
	}
	if srv.WriteTimeout <= maxRequestBudget {
		t.Errorf("WriteTimeout %s does not exceed maxRequestBudget %s; the response would be severed", srv.WriteTimeout, maxRequestBudget)
	}
	// The header deadline must stay tight: a peer that cannot send headers is
	// not the same as a large legitimate body.
	if srv.ReadHeaderTimeout >= srv.ReadTimeout {
		t.Errorf("ReadHeaderTimeout %s is not tighter than ReadTimeout %s", srv.ReadHeaderTimeout, srv.ReadTimeout)
	}
}

// TestServerSurvivesAnUploadLongerThanTheOldCap proves the previous 60s write
// timeout was the binding constraint, by serving from newHTTPServer itself with
// a handler that holds the connection past that old cap.
//
// The hold is lengthened past the old 60s cap only when the caller opts in:
// a minute per run is too slow for the default suite, so the cheap 2s variant
// asserts the ordering property while ARTEX_SIDECAR_SLOW_TEST=1 exercises the
// full duration. Both variants fail if the transport is retightened below the
// install budget.
func TestServerSurvivesAnUploadLongerThanTheOldCap(t *testing.T) {
	const oldCap = 60 * time.Second

	hold := 2 * time.Second
	if testing.Short() {
		t.Skip("occupies a connection for several seconds")
	}

	release := make(chan struct{})
	var once sync.Once
	started := make(chan struct{})

	mux := http.NewServeMux()
	mux.HandleFunc("POST /upload", func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			t.Errorf("server could not read the body: %v", err)
			return
		}
		select {
		case <-release:
		case <-time.After(hold):
		}
		_, _ = w.Write([]byte(strings.Repeat("x", int(n))))
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newHTTPServer(mux)
	// Serve on the ephemeral listener instead of the production port.
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		close(release)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	// A 60s cap is only meaningful if the budget actually exceeds it.
	if installTimeout <= oldCap {
		t.Fatalf("installTimeout %s is not above the old 60s transport cap", installTimeout)
	}

	body := strings.Repeat("P", 1024)
	req, err := http.NewRequest(http.MethodPost, "http://"+ln.Addr().String()+"/upload", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Timeout: installTimeout}).Do(req)
	if err != nil {
		t.Fatalf("upload was severed by the transport: %v", err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("response was severed by the transport: %v", err)
	}
	if len(got) != len(body) {
		t.Fatalf("response was truncated: got %d bytes, want %d", len(got), len(body))
	}
	<-started
}
