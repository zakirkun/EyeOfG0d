package server

import (
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"github.com/zakirkun/EyeOfG0d/db"
)

type diffResponse struct {
	New                 []db.FindingDiffEntry `json:"new"`
	Persisting          []db.FindingDiffEntry `json:"persisting"`
	Resolved            []db.FindingDiffEntry `json:"resolved"`
	Regressed           []db.FindingDiffEntry `json:"regressed"`
	BaseComplete        bool                  `json:"base_complete"`
	HeadComplete        bool                  `json:"head_complete"`
	ResolvedTrustworthy bool                  `json:"resolved_trustworthy"`
	ResolvedNote        string                `json:"resolved_note"`
	Untracked           int                   `json:"untracked"`
}

// diffPair creates two tasks and registers their findings for cleanup. Findings
// are removed before the tasks because findings.task_id is ON DELETE SET NULL:
// dropping the task alone would leave orphan rows behind.
func diffPair(t *testing.T, s *Server) (baseID, headID int64) {
	t.Helper()
	pg := s.m.pg

	mk := func(desc string) int64 {
		t.Helper()
		tk, err := s.m.CreateTask(desc, "goal", nil, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		id, err := strconv.ParseInt(tk.ID, 10, 64)
		if err != nil {
			t.Fatalf("task id %q: %v", tk.ID, err)
		}
		return id
	}
	baseID, headID = mk("diff base"), mk("diff head")
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM findings WHERE task_id IN ($1,$2)`, baseID, headID)
		_ = pg.DeleteTask(baseID)
		_ = pg.DeleteTask(headID)
	})
	return baseID, headID
}

func mustAddFinding(t *testing.T, s *Server, taskID int64, class, status string) {
	t.Helper()
	id, err := s.m.pg.AddFinding(taskID, 0, class, class, "high", "summary", "evidence", "worker", []int64{4242})
	if err != nil {
		t.Fatalf("AddFinding(%s): %v", class, err)
	}
	if status != "" && status != db.FindingPending {
		if _, err := s.m.pg.Exec(`UPDATE findings SET status=$2 WHERE id=$1`, id, status); err != nil {
			t.Fatal(err)
		}
	}
}

// The endpoint answers the question the feature exists for: what changed between
// these two runs?
func TestTaskDiffEndpointBuckets(t *testing.T) {
	s, _, req := trafficEvidenceServer(t)
	baseID, headID := diffPair(t, s)

	mustAddFinding(t, s, baseID, "xss", "")  // also in head → persisting
	mustAddFinding(t, s, baseID, "sqli", "") // absent from head → resolved
	mustAddFinding(t, s, headID, "xss", "")
	mustAddFinding(t, s, headID, "ssrf", "") // only in head → new

	w := req("GET", fmt.Sprintf("/api/tasks/%d/diff?base=%d", headID, baseID), "")
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var got diffResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}

	if len(got.New) != 1 || got.New[0].VulnClass != "ssrf" {
		t.Errorf("new = %+v, want ssrf", got.New)
	}
	if len(got.Persisting) != 1 || got.Persisting[0].VulnClass != "xss" {
		t.Errorf("persisting = %+v, want xss", got.Persisting)
	}
	if len(got.Resolved) != 1 || got.Resolved[0].VulnClass != "sqli" {
		t.Errorf("resolved = %+v, want sqli", got.Resolved)
	}
	if len(got.Regressed) != 0 {
		t.Errorf("regressed = %+v, want empty", got.Regressed)
	}
}

// A previously-fixed issue that is back is a regression, and the endpoint must
// say so rather than calling it a persisting finding.
func TestTaskDiffEndpointReportsRegression(t *testing.T) {
	s, _, req := trafficEvidenceServer(t)
	baseID, headID := diffPair(t, s)

	mustAddFinding(t, s, baseID, "xss", db.FindingFixed)
	mustAddFinding(t, s, headID, "xss", db.FindingConfirmed)

	w := req("GET", fmt.Sprintf("/api/tasks/%d/diff?base=%d", headID, baseID), "")
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var got diffResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Regressed) != 1 || got.Regressed[0].VulnClass != "xss" {
		t.Fatalf("regressed = %+v, want xss", got.Regressed)
	}
	if len(got.Persisting) != 0 {
		t.Errorf("a fixed issue that returned must not also be persisted: %+v", got.Persisting)
	}
}

// The honesty rule must survive the HTTP boundary: an unfinished head run cannot
// claim a fix.
func TestTaskDiffEndpointWithholdsResolvedOnIncompleteHead(t *testing.T) {
	s, _, req := trafficEvidenceServer(t)
	baseID, headID := diffPair(t, s)

	mustAddFinding(t, s, baseID, "sqli", "")

	w := req("GET", fmt.Sprintf("/api/tasks/%d/diff?base=%d", headID, baseID), "")
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var got diffResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.HeadComplete {
		t.Fatal("head task reports complete while still in progress")
	}
	if got.ResolvedTrustworthy {
		t.Fatal("HONESTY RULE VIOLATED over HTTP: incomplete head claimed a trustworthy resolved")
	}
	if got.ResolvedNote == "" {
		t.Fatal("withheld the claim but sent no explanation")
	}
	if len(got.Resolved) != 1 {
		t.Errorf("the entry should still be reported, got %+v", got.Resolved)
	}
}

// Requests that cannot mean anything must be rejected rather than answered with
// a plausible-looking empty diff.
func TestTaskDiffEndpointRejectsBadRequests(t *testing.T) {
	s, f, req := trafficEvidenceServer(t)

	var taskID int64
	if err := s.m.pg.QueryRow(`SELECT task_id FROM findings WHERE id=$1`, f.FindingID).Scan(&taskID); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		url  string
		want int
	}{
		{"missing base", fmt.Sprintf("/api/tasks/%d/diff", taskID), 400},
		{"unknown base", fmt.Sprintf("/api/tasks/%d/diff?base=999999999", taskID), 404},
		{"self diff", fmt.Sprintf("/api/tasks/%d/diff?base=%d", taskID, taskID), 400},
		{"unknown head", "/api/tasks/999999999/diff?base=1", 404},
	} {
		w := req("GET", tc.url, "")
		if w.Code != tc.want {
			t.Errorf("%s: status %d, want %d (%s)", tc.name, w.Code, tc.want, w.Body.String())
		}
	}
}
