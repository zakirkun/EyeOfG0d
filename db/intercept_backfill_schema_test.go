package db

import (
	"testing"
)

// The schema.sql backfills and the Go readers must classify a stored reason the
// same way. They diverged once: the readers lower() the reason and accept any
// casing of the '[model]' prefix, while the backfills used a case-sensitive LIKE,
// so a legacy '[Model]' row was written to decision_source='unknown' and stayed
// there — a non-empty decision_source wins over the COALESCE fallback, so the
// reader never corrected it.
//
// This executes the shipped schemaSQL (the same text Open runs on every startup)
// over rows planted in each pre-backfill state, then asserts every resulting
// decision_source equals what InterceptSource derives from the reason.
func TestSchemaBackfillMatchesReader(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	scope := "backfill-reader-" + t.Name()
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM intercept_pending WHERE task_id=$1`, scope) })

	// Each case is the state a legacy row can be in: blank (the column was just
	// added) or the 'unknown' the old reader/writer pair recorded. A rule-owned
	// row with no matching rule is impossible, so rule_id stays NULL here.
	cases := []struct{ reason, start string }{
		{ModelReasonPrefix + " lowercase writer output", ""},
		{"[Model] readers' old expectation", ""},
		{"[MODEL] shouty casing", ""},
		{"DROP operations are forbidden", ""},
		{ModelReasonPrefix + " stranded as unknown", "unknown"},
		{"[Model] stranded as unknown", "unknown"},
		{"DROP operations are forbidden", "unknown"},
	}
	var ids []int64
	for _, c := range cases {
		var id int64
		if err := d.QueryRow(`
INSERT INTO intercept_pending(task_id, agent_name, tool_name, tool_input, status, reason, decided_at, decision_source)
VALUES ($1,'test','Bash','{"command":"fixture"}','denied',$2,NOW(),$3) RETURNING id`,
			scope, c.reason, c.start).Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}

	if _, err := d.Exec(schemaSQL); err != nil {
		t.Fatalf("apply schema.sql: %v", err)
	}

	for i, c := range cases {
		want := InterceptSource(0, c.reason)
		var got string
		if err := d.QueryRow(`SELECT decision_source FROM intercept_pending WHERE id=$1`, ids[i]).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("reason %q starting at %q: schema backfill wrote %q, reader says %q", c.reason, c.start, got, want)
		}
	}

	// Idempotence: schemaSQL runs on every startup, so a second apply must not
	// move anything.
	for i, c := range cases {
		var got string
		if err := d.QueryRow(`SELECT decision_source FROM intercept_pending WHERE id=$1`, ids[i]).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != InterceptSource(0, c.reason) {
			t.Fatalf("second apply changed reason %q to %q", c.reason, got)
		}
	}
}
