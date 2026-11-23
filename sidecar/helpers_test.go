package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// taskRequest builds a request the way the mux would, with the path value set.
func taskRequest(id string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/tasks/"+id+"/start", nil)
	r.SetPathValue("id", id)
	return r
}

func decode(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
}

// launchRequest builds a launch POST with a JSON body.
func launchRequest(id, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/tasks/"+id+"/launch", strings.NewReader(body))
	r.SetPathValue("id", id)
	return r
}

// getRequest builds a GET with the path value set the way the mux would.
func getRequest(id, target string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.SetPathValue("id", id)
	return r
}
