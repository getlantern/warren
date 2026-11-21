package main

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/getlantern/warren/natprobe"
)

// -json with -mapping-timeout must still print exactly one JSON document.
func TestJSONIncludesMappingTimeout(t *testing.T) {
	var buf bytes.Buffer
	rep := &natprobe.Report{Queries: 3}
	tr := &natprobe.TimeoutResult{Detectable: true, AliveAt: 30 * time.Second, Expired: time.Minute}
	if err := writeJSON(&buf, rep, tr); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(&buf)
	var got map[string]any
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if dec.More() {
		t.Fatal("output holds more than one JSON document")
	}
	if _, ok := got["mapping_timeout"]; !ok {
		t.Fatalf("no mapping_timeout in %v", got)
	}
	if _, ok := got["local"]; !ok {
		t.Fatalf("report fields not flattened: %v", got)
	}
}
