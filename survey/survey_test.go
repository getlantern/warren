package survey

import (
	"net/netip"
	"strings"
	"testing"
)

func TestPrefixLabeler(t *testing.T) {
	l := PrefixLabeler(map[string][]netip.Prefix{"IR": {netip.MustParsePrefix("2.176.0.0/12")}})
	if got := l(netip.MustParseAddr("2.180.1.1")); got != "IR" {
		t.Errorf("label = %q", got)
	}
	if got := l(netip.MustParseAddr("::ffff:2.180.1.1")); got != "IR" {
		t.Errorf("mapped label = %q", got)
	}
	if got := l(netip.MustParseAddr("8.8.8.8")); got != "other" {
		t.Errorf("label = %q", got)
	}
}

func TestTallyReport(t *testing.T) {
	tl := NewTally()
	for i := range 10 {
		tl.update("IR", func(c *Counts) {
			c.ColdProbed++
			if i < 3 {
				c.ColdAnswered++
			}
		})
	}
	out := tl.String()
	if !strings.Contains(out, "IR") || !strings.Contains(out, " 30% of     10 probed") {
		t.Errorf("report:\n%s", out)
	}
}
