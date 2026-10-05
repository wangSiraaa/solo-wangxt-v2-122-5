package query

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"localtest/dnszone/internal/zone"
)

const zoneV1 = `$ORIGIN lab.test.
$TTL 3600
@ IN SOA ns1.lab.test. admin.lab.test. (1 7200 3600 1209600 300)
@ IN NS ns1.lab.test.
ns1 IN A 127.0.0.10
www IN A 127.0.0.20
www IN TXT "v1"
alias IN CNAME www.lab.test.
out IN CNAME elsewhere.example.net.
`

const zoneV2 = `$ORIGIN lab.test.
$TTL 3600
@ IN SOA ns1.lab.test. admin.lab.test. (2 7200 3600 1209600 300)
@ IN NS ns1.lab.test.
ns1 IN A 127.0.0.10
www IN A 127.0.0.20
www IN A 127.0.0.21
www IN TXT "v2"
alias IN CNAME www.lab.test.
out IN CNAME elsewhere.example.net.
`

func mustSnap(t *testing.T, serial uint32, text string) *zone.Snapshot {
	t.Helper()
	rrs, err := zone.Parse(strings.NewReader(text), "lab.test.",
		zone.Limits{MinTTL: 30, MaxTTL: 86400})
	if err != nil {
		t.Fatal(err)
	}
	s, err := zone.NewSnapshot("lab.test.", serial, rrs)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestParseType(t *testing.T) {
	cases := map[string]uint16{
		"A":    dns.TypeA,
		"aaaa": dns.TypeAAAA,
		"Any":  dns.TypeANY,
		"MX":   dns.TypeMX,
		"65":   65, // HTTPS: arbitrary numeric type accepted
		"TXT ": dns.TypeTXT,
	}
	for in, want := range cases {
		got, err := ParseType(in)
		if err != nil || got != want {
			t.Fatalf("ParseType(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"AXFR", "ixfr", "bogus", ""} {
		if _, err := ParseType(bad); err == nil {
			t.Fatalf("ParseType(%q) expected error", bad)
		}
	}
}

func TestQualifyName(t *testing.T) {
	cases := map[string]string{
		"www":            "www.lab.test.",
		"www.lab.test":   "www.lab.test.",
		"WWW.LAB.TEST.":  "www.lab.test.",
		"@":              "lab.test.",
		"a.b.lab.test.":  "a.b.lab.test.",
		"other.example.": "other.example.",
	}
	for in, want := range cases {
		if got := QualifyName(in, "lab.test."); got != want {
			t.Fatalf("QualifyName(%q) = %q, want %q", in, got, want)
		}
	}
}

func render(t *testing.T, snap *zone.Snapshot, name string, qtype uint16) string {
	t.Helper()
	resp := snap.AuthoritativeReply(dns.Question{
		Name: dns.Fqdn(name), Qtype: qtype, Qclass: dns.ClassINET,
	})
	var b bytes.Buffer
	Render(&b, resp, snap, VersionDetail{
		Serial: snap.Serial, Note: "n", CurrentSerial: 2,
		PublishedAt: time.Date(2026, 10, 5, 1, 2, 3, 0, time.UTC),
	})
	return b.String()
}

func TestRenderOldVsNewVersionDiffer(t *testing.T) {
	// Same name, old vs new version must show different records.
	old := render(t, mustSnap(t, 1, zoneV1), "www.lab.test.", dns.TypeA)
	new := render(t, mustSnap(t, 2, zoneV2), "www.lab.test.", dns.TypeA)
	if !strings.Contains(old, "127.0.0.20") || strings.Count(old, "127.0.0.2") != 1 {
		t.Fatalf("v1 www A should have one address:\n%s", old)
	}
	if !strings.Contains(new, "127.0.0.20") || !strings.Contains(new, "127.0.0.21") {
		t.Fatalf("v2 www A should have two addresses:\n%s", new)
	}
	if !strings.Contains(new, "version 2") || !strings.Contains(new, "currently serving version") {
		t.Fatalf("header must identify the queried and serving versions:\n%s", new)
	}
}

func TestRenderNXDOMAINVsNODATA(t *testing.T) {
	nx := render(t, mustSnap(t, 1, zoneV1), "nonexistent.lab.test.", dns.TypeA)
	if !strings.Contains(nx, "NXDOMAIN") || !strings.Contains(nx, "does not exist") {
		t.Fatalf("missing name must render NXDOMAIN:\n%s", nx)
	}
	if !strings.Contains(nx, "negative-answer SOA TTL: 300") {
		t.Fatalf("NXDOMAIN must show negative TTL:\n%s", nx)
	}

	nd := render(t, mustSnap(t, 1, zoneV1), "www.lab.test.", dns.TypeMX)
	if !strings.Contains(nd, "NODATA") || strings.Contains(nd, "NXDOMAIN") {
		t.Fatalf("existing name missing a type must render NODATA, not NXDOMAIN:\n%s", nd)
	}
	if !strings.Contains(nd, "status: NOERROR") || !strings.Contains(nd, "AUTHORITY SECTION") {
		t.Fatalf("NODATA must be NOERROR with SOA authority:\n%s", nd)
	}
}

func TestRenderCNAMEFollowed(t *testing.T) {
	out := render(t, mustSnap(t, 1, zoneV1), "alias.lab.test.", dns.TypeA)
	if !strings.Contains(out, "CNAME") ||
		!strings.Contains(out, "alias.lab.test. -> www.lab.test.") {
		t.Fatalf("in-zone CNAME chain should be explained:\n%s", out)
	}
}

func TestRenderCNAMELeavesZone(t *testing.T) {
	out := render(t, mustSnap(t, 1, zoneV1), "out.lab.test.", dns.TypeA)
	if !strings.Contains(out, "leaves the zone") ||
		!strings.Contains(out, "elsewhere.example.net") ||
		!strings.Contains(out, "ra=0") {
		t.Fatalf("out-of-zone CNAME target must explain the stop:\n%s", out)
	}
}

func TestRenderOutOfZoneRefused(t *testing.T) {
	snap := mustSnap(t, 1, zoneV1)
	req := new(dns.Msg)
	req.SetQuestion("evil.example.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeRefused)
	var b bytes.Buffer
	Render(&b, resp, snap, VersionDetail{Serial: 1, CurrentSerial: 1})
	out := b.String()
	if !strings.Contains(out, "status: REFUSED") ||
		!strings.Contains(out, "outside zone lab.test") ||
		strings.Contains(out, "aa ") {
		t.Fatalf("out-of-zone output must match REFUSED/AA=0 semantics:\n%s", out)
	}
}
