package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"localtest/dnszone/internal/zone"
)

func testSnapshotForQuery(t *testing.T, serial uint32) *zone.Snapshot {
	t.Helper()
	text := `$ORIGIN lab.test.
$TTL 3600
@ IN SOA ns1.lab.test. admin.lab.test. (1 7200 3600 1209600 300)
@ IN NS ns1.lab.test.
www IN A 127.0.0.20
www IN TXT "present"
alias IN CNAME www.lab.test.
external IN CNAME target.example.net.
`
	rrs, err := zone.Parse(strings.NewReader(text), "lab.test.",
		zone.Limits{MinTTL: 30, MaxTTL: 86400})
	if err != nil {
		t.Fatal(err)
	}
	snap, err := zone.NewSnapshot("lab.test.", serial, rrs)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func TestParseQueryType(t *testing.T) {
	cases := map[string]uint16{
		"A":      dns.TypeA,
		"aaaa":   dns.TypeAAAA,
		"ANY":    dns.TypeANY,
		"255":    dns.TypeANY,
		"TYPE99": 99,
	}
	for in, want := range cases {
		got, err := parseQueryType(in)
		if err != nil || got != want {
			t.Fatalf("parseQueryType(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	if _, err := parseQueryType("not-a-type"); err == nil {
		t.Fatal("invalid query type must be rejected")
	}
}

func TestQualifyName(t *testing.T) {
	cases := map[string]string{
		"@":             "lab.test.",
		"www":           "www.lab.test.",
		"www.lab.test":  "www.lab.test.",
		"WWW.LAB.TEST.": "www.lab.test.",
		"example.com.":  "example.com.",
	}
	for in, want := range cases {
		if got := qualifyName(in, "lab.test."); got != want {
			t.Fatalf("qualifyName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRenderOfflineQueryAnswerCNAMEAndNegative(t *testing.T) {
	snap := testSnapshotForQuery(t, 3)
	cases := []struct {
		name  string
		qname string
		qtype uint16
		want  []string
	}{
		{
			name:  "answer",
			qname: "www.lab.test.",
			qtype: dns.TypeA,
			want: []string{
				"status: ANSWER",
				"response code: NOERROR",
				"www.lab.test. 3600 IN A 127.0.0.20",
				"authoritative: yes",
				"recursion available: no",
			},
		},
		{
			name:  "nodata",
			qname: "www.lab.test.",
			qtype: dns.TypeMX,
			want: []string{
				"status: NODATA",
				"response code: NOERROR",
				"authority:",
				"negative SOA TTL: 300",
			},
		},
		{
			name:  "nxdomain",
			qname: "missing.lab.test.",
			qtype: dns.TypeA,
			want: []string{
				"status: NXDOMAIN",
				"response code: NXDOMAIN",
				"authority:",
				"negative SOA TTL: 300",
			},
		},
		{
			name:  "internal cname",
			qname: "alias.lab.test.",
			qtype: dns.TypeA,
			want: []string{
				"CNAME chase:",
				"alias.lab.test. -> www.lab.test.: followed inside authoritative zone",
			},
		},
		{
			name:  "external cname",
			qname: "external.lab.test.",
			qtype: dns.TypeA,
			want: []string{
				"CNAME chase:",
				"external.lab.test. -> target.example.net.: not followed (target outside zone; no recursion is performed)",
				"CNAME result: target outside zone",
			},
		},
		{
			name:  "out of zone",
			qname: "example.com.",
			qtype: dns.TypeA,
			want: []string{
				"status: REFUSED",
				"response code: REFUSED",
				"authoritative: no",
				"explanation: example.com. is outside authoritative zone lab.test.; online service returns REFUSED with RA=0",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			result := snap.Resolve(tc.qname, tc.qtype, dns.ClassINET)
			renderOfflineQuery(&buf, snap, tc.qname, tc.qtype, result)
			out := buf.String()
			for _, want := range tc.want {
				if !strings.Contains(out, want) {
					t.Fatalf("output missing %q:\n%s", want, out)
				}
			}
		})
	}
}
