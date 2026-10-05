package zone

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

const validZone = `$ORIGIN lab.test.
$TTL 3600
@ IN SOA ns1.lab.test. admin.lab.test. (1 7200 3600 1209600 300)
@ IN NS ns1.lab.test.
ns1 IN A 127.0.0.10
@ IN A 127.0.0.5
www IN A 127.0.0.20
www IN A 127.0.0.21
www IN TXT "hello"
alias IN CNAME www.lab.test.
*.wild IN A 127.0.0.99
`

func mustParse(t *testing.T, text string, lim Limits) []dns.RR {
	t.Helper()
	rrs, err := Parse(strings.NewReader(text), "lab.test.", lim)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return rrs
}

func TestParseValid(t *testing.T) {
	rrs := mustParse(t, validZone, Limits{MinTTL: 30, MaxTTL: 86400})
	snap, err := NewSnapshot("lab.test.", 42, rrs)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if got := snap.SOA().Serial; got != 42 {
		t.Fatalf("SOA serial = %d, want 42 (publisher must rewrite it)", got)
	}
}

func TestTTLBounds(t *testing.T) {
	lim := Limits{MinTTL: 30, MaxTTL: 86400}
	cases := map[string]string{
		"below min": `low 29 IN A 127.0.0.1`,
		"above max": `high 90000 IN A 127.0.0.1`,
	}
	for name, rec := range cases {
		t.Run(name, func(t *testing.T) {
			text := strings.Replace(validZone, "*.wild IN A 127.0.0.99\n",
				rec+"\n", 1)
			if _, err := Parse(strings.NewReader(text), "lab.test.", lim); err == nil {
				t.Fatalf("%s: expected TTL rejection", name)
			}
		})
	}
	t.Run("exact bounds accepted", func(t *testing.T) {
		text := strings.Replace(validZone, "*.wild IN A 127.0.0.99\n",
			"lo 30 IN A 127.0.0.1\nhi 86400 IN A 127.0.0.2\n", 1)
		if _, err := Parse(strings.NewReader(text), "lab.test.", lim); err != nil {
			t.Fatalf("boundary TTLs rejected: %v", err)
		}
	})
}

func TestRejectCNAMEConflict(t *testing.T) {
	base := strings.Replace(validZone, "*.wild IN A 127.0.0.99\n", "", 1)
	cases := map[string]string{
		"coexists with A": base + "h IN A 127.0.0.7\nh IN CNAME x.lab.test.\n",
		"two CNAMEs":      base + "h IN CNAME a.lab.test.\nh IN CNAME b.lab.test.\n",
		"CNAME at apex":   "@ IN CNAME elsewhere.example.net.\n",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(text), "lab.test.",
				Limits{MinTTL: 30, MaxTTL: 86400}); err == nil {
				t.Fatalf("%s: expected conflict rejection", name)
			}
		})
	}
}

func TestRejectOutOfZoneAndTypes(t *testing.T) {
	base := strings.Replace(validZone, "*.wild IN A 127.0.0.99\n", "", 1)
	cases := map[string]string{
		"out of zone owner": base + "h.other.test. IN A 1.2.3.4\n",
		"unsupported type":  base + "h IN DNSKEY 256 3 8 AAAA\n",
		"class CH":          base + "h 3600 CH TXT \"x\"\n",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(text), "lab.test.",
				Limits{MinTTL: 30, MaxTTL: 86400}); err == nil {
				t.Fatalf("%s: expected rejection", name)
			}
		})
	}
}

func TestLookupMultiRecord(t *testing.T) {
	rrs := mustParse(t, validZone, Limits{MinTTL: 30, MaxTTL: 86400})
	snap, _ := NewSnapshot("lab.test.", 1, rrs)
	as, found := snap.Lookup("www.lab.test.", dns.TypeA)
	if !found || len(as) != 2 {
		t.Fatalf("www A: found=%v n=%d, want 2 A records", found, len(as))
	}
	txts, _ := snap.Lookup("WWW.LAB.TEST.", dns.TypeTXT)
	if len(txts) != 1 {
		t.Fatalf("case-insensitive www TXT: got %d", len(txts))
	}
	// NODATA: name exists, wrong type. found stays true but no answers.
	if any, found := snap.Lookup("www.lab.test.", dns.TypeAAAA); !found || len(any) != 0 {
		t.Fatalf("www AAAA must be NODATA (found=true, 0 answers), got found=%v n=%d", found, len(any))
	}
	// NXDOMAIN: name absent.
	if _, found := snap.Lookup("missing.lab.test.", dns.TypeA); found {
		t.Fatal("missing name must report not found")
	}
}

func TestLookupCNAMEChain(t *testing.T) {
	rrs := mustParse(t, validZone, Limits{MinTTL: 30, MaxTTL: 86400})
	snap, _ := NewSnapshot("lab.test.", 1, rrs)
	ans, found := snap.Lookup("alias.lab.test.", dns.TypeA)
	if !found || len(ans) != 3 {
		t.Fatalf("alias A: found=%v n=%d, want CNAME+2A", found, len(ans))
	}
	if ans[0].Header().Rrtype != dns.TypeCNAME {
		t.Fatal("first answer must be the CNAME")
	}
	// Explicit CNAME query returns just the CNAME.
	cs, _ := snap.Lookup("alias.lab.test.", dns.TypeCNAME)
	if len(cs) != 1 {
		t.Fatalf("CNAME query returned %d", len(cs))
	}
}

func TestLookupWildcard(t *testing.T) {
	rrs := mustParse(t, validZone, Limits{MinTTL: 30, MaxTTL: 86400})
	snap, _ := NewSnapshot("lab.test.", 1, rrs)
	ans, found := snap.Lookup("anything.wild.lab.test.", dns.TypeA)
	if !found || len(ans) != 1 || ans[0].Header().Name != "anything.wild.lab.test." {
		t.Fatalf("wildcard expansion wrong: found=%v ans=%v", found, ans)
	}
	if ans[0].(*dns.A).A.String() != "127.0.0.99" {
		t.Fatalf("wildcard rdata = %v", ans[0])
	}
}

func TestNegativeTTL(t *testing.T) {
	rrs := mustParse(t, validZone, Limits{MinTTL: 30, MaxTTL: 86400})
	snap, _ := NewSnapshot("lab.test.", 1, rrs)
	if got := snap.NegativeTTL(); got != 300 {
		t.Fatalf("negative TTL = %d, want min(SOA ttl 3600, minimum 300)=300", got)
	}
}

func TestDiffExcludesSOA(t *testing.T) {
	v1 := mustParse(t, validZone, Limits{MinTTL: 30, MaxTTL: 86400})
	s1, _ := NewSnapshot("lab.test.", 1, v1)
	v2text := strings.Replace(validZone,
		"www IN A 127.0.0.21\n",
		"www IN A 127.0.0.21\nwww IN A 127.0.0.22\n", 1)
	v2 := mustParse(t, v2text, Limits{MinTTL: 30, MaxTTL: 86400})
	s2, _ := NewSnapshot("lab.test.", 2, v2)
	changes := Diff(s1, s2)
	var n int
	for _, c := range changes {
		if c.RR.Header().Rrtype == dns.TypeSOA {
			t.Fatal("SOA must not appear in changelog deltas")
		}
		n++
	}
	if n != 1 {
		var b strings.Builder
		for _, c := range changes {
			b.WriteString(c.Action + " " + CanonicalText(c.RR) + "\n")
		}
		t.Fatalf("diff = %d changes, want 1 (only new A);\n%s", n, b.String())
	}
}

func TestResolveAuthoritativeAnswersAndNegatives(t *testing.T) {
	rrs := mustParse(t, validZone, Limits{MinTTL: 30, MaxTTL: 86400})
	snap, _ := NewSnapshot("lab.test.", 1, rrs)

	positive := snap.Resolve("www.lab.test.", dns.TypeA, dns.ClassINET)
	if positive.Rcode != dns.RcodeSuccess || !positive.Authoritative || len(positive.Answers) != 2 {
		t.Fatalf("positive result: %+v", positive)
	}
	if len(positive.Authority) != 0 || positive.RecursionAvailable {
		t.Fatalf("positive answer must have no authority and RA=false: %+v", positive)
	}

	nodata := snap.Resolve("www.lab.test.", dns.TypeAAAA, dns.ClassINET)
	if nodata.Rcode != dns.RcodeSuccess || !nodata.NameExists || len(nodata.Answers) != 0 {
		t.Fatalf("NODATA result: %+v", nodata)
	}
	if len(nodata.Authority) != 1 || nodata.Authority[0].(*dns.SOA).Hdr.Ttl != 300 {
		t.Fatalf("NODATA needs SOA authority with TTL 300: %+v", nodata.Authority)
	}

	nxdomain := snap.Resolve("missing.lab.test.", dns.TypeA, dns.ClassINET)
	if nxdomain.Rcode != dns.RcodeNameError || nxdomain.NameExists || len(nxdomain.Answers) != 0 {
		t.Fatalf("NXDOMAIN result: %+v", nxdomain)
	}
	if len(nxdomain.Authority) != 1 || nxdomain.Authority[0].(*dns.SOA).Hdr.Ttl != 300 {
		t.Fatalf("NXDOMAIN needs SOA authority with TTL 300: %+v", nxdomain.Authority)
	}

	refused := snap.Resolve("example.com.", dns.TypeA, dns.ClassINET)
	if refused.Rcode != dns.RcodeRefused || refused.Authoritative || len(refused.Authority) != 0 {
		t.Fatalf("out-of-zone result must match online REFUSED: %+v", refused)
	}

	classRefused := snap.Resolve("www.lab.test.", dns.TypeA, dns.ClassCHAOS)
	if classRefused.Rcode != dns.RcodeRefused || classRefused.Authoritative {
		t.Fatalf("non-IN class result: %+v", classRefused)
	}
}

func TestResolveCNAMETrace(t *testing.T) {
	rrs := mustParse(t, validZone, Limits{MinTTL: 30, MaxTTL: 86400})
	snap, _ := NewSnapshot("lab.test.", 1, rrs)

	result := snap.Resolve("alias.lab.test.", dns.TypeA, dns.ClassINET)
	if result.Rcode != dns.RcodeSuccess || len(result.Answers) != 3 {
		t.Fatalf("internal CNAME answer: %+v", result)
	}
	if len(result.Trace.CNAMEHops) != 1 || !result.Trace.CNAMEHops[0].Followed {
		t.Fatalf("internal CNAME hop not recorded as followed: %+v", result.Trace.CNAMEHops)
	}
	if result.Trace.FinalName != "www.lab.test." {
		t.Fatalf("final name = %q", result.Trace.FinalName)
	}

	direct := snap.Resolve("alias.lab.test.", dns.TypeCNAME, dns.ClassINET)
	if len(direct.Answers) != 1 || len(direct.Trace.CNAMEHops) != 0 {
		t.Fatalf("direct CNAME query must return CNAME without chasing: %+v", direct.Trace)
	}

	externalText := strings.Replace(validZone,
		"alias IN CNAME www.lab.test.",
		"external IN CNAME target.example.net.", 1)
	externalRRs := mustParse(t, externalText, Limits{MinTTL: 30, MaxTTL: 86400})
	externalSnap, _ := NewSnapshot("lab.test.", 2, externalRRs)
	external := externalSnap.Resolve("external.lab.test.", dns.TypeA, dns.ClassINET)
	if external.Rcode != dns.RcodeSuccess || len(external.Answers) != 1 {
		t.Fatalf("external CNAME answer: %+v", external)
	}
	if len(external.Trace.CNAMEHops) != 1 || external.Trace.CNAMEHops[0].Followed {
		t.Fatalf("external CNAME must be returned and not followed: %+v", external.Trace.CNAMEHops)
	}
	if external.Trace.Stopped != "target outside zone" {
		t.Fatalf("stop reason = %q", external.Trace.Stopped)
	}
}

func TestResolveCNAMELoop(t *testing.T) {
	text := strings.Replace(validZone,
		"alias IN CNAME www.lab.test.",
		"loop1 IN CNAME loop2.lab.test.\nloop2 IN CNAME loop1.lab.test.", 1)
	rrs := mustParse(t, text, Limits{MinTTL: 30, MaxTTL: 86400})
	snap, _ := NewSnapshot("lab.test.", 1, rrs)

	result := snap.Resolve("loop1.lab.test.", dns.TypeA, dns.ClassINET)
	if result.Rcode != dns.RcodeSuccess || len(result.Answers) != 2 {
		t.Fatalf("CNAME loop result: %+v", result)
	}
	if result.Trace.Stopped != "CNAME loop detected" {
		t.Fatalf("stop reason = %q, want loop", result.Trace.Stopped)
	}
}

func TestResolveCanDistinguishVersions(t *testing.T) {
	v1 := mustParse(t, validZone, Limits{MinTTL: 30, MaxTTL: 86400})
	s1, _ := NewSnapshot("lab.test.", 1, v1)
	v2Text := strings.Replace(validZone,
		`www IN TXT "hello"`,
		`www IN TXT "hello"
www IN A 127.0.0.22`, 1)
	v2 := mustParse(t, v2Text, Limits{MinTTL: 30, MaxTTL: 86400})
	s2, _ := NewSnapshot("lab.test.", 2, v2)

	r1 := s1.Resolve("www.lab.test.", dns.TypeA, dns.ClassINET)
	r2 := s2.Resolve("www.lab.test.", dns.TypeA, dns.ClassINET)
	if len(r1.Answers) != 2 || len(r2.Answers) != 3 {
		t.Fatalf("version answers old=%d new=%d, want 2 and 3", len(r1.Answers), len(r2.Answers))
	}
}

func TestAXFROrdering(t *testing.T) {
	rrs := mustParse(t, validZone, Limits{MinTTL: 30, MaxTTL: 86400})
	snap, _ := NewSnapshot("lab.test.", 1, rrs)
	if snap.RRs[0].Header().Rrtype != dns.TypeSOA {
		t.Fatal("AXFR must begin with SOA")
	}
	if snap.RRs[1].Header().Rrtype != dns.TypeNS {
		t.Fatalf("position 1 must be apex NS, got %v", snap.RRs[1])
	}
}
