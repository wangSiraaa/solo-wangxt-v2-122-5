package zone

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func replyFor(t *testing.T, text string, serial uint32, name string, qtype uint16) *dns.Msg {
	t.Helper()
	rrs := mustParse(t, text, Limits{MinTTL: 30, MaxTTL: 86400})
	snap, err := NewSnapshot("lab.test.", serial, rrs)
	if err != nil {
		t.Fatal(err)
	}
	q := dns.Question{Name: dns.Fqdn(name), Qtype: qtype, Qclass: dns.ClassINET}
	return snap.AuthoritativeReply(q)
}

func TestAuthoritativeReplyPositive(t *testing.T) {
	r := replyFor(t, validZone, 3, "www.lab.test.", dns.TypeA)
	if r.Rcode != dns.RcodeSuccess || !r.Authoritative || r.RecursionAvailable {
		t.Fatalf("www A: rcode=%s aa=%v ra=%v",
			dns.RcodeToString[r.Rcode], r.Authoritative, r.RecursionAvailable)
	}
	if len(r.Answer) != 2 || len(r.Ns) != 0 {
		t.Fatalf("www A: answers=%d authority=%d, want 2/0", len(r.Answer), len(r.Ns))
	}
}

func TestAuthoritativeReplyCNAMEChain(t *testing.T) {
	r := replyFor(t, validZone, 3, "alias.lab.test.", dns.TypeA)
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 3 {
		t.Fatalf("alias A: rcode=%s answers=%d", dns.RcodeToString[r.Rcode], len(r.Answer))
	}
	if r.Answer[0].Header().Rrtype != dns.TypeCNAME {
		t.Fatal("first answer must be the CNAME from Lookup")
	}
	if len(r.Ns) != 0 {
		t.Fatalf("successful chase must carry no authority SOA, got %d", len(r.Ns))
	}
}

func TestAuthoritativeReplyNXDOMAIN(t *testing.T) {
	r := replyFor(t, validZone, 3, "missing.lab.test.", dns.TypeA)
	if r.Rcode != dns.RcodeNameError || len(r.Answer) != 0 || len(r.Ns) != 1 {
		t.Fatalf("NXDOMAIN: rcode=%s answers=%d ns=%d",
			dns.RcodeToString[r.Rcode], len(r.Answer), len(r.Ns))
	}
	soa, ok := r.Ns[0].(*dns.SOA)
	if !ok {
		t.Fatal("authority must be the SOA")
	}
	if soa.Hdr.Ttl != 300 {
		t.Fatalf("negative SOA TTL=%d, want min(3600,300)=300", soa.Hdr.Ttl)
	}
}

func TestAuthoritativeReplyNODATA(t *testing.T) {
	// www exists with A and TXT; an MX query is NODATA (NOERROR + SOA),
	// which must stay distinct from the NXDOMAIN above.
	r := replyFor(t, validZone, 3, "www.lab.test.", dns.TypeMX)
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 || len(r.Ns) != 1 {
		t.Fatalf("NODATA: rcode=%s answers=%d ns=%d",
			dns.RcodeToString[r.Rcode], len(r.Answer), len(r.Ns))
	}
}

func TestAuthoritativeReplyNegativeTTLIsMinOfFields(t *testing.T) {
	// SOA TTL 200 below the 300 minimum: negative TTL follows the SOA TTL.
	text := strings.Replace(validZone,
		"@ IN SOA ns1.lab.test. admin.lab.test. (1 7200 3600 1209600 300)",
		"@ 200 IN SOA ns1.lab.test. admin.lab.test. (1 7200 3600 1209600 300)", 1)
	r := replyFor(t, text, 1, "missing.lab.test.", dns.TypeA)
	if got := r.Ns[0].(*dns.SOA).Hdr.Ttl; got != 200 {
		t.Fatalf("negative TTL=%d, want 200", got)
	}
}
