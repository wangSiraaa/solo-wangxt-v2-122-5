// Package query implements the offline version query used by the
// `dnszone query` command. It renders exactly what the authoritative
// server would answer for a name/type against a persisted zone version,
// without sending any DNS traffic or changing the serving version.
//
// The answer itself is produced by zone.Snapshot.AuthoritativeReply — the
// same function the live UDP/TCP handler calls — so this code only adds
// argument parsing and a human-readable rendering of that reply.
package query

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/miekg/dns"

	"localtest/dnszone/internal/zone"
)

// VersionDetail identifies which persisted snapshot is being shown and
// which version the live service is currently serving.
type VersionDetail struct {
	Serial        uint32
	Note          string
	PublishedAt   time.Time
	CurrentSerial uint32
}

// ParseType converts a CLI type argument (A, aaaa, MX, ANY, or a numeric
// type) into a wire qtype. Zone-transfer opcodes are rejected: they are
// not answerable through the offline lookup path.
func ParseType(s string) (uint16, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty query type")
	}
	if strings.EqualFold(s, "ANY") {
		return dns.TypeANY, nil
	}
	if t, ok := dns.StringToType[strings.ToUpper(s)]; ok {
		switch t {
		case dns.TypeAXFR, dns.TypeIXFR:
			return 0, fmt.Errorf("%s is a zone-transfer operation, not a name query; "+
				"use the TSIG-gated TCP transfer path instead", strings.ToUpper(s))
		}
		return t, nil
	}
	if n, err := strconv.ParseUint(s, 10, 16); err == nil {
		// Arbitrary numeric qtypes are accepted exactly as they are on the
		// wire: the type allow-list only gates publishing, not queries.
		return uint16(n), nil
	}
	return 0, fmt.Errorf("unknown DNS record type %q", s)
}

// QualifyName normalizes a CLI name argument to a lowercase FQDN. A
// trailing dot is honored; a dotless name that already sits under the
// origin (e.g. "www.lab.test") is taken as written; any other dotless
// name is taken relative to the zone origin (like a zone-file owner),
// and "@" names the apex. Use a trailing dot to name something outside
// the zone, e.g. "example.com.".
func QualifyName(name, origin string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	switch {
	case name == "":
		return ""
	case name == "@":
		return dns.Fqdn(origin)
	case dns.IsFqdn(name):
		return dns.CanonicalName(name)
	case dns.IsSubDomain(origin, dns.Fqdn(name)):
		return dns.CanonicalName(name)
	default:
		return dns.CanonicalName(name + "." + origin)
	}
}

// Render writes a dig-style explanation of resp, which must have been
// produced by snap.AuthoritativeReply (or be the out-of-zone REFUSED the
// server would send). Output is deterministic and goes to w.
func Render(w io.Writer, resp *dns.Msg, snap *zone.Snapshot, d VersionDetail) {
	q := resp.Question[0]
	typeName := dns.TypeToString[q.Qtype]

	fmt.Fprintf(w, ";; offline snapshot query: version %d", d.Serial)
	if d.Note != "" {
		fmt.Fprintf(w, " (%q)", d.Note)
	}
	if !d.PublishedAt.IsZero() {
		fmt.Fprintf(w, ", published %s", d.PublishedAt.Format("2006-01-02 15:04:05 MST"))
	}
	switch {
	case d.CurrentSerial == 0:
		fmt.Fprint(w, "; no version is currently being served\n")
	case d.Serial == d.CurrentSerial:
		fmt.Fprintf(w, "; this is the currently serving version\n")
	default:
		fmt.Fprintf(w, "; the live service is serving version %d (unchanged by this query)\n",
			d.CurrentSerial)
	}

	fmt.Fprintln(w, ";; QUESTION SECTION:")
	fmt.Fprintf(w, ";%s\t\tIN\t%s\n", q.Name, typeName)

	fmt.Fprintf(w, ";; -> status: %s, flags: %s\n",
		dns.RcodeToString[resp.Rcode], flagList(resp))

	switch resp.Rcode {
	case dns.RcodeRefused:
		fmt.Fprintf(w, ";;    %s is outside zone %s: the live server answers REFUSED with "+
			"AA=0/RA=0 and never recurses or sends a network request\n",
			q.Name, snap.Origin)
	case dns.RcodeNameError:
		fmt.Fprintln(w, ";;    NXDOMAIN: the name does not exist in this version")
	case dns.RcodeSuccess:
		if len(resp.Answer) == 0 {
			fmt.Fprintf(w, ";;    NODATA: the name exists in this version but has no %s records\n",
				typeName)
		} else {
			fmt.Fprintf(w, ";;    %d answer record(s)\n", len(resp.Answer))
		}
	}

	if len(resp.Answer) > 0 {
		fmt.Fprintln(w, ";; ANSWER SECTION:")
		printRRs(w, resp.Answer)
		writeCNAMENote(w, resp, snap)
	}
	if len(resp.Ns) > 0 {
		fmt.Fprintln(w, ";; AUTHORITY SECTION:")
		printRRs(w, resp.Ns)
		if soa, ok := resp.Ns[0].(*dns.SOA); ok && resp.Rcode != dns.RcodeRefused {
			fmt.Fprintf(w, ";; negative-answer SOA TTL: %d = min(SOA TTL %d, SOA MINIMUM %d) per RFC 2308\n",
				soa.Hdr.Ttl, snap.SOA().Hdr.Ttl, soa.Minttl)
		}
	}
	if len(resp.Extra) > 0 {
		fmt.Fprintln(w, ";; ADDITIONAL SECTION:")
		printRRs(w, resp.Extra)
	}

	fmt.Fprintln(w, ";; read from the persisted snapshot only; no network DNS requests were sent")
}

func flagList(resp *dns.Msg) string {
	var flags []string
	flags = append(flags, "qr")
	if resp.Authoritative {
		flags = append(flags, "aa")
	}
	// RA is always absent: this is an authoritative-only non-recursing
	// service; render it explicitly so the offline report states it.
	if resp.RecursionAvailable {
		flags = append(flags, "ra")
	} else {
		flags = append(flags, "ra=0")
	}
	return strings.Join(flags, " ")
}

func printRRs(w io.Writer, rrs []dns.RR) {
	tw := tabwriter.NewWriter(w, 0, 4, 1, ' ', 0)
	for _, rr := range rrs {
		fmt.Fprintln(tw, rr.String())
	}
	tw.Flush()
}

// writeCNAMENote explains how the CNAME chain in the answer was chased:
// in-zone to terminal records, in-zone to a negative/loop end, or out of
// zone where the authoritative server must stop.
func writeCNAMENote(w io.Writer, resp *dns.Msg, snap *zone.Snapshot) {
	q := resp.Question[0]
	if q.Qtype == dns.TypeCNAME {
		// An explicit CNAME query returns the CNAME itself; no chase.
		return
	}
	var cnames []*dns.CNAME
	for _, rr := range resp.Answer {
		if c, ok := rr.(*dns.CNAME); ok {
			cnames = append(cnames, c)
		}
	}
	if len(cnames) == 0 {
		return
	}
	chain := []string{strings.ToLower(cnames[0].Hdr.Name)}
	for _, c := range cnames {
		chain = append(chain, strings.ToLower(c.Target))
	}
	lastTarget := chain[len(chain)-1]
	switch {
	case !dns.IsSubDomain(snap.Origin, lastTarget):
		fmt.Fprintf(w, ";; CNAME chain %s leaves the zone; the authoritative server stops here "+
			"(no recursion, RA=0) and returns the chain so far\n", strings.Join(chain, " -> "))
	case len(resp.Answer) == len(cnames):
		// Only CNAMEs came back: the in-zone target produced no record of
		// the requested type at this version (or a loop was cut), so the
		// live answer is NOERROR plus the chain, without an SOA.
		fmt.Fprintf(w, ";; CNAME chain %s stayed in-zone but yielded no %s records at the target in this version\n",
			strings.Join(chain, " -> "), dns.TypeToString[q.Qtype])
	default:
		fmt.Fprintf(w, ";; CNAME chain followed in-zone: %s\n", strings.Join(chain, " -> "))
	}
}
