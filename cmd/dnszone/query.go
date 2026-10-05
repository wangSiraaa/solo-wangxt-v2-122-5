package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"localtest/dnszone/internal/store"
	"localtest/dnszone/internal/zone"
)

// offlineQueryOptions holds the inputs to one read-only historical lookup.
type offlineQueryOptions struct {
	configPath string
	version    uint64
	name       string
	qtypeText  string
}

func registerOfflineQueryFlags(fs *flag.FlagSet) *offlineQueryOptions {
	opts := &offlineQueryOptions{}
	fs.StringVar(&opts.configPath, "config", "config.json", "path to config JSON")
	fs.Uint64Var(&opts.version, "version", 0, "published zone serial/version to inspect")
	fs.StringVar(&opts.name, "name", "", "DNS owner name (relative names are completed with the configured zone)")
	fs.StringVar(&opts.qtypeText, "type", "A", "DNS query type (for example A, AAAA, MX, CNAME or 255 for ANY)")
	return opts
}

func runOfflineQuery(args []string) error {
	fs := flag.NewFlagSet("query", flag.ContinueOnError)
	opts := registerOfflineQueryFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if opts.version == 0 {
		return errors.New("required flag -version must identify a published serial")
	}
	if opts.version > math.MaxUint32 {
		return fmt.Errorf("version %d is larger than the maximum zone serial %d", opts.version, uint32(math.MaxUint32))
	}
	if strings.TrimSpace(opts.name) == "" {
		return errors.New("required flag -name must identify a DNS owner name")
	}
	cfg, err := loadConfig(opts.configPath)
	if err != nil {
		return err
	}
	qtype, err := parseQueryType(opts.qtypeText)
	if err != nil {
		return err
	}
	if qtype == dns.TypeAXFR || qtype == dns.TypeIXFR {
		return errors.New("offline query handles standard name/type lookups; use a TSIG-gated transfer for AXFR/IXFR")
	}
	qname := qualifyName(opts.name, cfg.ZoneOrigin())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Read-only PostgreSQL access is the only I/O. This process does not
	// open DNS sockets and never updates zone_meta, so serving is unaffected.
	st, err := store.OpenReadOnly(ctx, cfg.DatabaseURL, cfg.ZoneOrigin())
	if err != nil {
		return fmt.Errorf("postgres read-only: %w", err)
	}
	defer st.Close()

	snap, err := st.LoadSnapshot(ctx, uint32(opts.version))
	if err != nil {
		if errors.Is(err, store.ErrNoVersion) {
			current, curErr := st.CurrentSerial(ctx)
			if curErr != nil {
				return err
			}
			if current == 0 {
				return fmt.Errorf("%w (no versions have been published yet)", err)
			}
			return fmt.Errorf("%w (current served version is %d; it is not changed by this command)", err, current)
		}
		return err
	}

	result := snap.Resolve(qname, qtype, dns.ClassINET)
	renderOfflineQuery(os.Stdout, snap, qname, qtype, result)
	return nil
}

func parseQueryType(text string) (uint16, error) {
	t := strings.ToUpper(strings.TrimSpace(text))
	if t == "ANY" {
		return dns.TypeANY, nil
	}
	if code, ok := dns.StringToType[t]; ok {
		return code, nil
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(t, "TYPE"), 10, 16)
	if err != nil {
		return 0, fmt.Errorf("unknown DNS query type %q", text)
	}
	return uint16(n), nil
}

func queryTypeName(qtype uint16) string {
	if name, ok := dns.TypeToString[qtype]; ok {
		return name
	}
	return fmt.Sprintf("TYPE%d", qtype)
}

func qualifyName(name, origin string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "@" {
		return origin
	}
	if dns.IsFqdn(name) || dns.IsSubDomain(origin, dns.Fqdn(name)) {
		return dns.Fqdn(name)
	}
	return dns.Fqdn(name + "." + origin)
}

func renderOfflineQuery(w io.Writer, snap *zone.Snapshot, qname string, qtype uint16, result zone.QueryResult) {
	fmt.Fprintf(w, "offline query: version %d of %s\n", snap.Serial, snap.Origin)
	fmt.Fprintf(w, "question: %s IN %s\n", qname, queryTypeName(qtype))
	fmt.Fprintf(w, "status: %s\n", offlineStatus(result))
	fmt.Fprintf(w, "response code: %s\n", dns.RcodeToString[result.Rcode])
	fmt.Fprintf(w, "authoritative: %s\n", yesNo(result.Authoritative))
	fmt.Fprintf(w, "recursion available: %s\n", yesNo(result.RecursionAvailable))

	if len(result.Answers) > 0 {
		fmt.Fprintln(w, "answers:")
		for _, rr := range result.Answers {
			fmt.Fprintf(w, "  %s\n", zone.CanonicalText(rr))
		}
	}
	if hops := result.Trace.CNAMEHops; len(hops) > 0 {
		fmt.Fprintln(w, "CNAME chase:")
		for _, hop := range hops {
			if hop.Followed {
				fmt.Fprintf(w, "  %s -> %s: followed inside authoritative zone\n", hop.From, hop.To)
			} else {
				fmt.Fprintf(w, "  %s -> %s: not followed (target outside zone; no recursion is performed)\n", hop.From, hop.To)
			}
		}
	}
	if result.Trace.Stopped != "" {
		fmt.Fprintf(w, "CNAME result: %s\n", result.Trace.Stopped)
	}

	if len(result.Authority) > 0 {
		fmt.Fprintln(w, "authority:")
		for _, rr := range result.Authority {
			fmt.Fprintf(w, "  %s\n", zone.CanonicalText(rr))
		}
		if soa, ok := result.Authority[0].(*dns.SOA); ok {
			fmt.Fprintf(w, "negative SOA TTL: %d\n", soa.Hdr.Ttl)
		}
	}
	if result.Rcode == dns.RcodeRefused {
		fmt.Fprintf(w, "explanation: %s is outside authoritative zone %s; online service returns REFUSED with RA=0\n",
			qname, snap.Origin)
	}
}

func offlineStatus(result zone.QueryResult) string {
	switch {
	case result.Rcode == dns.RcodeNameError:
		return "NXDOMAIN"
	case result.Rcode == dns.RcodeRefused:
		return "REFUSED"
	case len(result.Answers) == 0:
		return "NODATA"
	default:
		return "ANSWER"
	}
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
