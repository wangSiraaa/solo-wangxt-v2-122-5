// Command dnszone runs the local-only authoritative DNS zone service and
// publishes zone versions atomically into PostgreSQL.
//
// Usage:
//
//	dnszone serve   --config config.json
//	dnszone publish --config config.json --file zone.db [--note "..."]
//	dnszone versions --config config.json
//	dnszone query   --config config.json --version 3 --name www.lab.test. --type A
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/miekg/dns"

	"localtest/dnszone/internal/config"
	"localtest/dnszone/internal/query"
	"localtest/dnszone/internal/server"
	"localtest/dnszone/internal/store"
	"localtest/dnszone/internal/zone"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = runServe(args)
	case "publish":
		err = runPublish(args)
	case "versions":
		err = runVersions(args)
	case "query":
		err = runQuery(args)
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", cmd, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `dnszone - local test-domain authoritative DNS service

Commands:
  serve     run the authoritative UDP/TCP server
  publish   atomically publish a zone file as a new version
  versions  list published zone versions
  query     offline: show what a persisted version answers for a name/type

Run "<command> -h" for command flags.
`)
}

func loadConfig(path string) (*config.Config, error) {
	c, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.json", "path to config JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger := log.New(os.Stdout, "dnszone ", log.LstdFlags|log.Lmicroseconds)
	st, err := store.New(ctx, cfg.DatabaseURL, cfg.ZoneOrigin())
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer st.Close()

	srv, err := server.New(ctx, cfg, st, logger)
	if err != nil {
		return err
	}
	return srv.Run(ctx)
}

func runPublish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.json", "path to config JSON")
	file := fs.String("file", "zone.db", "RFC 1035 zone master file")
	note := fs.String("note", "", "change note stored with the version")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	f, err := os.Open(*file)
	if err != nil {
		return err
	}
	defer f.Close()

	lim := zone.Limits{MinTTL: cfg.TTLMin, MaxTTL: cfg.TTLMax}
	rrs, err := zone.Parse(f, cfg.ZoneOrigin(), lim)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	st, err := store.New(ctx, cfg.DatabaseURL, cfg.ZoneOrigin())
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer st.Close()

	res, err := st.Publish(ctx, rrs, *note, lim)
	if err != nil {
		return err
	}
	fmt.Printf("published serial %d (%d record changes)\n", res.Serial, len(res.Changes))
	for _, c := range res.Changes {
		fmt.Printf("  %s %s\n", c.Action, zone.CanonicalText(c.RR))
	}
	return nil
}

func runVersions(args []string) error {
	fs := flag.NewFlagSet("versions", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.json", "path to config JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, err := store.New(ctx, cfg.DatabaseURL, cfg.ZoneOrigin())
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer st.Close()
	vs, err := st.ListVersions(ctx, 100)
	if err != nil {
		return err
	}
	fmt.Printf("current zone: %s\n", cfg.ZoneOrigin())
	for _, v := range vs {
		fmt.Printf("  serial %d  %s  %q\n", v.Serial,
			v.PublishedAt.Format("2006-01-02 15:04:05 MST"), v.Note)
	}
	return nil
}

// runQuery answers one name/type question offline against a persisted
// version. It only reads PostgreSQL, constructs no DNS packets and never
// touches the live server's current-version pointer.
func runQuery(args []string) error {
	fs := flag.NewFlagSet("query", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.json", "path to config JSON")
	versionArg := fs.String("version", "", "zone serial to query (required; \"current\" uses the serving version)")
	nameArg := fs.String("name", "", "owner name, e.g. www.lab.test (required)")
	typeArg := fs.String("type", "A", "record type (A, AAAA, CNAME, MX, ..., ANY, or numeric)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *versionArg == "" {
		return errors.New("-version is required (use a serial or \"current\")")
	}
	if *nameArg == "" {
		return errors.New("-name is required")
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	qtype, err := query.ParseType(*typeArg)
	if err != nil {
		return err
	}
	qname := query.QualifyName(*nameArg, cfg.ZoneOrigin())
	if qname == "" {
		return errors.New("-name is required")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, err := store.New(ctx, cfg.DatabaseURL, cfg.ZoneOrigin())
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer st.Close()

	current, err := st.CurrentSerial(ctx)
	if err != nil {
		return err
	}
	var serial uint32
	switch *versionArg {
	case "current", "latest", "head":
		if current == 0 {
			return errors.New("no zone version has been published yet")
		}
		serial = current
	default:
		n, err := strconv.ParseUint(strings.TrimSpace(*versionArg), 10, 32)
		if err != nil || n == 0 {
			return fmt.Errorf("invalid -version %q: expected a positive serial or \"current\"",
				*versionArg)
		}
		serial = uint32(n)
	}

	snap, err := st.LoadSnapshot(ctx, serial)
	if err != nil {
		if errors.Is(err, store.ErrNoVersion) {
			return describeMissingVersion(ctx, st, serial, current)
		}
		return err
	}
	info, err := st.VersionInfo(ctx, serial)
	if err != nil {
		return err
	}
	detail := query.VersionDetail{
		Serial:        serial,
		Note:          info.Note,
		PublishedAt:   info.PublishedAt,
		CurrentSerial: current,
	}

	question := dns.Question{Name: qname, Qtype: qtype, Qclass: dns.ClassINET}
	var resp *dns.Msg
	if !dns.IsSubDomain(snap.Origin, qname) {
		// Mirror the live handler's out-of-zone gate exactly:
		// authoritative REFUSED, RA=0, no question chase.
		request := new(dns.Msg)
		request.SetQuestion(qname, qtype)
		resp = new(dns.Msg)
		resp.SetRcode(request, dns.RcodeRefused)
		resp.RecursionAvailable = false
		resp.Authoritative = false
	} else {
		resp = snap.AuthoritativeReply(question)
	}
	query.Render(os.Stdout, resp, snap, detail)
	return nil
}

// describeMissingVersion turns a nonexistent-version lookup into guidance
// consistent with what the database reports, instead of a bare error.
func describeMissingVersion(ctx context.Context, st *store.Store, requested, current uint32) error {
	vs, err := st.ListVersions(ctx, 100)
	if err != nil {
		return fmt.Errorf("version %d does not exist (and history could not be listed: %v)",
			requested, err)
	}
	if len(vs) == 0 {
		return fmt.Errorf("version %d does not exist; no zone version has been published yet",
			requested)
	}
	if current == 0 {
		current = vs[0].Serial // ListVersions is newest-first
	}
	var b strings.Builder
	fmt.Fprintf(&b, "version %d does not exist; the live service is serving version %d. Available versions:",
		requested, current)
	for _, v := range vs {
		fmt.Fprintf(&b, "\n  serial %d  %s  %q", v.Serial,
			v.PublishedAt.Format("2006-01-02 15:04:05 MST"), v.Note)
	}
	return errors.New(b.String())
}
