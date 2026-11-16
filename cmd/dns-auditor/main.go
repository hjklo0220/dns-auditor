// Command dns-auditor finds in-cluster calls that use a short Service name
// across namespaces (http://billing from namespace shop when billing lives in
// namespace payments) and suggests the fully qualified address.
//
// Usage:
//
//	dns-auditor serve   [-dnstap-addr :6000] [-http-addr :8080] [-kubeconfig path] ...
//	dns-auditor analyze -coredns-log coredns.log -snapshot snapshot.json [-format text|json]
//	dns-auditor version
//
// The snapshot is the output of:
//
//	kubectl get namespaces,services,pods -A -o json > snapshot.json
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/hjklo0220/dns-auditor/internal/analyze"
	"github.com/hjklo0220/dns-auditor/internal/inventory"
	"github.com/hjklo0220/dns-auditor/internal/report"
	"github.com/hjklo0220/dns-auditor/internal/rule"
)

var version = "dev"

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "dns-auditor:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: dns-auditor <serve|analyze|version> [flags]")
	}
	switch args[0] {
	case "serve":
		return cmdServe(args[1:])
	case "analyze":
		return cmdAnalyze(args[1:], out)
	case "version":
		_, err := fmt.Fprintln(out, version)
		return err
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func cmdAnalyze(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	var logs, snaps multiFlag
	fs.Var(&logs, "coredns-log", "CoreDNS log file (repeatable)")
	fs.Var(&snaps, "snapshot", "kubectl get namespaces,services,pods -A -o json output (repeatable)")
	domain := fs.String("cluster-domain", "cluster.local", "cluster DNS domain")
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(logs) == 0 || len(snaps) == 0 {
		return errors.New("analyze needs at least one -coredns-log and one -snapshot")
	}

	inv := inventory.NewStatic()
	for _, p := range snaps {
		if err := withFile(p, func(r io.Reader) error { return inventory.LoadKubectlJSON(r, inv) }); err != nil {
			return err
		}
	}
	var readers []io.Reader
	for _, p := range logs {
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		readers = append(readers, f)
	}
	rep, err := analyze.Run(readers, inv, analyze.Options{ClusterDomain: *domain})
	if err != nil {
		return err
	}
	switch *format {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	case "text":
		return writeText(out, rep)
	default:
		return fmt.Errorf("unknown format %q", *format)
	}
}

func withFile(path string, fn func(io.Reader) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := fn(f); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// writeText renders into a buffer (bytes.Buffer writes cannot fail) and
// writes it once, so the only error to check is the final write.
func writeText(out io.Writer, rep report.Report) error {
	var b bytes.Buffer
	s := rep.Summary
	fmt.Fprintf(&b, "lines %d, parsed %d, skipped %d\n", s.Lines, s.Parsed, s.Skipped)
	for _, c := range rule.Categories {
		fmt.Fprintf(&b, "  %-22s %d\n", c, s.Categories[c])
	}
	b.WriteString("\n")
	if len(rep.Findings) == 0 {
		b.WriteString("no misrouted short-name lookups found\n")
		_, err := out.Write(b.Bytes())
		return err
	}
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "COUNT\tCALLER\tLOOKED UP\tUSE INSTEAD")
	for _, r := range rep.Findings {
		caller := r.CallerWorkload
		if caller == report.UnknownWorkload {
			caller = r.CallerNamespace + "/? (" + strings.Join(r.CallerIPs, ",") + ")"
		}
		var use []string
		for _, sg := range r.Suggestions {
			use = append(use, sg.Host+portSuffix(sg.Ports))
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n", r.Count, caller, r.Name, strings.Join(use, " | "))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	_, err := out.Write(b.Bytes())
	return err
}

func portSuffix(ports []int32) string {
	switch len(ports) {
	case 0:
		return ""
	case 1:
		return fmt.Sprintf(":%d", ports[0])
	}
	ps := make([]string, len(ports))
	for i, p := range ports {
		ps[i] = fmt.Sprint(p)
	}
	return ":{" + strings.Join(ps, ",") + "}"
}
