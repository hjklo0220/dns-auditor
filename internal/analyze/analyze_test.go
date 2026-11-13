package analyze

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/hjklo0220/dns-auditor/internal/inventory"
	"github.com/hjklo0220/dns-auditor/internal/report"
)

// Each case directory holds:
//
//	*.log          CoreDNS log input
//	snapshot.json  kubectl get namespaces,services,pods -A -o json
//	expected.json  the expected report, produced independently of this code
//	               (by the synthetic generator, or by hand for real captures)
//
// Public cases live in testdata/. Private cases (real cluster captures, never
// committed) are read from $DNS_AUDITOR_PRIVATE/cases when it is set.

func TestGoldenPublic(t *testing.T) {
	runCases(t, filepath.Join("..", "..", "testdata"))
}

func TestGoldenPrivate(t *testing.T) {
	root := os.Getenv("DNS_AUDITOR_PRIVATE")
	if root == "" {
		t.Skip("DNS_AUDITOR_PRIVATE not set")
	}
	dir := filepath.Join(root, "cases")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("no private cases: %v", err)
	}
	runCases(t, dir)
}

func runCases(t *testing.T, root string) {
	t.Helper()
	expected, err := filepath.Glob(filepath.Join(root, "*", "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(expected) == 0 {
		t.Fatalf("no cases under %s", root)
	}
	for _, exp := range expected {
		dir := filepath.Dir(exp)
		t.Run(filepath.Base(dir), func(t *testing.T) { runCase(t, dir) })
	}
}

func runCase(t *testing.T, dir string) {
	inv := inventory.NewStatic()
	f, err := os.Open(filepath.Join(dir, "snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := inventory.LoadKubectlJSON(f, inv); err != nil {
		t.Fatal(err)
	}
	logs, err := filepath.Glob(filepath.Join(dir, "*.log"))
	if err != nil || len(logs) == 0 {
		t.Fatalf("no logs in %s", dir)
	}
	var readers []io.Reader
	for _, p := range logs {
		lf, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		defer lf.Close()
		readers = append(readers, lf)
	}
	got, err := Run(readers, inv, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var want report.Report
	raw, err := os.ReadFile(filepath.Join(dir, "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Summary, want.Summary) {
		t.Errorf("summary\n got  %+v\n want %+v", got.Summary, want.Summary)
	}
	if !reflect.DeepEqual(normalize(got.Findings), normalize(want.Findings)) {
		g, _ := json.MarshalIndent(got.Findings, "", "  ")
		w, _ := json.MarshalIndent(want.Findings, "", "  ")
		t.Errorf("findings\n got  %s\n want %s", g, w)
	}
	t.Logf("%s: %d lines, %d findings, categories %v", filepath.Base(dir), got.Summary.Lines, len(got.Findings), got.Summary.Categories)
}

// normalize makes nil and empty slices compare equal.
func normalize(rows []report.Row) []report.Row {
	if len(rows) == 0 {
		return nil
	}
	return rows
}
