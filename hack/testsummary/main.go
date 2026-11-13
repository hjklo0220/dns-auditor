// Command testsummary reads `go test -json` from stdin, prints failures and a
// one-line summary, writes a machine-readable result file, and exits non-zero
// when any test failed. It is the "verdict" step of `make check`.
//
//	go test -json ./... | go run ./hack/testsummary -out docs/results/test-latest.json
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type testEvent struct {
	Action  string
	Package string
	Test    string
	Output  string
	Elapsed float64
}

type pkgResult struct {
	Pass, Fail, Skip int
	Coverage         string `json:",omitempty"`
}

type result struct {
	Time     time.Time             `json:"time"`
	Pass     int                   `json:"pass"`
	Fail     int                   `json:"fail"`
	Skip     int                   `json:"skip"`
	Failed   []string              `json:"failed,omitempty"`
	Skipped  []string              `json:"skipped,omitempty"`
	Packages map[string]*pkgResult `json:"packages"`
}

func main() {
	out := flag.String("out", "", "write JSON result here")
	flag.Parse()

	res := result{Time: time.Now().UTC(), Packages: map[string]*pkgResult{}}
	outputs := map[string][]string{} // pkg/test -> output lines, kept for failures
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		var ev testEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			fmt.Println(sc.Text()) // build errors are not JSON
			continue
		}
		p := res.Packages[ev.Package]
		if p == nil {
			p = &pkgResult{}
			res.Packages[ev.Package] = p
		}
		id := ev.Package + " " + ev.Test
		switch ev.Action {
		case "output":
			outputs[id] = append(outputs[id], ev.Output)
			if i := strings.Index(ev.Output, "coverage: "); i >= 0 && ev.Test == "" {
				p.Coverage = strings.Fields(ev.Output[i+len("coverage: "):])[0]
			}
		case "pass", "fail", "skip":
			if ev.Test == "" {
				if ev.Action == "fail" && p.Fail == 0 {
					res.Fail++ // package-level failure (build error, panic)
					res.Failed = append(res.Failed, ev.Package+" (package)")
					fmt.Print(strings.Join(outputs[id], ""))
				}
				continue
			}
			switch ev.Action {
			case "pass":
				p.Pass++
				res.Pass++
			case "fail":
				p.Fail++
				res.Fail++
				res.Failed = append(res.Failed, id)
				fmt.Print(strings.Join(outputs[id], ""))
			case "skip":
				p.Skip++
				res.Skip++
				res.Skipped = append(res.Skipped, id)
			}
		}
	}
	sort.Strings(res.Failed)
	sort.Strings(res.Skipped)

	pkgs := make([]string, 0, len(res.Packages))
	for k := range res.Packages {
		pkgs = append(pkgs, k)
	}
	sort.Strings(pkgs)
	for _, k := range pkgs {
		p := res.Packages[k]
		if p.Pass+p.Fail+p.Skip == 0 {
			continue
		}
		fmt.Printf("  %-55s pass %3d  fail %d  skip %d  %s\n", k, p.Pass, p.Fail, p.Skip, p.Coverage)
	}
	for _, s := range res.Skipped {
		fmt.Println("  skipped:", s)
	}
	fmt.Printf("tests: pass %d, fail %d, skip %d\n", res.Pass, res.Fail, res.Skip)

	if *out != "" {
		b, _ := json.MarshalIndent(res, "", "  ")
		if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if res.Fail > 0 {
		os.Exit(1)
	}
}
