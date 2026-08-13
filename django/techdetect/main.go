// techdetect is a thin CLI wrapper around wappalyzergo: it reads already-
// captured response headers/body as JSON from stdin and prints matched
// technologies (name + optional version) as JSON to stdout. It makes no
// network requests of its own — it only fingerprints data handed to it,
// so it's safe to run on every passively-captured flow.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

type input struct {
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

type match struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func main() {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read stdin:", err)
		os.Exit(1)
	}

	var in input
	if err := json.Unmarshal(raw, &in); err != nil {
		fmt.Fprintln(os.Stderr, "parse input json:", err)
		os.Exit(1)
	}

	headers := make(map[string][]string, len(in.Headers))
	for name, value := range in.Headers {
		headers[name] = []string{value}
	}

	client, err := wappalyzer.New()
	if err != nil {
		fmt.Fprintln(os.Stderr, "load fingerprints:", err)
		os.Exit(1)
	}

	fingerprints := client.Fingerprint(headers, []byte(in.Body))

	matches := make([]match, 0, len(fingerprints))
	for appVersion := range fingerprints {
		name, version, _ := strings.Cut(appVersion, ":")
		matches = append(matches, match{Name: name, Version: version})
	}

	if err := json.NewEncoder(os.Stdout).Encode(matches); err != nil {
		fmt.Fprintln(os.Stderr, "write output json:", err)
		os.Exit(1)
	}
}
