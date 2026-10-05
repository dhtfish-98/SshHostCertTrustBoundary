package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/dhtfish-98/SshHostCertTrustBoundary/hosttrust"
	"github.com/dhtfish-98/SshHostCertTrustBoundary/internal/loopback"
)

func main() {
	version := flag.Bool("version", false, "print the version")
	selfTest := flag.Bool("self-test", false, "run the real loopback SSH host-certificate lab")
	auditFile := flag.String("audit-file", "", "path to the owner-only JSONL decision log")
	flag.Parse()
	if *version {
		fmt.Println(hosttrust.Version)
		return
	}
	if !*selfTest {
		fmt.Fprintln(os.Stderr, "use --self-test --audit-file <path> or --version")
		os.Exit(2)
	}
	report, err := loopback.RunSelfTest(*auditFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
