// Package version exposes build metadata of the WAEaA collector.
//
// The variables are overridden at link time by the build scripts, e.g.:
//
//	go build -ldflags "-X github.com/Cybsquatch/WAEaA/collector/internal/version.Version=1.0.0"
//
// The values end up in the collection log and in the chain-of-custody record,
// so that every evidence archive can be traced back to the exact binary that
// produced it.
package version

import (
	"fmt"
	"runtime"
)

var (
	// Version is the semantic version of the collector.
	Version = "0.1.0-dev"
	// Commit is the git commit hash the binary was built from.
	Commit = "unknown"
	// BuildDate is the UTC build timestamp in RFC 3339 format.
	BuildDate = "unknown"
	// Flavor distinguishes the "modern" build (latest Go, Win10+) from the
	// "legacy" build (Go 1.20, Win7+).
	Flavor = "modern"
)

// Name is the product name shown in logs, GUI and reports.
const Name = "WAEaA Collector"

// String returns a single human readable line describing the build,
// e.g. "WAEaA Collector 1.0.0 (modern, abc1234, 2026-10-22T10:00:00Z, go1.27 windows/amd64)".
func String() string {
	return fmt.Sprintf("%s %s (%s, %s, %s, %s %s/%s)",
		Name, Version, Flavor, Commit, BuildDate,
		runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
