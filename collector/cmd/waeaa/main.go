// Command waeaa is the WAEaA forensic artefact collector.
//
// Run without arguments to open the interactive interface (GUI on Windows,
// terminal menu on Linux), or with arguments for command-line mode:
//
//	waeaa --help
package main

import (
	"os"

	"github.com/Cybsquatch/WAEaA/collector/internal/app"
)

func main() {
	os.Exit(app.Main(os.Args[1:], os.Stdout, os.Stderr))
}
