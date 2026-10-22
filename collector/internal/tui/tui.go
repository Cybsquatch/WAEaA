// Package tui provides an interactive terminal user interface for headless
// Linux servers and interactive console environments.
package tui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Cybsquatch/WAEaA/collector/internal/cli"
	"github.com/Cybsquatch/WAEaA/collector/internal/distro"
	"github.com/Cybsquatch/WAEaA/collector/internal/engine"
	"github.com/Cybsquatch/WAEaA/collector/internal/i18n"
	"github.com/Cybsquatch/WAEaA/collector/internal/logging"
	"github.com/Cybsquatch/WAEaA/collector/internal/privilege"
	"github.com/Cybsquatch/WAEaA/collector/internal/version"
)

// Run starts the interactive terminal menu.
func Run(stdin io.Reader, stdout io.Writer) int {
	reader := bufio.NewReader(stdin)
	tr := i18n.MustNew(i18n.Detect())

	fmt.Fprintln(stdout, "============================================================")
	fmt.Fprintf(stdout, "   %s - Interactive Forensic Acquisition\n", version.Name)
	fmt.Fprintln(stdout, "============================================================")

	dInfo := distro.Detect()
	fmt.Fprintf(stdout, "System OS : %s (Family: %s)\n", dInfo.PrettyName, dInfo.Family)

	if !privilege.IsAdmin() {
		fmt.Fprintln(stdout, "")
		fmt.Fprintln(stdout, "[!] WARNING: Running without root privileges.")
		fmt.Fprintln(stdout, "    Protected files (/etc/shadow, /var/log/audit) may be inaccessible.")
		fmt.Fprintln(stdout, "    For full acquisition, restart with: sudo waeaa")
		fmt.Fprintln(stdout, "")
	}

	// 1. Output Destination
	defaultOut := "/tmp/evidence"
	if dInfo.Family == distro.FamilyGeneric && os.Getenv("TMPDIR") != "" {
		defaultOut = os.Getenv("TMPDIR")
	}
	outDir := promptString(reader, stdout, "Evidence output directory", defaultOut)
	if outDir == "" {
		outDir = defaultOut
	}

	// 2. Rules Selection
	fmt.Fprintln(stdout, "\nSelect Artefact Collection Scope:")
	fmt.Fprintln(stdout, "  [1] Standard Linux Triage (linux.triage - Recommended)")
	fmt.Fprintln(stdout, "  [2] Core System Forensics (linux.common)")
	fmt.Fprintln(stdout, "  [3] Custom rule IDs (comma separated)")

	choice := promptString(reader, stdout, "Choose option [1-3]", "1")
	var selectedRules []string
	switch strings.TrimSpace(choice) {
	case "2":
		selectedRules = []string{"linux.common"}
	case "3":
		custom := promptString(reader, stdout, "Enter rule IDs", "linux.triage")
		for _, part := range strings.Split(custom, ",") {
			if s := strings.TrimSpace(part); s != "" {
				selectedRules = append(selectedRules, s)
			}
		}
	default:
		selectedRules = []string{"linux.triage"}
	}

	// 3. Extra hashes
	var extraHashes []string
	hashChoice := promptString(reader, stdout, "Calculate extra hashes? (md5/sha1/none)", "none")
	if strings.Contains(strings.ToLower(hashChoice), "md5") {
		extraHashes = append(extraHashes, "md5")
	}
	if strings.Contains(strings.ToLower(hashChoice), "sha1") {
		extraHashes = append(extraHashes, "sha1")
	}

	// 4. Case Metadata
	caseID := promptString(reader, stdout, "Case Identifier (optional)", "")
	examiner := promptString(reader, stdout, "Examiner Name (optional)", "")
	notes := promptString(reader, stdout, "Investigation Notes (optional)", "")

	// 5. Mandatory Authorisation
	fmt.Fprintln(stdout, "\n"+tr.T("legal.notice"))
	confirm := promptString(reader, stdout, "Do you have lawful authorization to acquire this host? [y/N]", "n")
	if !strings.EqualFold(strings.TrimSpace(confirm), "y") && !strings.EqualFold(strings.TrimSpace(confirm), "yes") {
		fmt.Fprintln(stdout, "\n[X] Acquisition aborted: authorization not confirmed.")
		return 1
	}

	opts := cli.Options{
		Source:      "/",
		Output:      outDir,
		Rules:       selectedRules,
		CaseID:      caseID,
		Examiner:    examiner,
		Notes:       notes,
		Authorized:  true,
		ExtraHashes: extraHashes,
		Lang:        tr.Lang(),
	}

	fmt.Fprintln(stdout, "\n>>> Starting acquisition...")
	logger := logging.New(stdout, logging.LevelInfo)
	if err := engine.Run(&opts, logger, tr); err != nil {
		fmt.Fprintf(stdout, "\n[ERROR] Acquisition failed: %v\n", err)
		return 1
	}

	fmt.Fprintln(stdout, "\n[+] Acquisition completed successfully.")
	return 0
}

func promptString(r *bufio.Reader, w io.Writer, prompt, defaultVal string) string {
	if defaultVal != "" {
		fmt.Fprintf(w, "%s [%s]: ", prompt, defaultVal)
	} else {
		fmt.Fprintf(w, "%s: ", prompt)
	}
	line, _ := r.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultVal
	}
	return line
}
