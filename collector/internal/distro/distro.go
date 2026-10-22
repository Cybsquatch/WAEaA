// Package distro identifies the running Linux distribution and its family
// by parsing /etc/os-release and standard system files.
package distro

import (
	"bufio"
	"bytes"
	"os"
	"strings"
)

// Family represents a broader classification of Linux distributions.
type Family string

const (
	FamilyDebian  Family = "debian"  // Debian, Ubuntu, Mint, Kali, Pop!_OS
	FamilyRHEL    Family = "rhel"    // RHEL, CentOS, Rocky, Alma, Fedora, Amazon Linux, Oracle
	FamilySUSE    Family = "suse"    // openSUSE, SLES
	FamilyArch    Family = "arch"    // Arch, Manjaro
	FamilyGeneric Family = "generic" // Fallback / unknown Linux
)

// Info holds distribution metadata discovered from the system.
type Info struct {
	ID         string
	Family     Family
	Name       string
	VersionID  string
	PrettyName string
}

// Detect inspects /etc/os-release (or /usr/lib/os-release) to determine the distribution.
func Detect() *Info {
	paths := []string{"/etc/os-release", "/usr/lib/os-release"}
	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil {
			if info := ParseOSRelease(data); info != nil {
				return info
			}
		}
	}

	// Legacy distribution checks
	if fileExists("/etc/debian_version") {
		return &Info{ID: "debian", Family: FamilyDebian, Name: "Debian", PrettyName: "Debian (legacy)"}
	}
	if fileExists("/etc/redhat-release") {
		return &Info{ID: "rhel", Family: FamilyRHEL, Name: "Red Hat", PrettyName: "RHEL/CentOS (legacy)"}
	}
	if fileExists("/etc/arch-release") {
		return &Info{ID: "arch", Family: FamilyArch, Name: "Arch Linux", PrettyName: "Arch (legacy)"}
	}
	if fileExists("/etc/SuSE-release") {
		return &Info{ID: "suse", Family: FamilySUSE, Name: "SUSE", PrettyName: "SUSE (legacy)"}
	}

	return &Info{ID: "linux", Family: FamilyGeneric, Name: "Generic Linux", PrettyName: "Linux"}
}

// ParseOSRelease parses the key=value format of /etc/os-release.
func ParseOSRelease(data []byte) *Info {
	fields := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
			fields[k] = v
		}
	}

	id := strings.ToLower(fields["ID"])
	idLike := strings.ToLower(fields["ID_LIKE"])
	name := fields["NAME"]
	pretty := fields["PRETTY_NAME"]
	ver := fields["VERSION_ID"]

	family := classifyFamily(id, idLike)

	return &Info{
		ID:         id,
		Family:     family,
		Name:       name,
		VersionID:  ver,
		PrettyName: pretty,
	}
}

func classifyFamily(id, idLike string) Family {
	all := id + " " + idLike

	switch {
	case strings.Contains(all, "debian") || strings.Contains(all, "ubuntu") || id == "kali" || id == "mint":
		return FamilyDebian
	case strings.Contains(all, "rhel") || strings.Contains(all, "fedora") || strings.Contains(all, "centos") ||
		id == "rocky" || id == "alma" || id == "amzn" || id == "ol":
		return FamilyRHEL
	case strings.Contains(all, "suse") || strings.Contains(all, "sles") || id == "opensuse":
		return FamilySUSE
	case strings.Contains(all, "arch") || id == "manjaro":
		return FamilyArch
	default:
		return FamilyGeneric
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
