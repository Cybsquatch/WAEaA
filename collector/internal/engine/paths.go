package engine

import (
	"os"
	"path/filepath"
	"strings"
)

// NormalizeDrive ensures a Windows drive string is formatted as "C:\" or Unix as "/".
func NormalizeDrive(source string) string {
	if source == "" {
		return ""
	}
	s := strings.TrimSpace(source)
	if len(s) == 2 && s[1] == ':' {
		return s + `\`
	}
	s = filepath.Clean(s)
	if len(s) == 3 && s[1] == ':' && s[2] == '.' {
		return s[:2] + `\`
	}
	return s
}

// isInsideOrSame reports whether target path is identical to or located inside parent.
func isInsideOrSame(target, parent string) bool {
	t := NormalizeDrive(target)
	p := NormalizeDrive(parent)
	if strings.EqualFold(t, p) {
		return true
	}
	sep := string(filepath.Separator)
	if !strings.HasSuffix(p, sep) && !strings.HasSuffix(p, `/`) && !strings.HasSuffix(p, `\`) {
		p += sep
	}
	return strings.HasPrefix(strings.ToLower(t), strings.ToLower(p))
}

// ExpandPath expands environment variables, adjusts the root drive/mount point,
// and resolves any wildcard directory segments (such as Users\*).
func ExpandPath(sourceRoot, rawPath string) ([]string, error) {
	// First expand environment variables if present
	expanded := os.ExpandEnv(rawPath)

	// In case %SystemRoot% or %SystemDrive% were not set by current env
	if strings.Contains(strings.ToLower(expanded), "%systemroot%") {
		expanded = replaceEnvVar(expanded, "%SystemRoot%", `C:\Windows`)
	}
	if strings.Contains(strings.ToLower(expanded), "%systemdrive%") {
		expanded = replaceEnvVar(expanded, "%SystemDrive%", `C:\`)
	}

	// Clean and standardise separators
	expanded = filepath.Clean(expanded)

	// If a custom source is specified, ensure it is normalized (e.g. "C:\")
	if sourceRoot != "" {
		normSource := NormalizeDrive(sourceRoot)
		if !isInsideOrSame(expanded, normSource) {
			expanded = applySourceRoot(normSource, expanded)
		}
	}

	// Resolve any wildcard components in the path (e.g. C:\Users\*\AppData)
	return resolveWildcardPaths(expanded)
}

func replaceEnvVar(s, varName, replacement string) string {
	lower := strings.ToLower(s)
	target := strings.ToLower(varName)
	idx := strings.Index(lower, target)
	if idx < 0 {
		return s
	}
	return s[:idx] + replacement + s[idx+len(varName):]
}

// applySourceRoot re-bases a target path onto the given source volume.
func applySourceRoot(source, target string) string {
	volSource := filepath.VolumeName(source)
	volTarget := filepath.VolumeName(target)

	// If on non-Windows OS, filepath.VolumeName will be empty even for Windows paths like "C:\Windows".
	// Detect Windows drive letter manually if volTarget is empty.
	if volTarget == "" && len(target) >= 2 && target[1] == ':' {
		c := target[0]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			volTarget = target[:2]
		}
	}

	// If source is just a drive (e.g. "D:" or "D:\"), preserve the root backslash
	// because filepath.Join("D:\", "path") on Windows collapses to "D:path".
	isDriveRoot := volSource != "" && len(strings.TrimRight(source, `\/`)) == 2

	var rel string
	if volTarget != "" {
		rel = strings.TrimLeft(target[len(volTarget):], `\/`)
	} else {
		rel = strings.TrimLeft(target, `\/`)
	}

	if isDriveRoot {
		drive := strings.TrimRight(source, `\/`)
		return drive + `\` + rel
	}

	return filepath.Join(source, rel)
}

// resolveWildcardPaths resolves directory segments containing wildcards.
func resolveWildcardPaths(pattern string) ([]string, error) {
	if !strings.ContainsAny(pattern, "*?[") {
		return []string{pattern}, nil
	}

	vol := filepath.VolumeName(pattern)
	rest := pattern[len(vol):]
	parts := strings.Split(filepath.Clean(rest), string(filepath.Separator))

	results := []string{vol + string(filepath.Separator)}
	if vol == "" && !strings.HasPrefix(pattern, string(filepath.Separator)) {
		results = []string{""}
	}

	for _, part := range parts {
		if part == "" {
			continue
		}
		var nextResults []string
		for _, base := range results {
			candidate := filepath.Join(base, part)
			if strings.ContainsAny(part, "*?[") {
				matches, err := filepath.Glob(candidate)
				if err != nil {
					continue
				}
				nextResults = append(nextResults, matches...)
			} else {
				nextResults = append(nextResults, candidate)
			}
		}
		results = nextResults
	}

	return results, nil
}
