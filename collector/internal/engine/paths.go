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
	s := filepath.Clean(source)
	if len(s) == 2 && s[1] == ':' {
		return s + `\`
	}
	return s
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
		volTarget := filepath.VolumeName(expanded)
		volSource := filepath.VolumeName(normSource)

		// Re-root if target volume differs from requested source volume or if target has no volume
		if volTarget != "" && volSource != "" && !strings.EqualFold(volTarget, volSource) {
			expanded = applySourceRoot(normSource, expanded)
		} else if volTarget == "" {
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
