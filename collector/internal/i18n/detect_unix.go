//go:build !windows

package i18n

import (
	"os"
	"strings"
)

// detectSystemLocale returns locale candidates from the standard POSIX
// environment variables, in their documented order of precedence.
// LANGUAGE may contain a colon-separated priority list (GNU extension).
func detectSystemLocale() []string {
	var tags []string
	for _, part := range strings.Split(os.Getenv("LANGUAGE"), ":") {
		if part != "" {
			tags = append(tags, part)
		}
	}
	for _, name := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(name); v != "" {
			tags = append(tags, v)
		}
	}
	return tags
}
