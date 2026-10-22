// Package rulesfs provides the embedded rules and loader functions.
package rulesfs

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Cybsquatch/WAEaA/collector/internal/rules"
)

//go:embed windows/*.yaml linux/*.yaml
var embeddedRulesFS embed.FS

// LoadDefaultRegistry creates and populates a rule registry with all
// embedded built-in rules.
func LoadDefaultRegistry() (*rules.Registry, error) {
	reg := rules.NewRegistry()

	err := fs.WalkDir(embeddedRulesFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".yaml") {
			return nil
		}
		data, err := embeddedRulesFS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("rulesfs: failed reading embedded %s: %w", path, err)
		}
		if _, err := reg.ParseYAML(data); err != nil {
			return fmt.Errorf("rulesfs: error parsing embedded %s: %w", path, err)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	return reg, nil
}

// LoadCustomRulesDirectory scans a custom directory on disk for YAML rules
// and registers them into the given registry.
func LoadCustomRulesDirectory(reg *rules.Registry, dir string) error {
	if dir == "" {
		return nil
	}
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(strings.ToLower(info.Name()), ".yaml") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("rulesfs: failed reading %s: %w", path, err)
		}
		if _, err := reg.ParseYAML(data); err != nil {
			return fmt.Errorf("rulesfs: error parsing %s: %w", path, err)
		}
		return nil
	})
}
