// Package rules defines the structure, parsing and resolution of forensic
// artefact collection rules for WAEaA.
//
// Rules specify target files, paths, patterns and whether raw filesystem access
// is advised. Compound rules group multiple individual rules together.
package rules

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Target describes one specific file or directory pattern to collect.
type Target struct {
	// Path is the base folder or file path. May contain environment variables
	// like %SystemRoot%, %SystemDrive% or glob wildcards like Users\*.
	Path string `yaml:"path"`
	// Mask is the filename or wildcard to collect inside Path (e.g. "*.evtx").
	// If empty and Path points to a file, that file is collected.
	Mask string `yaml:"mask,omitempty"`
	// Recursive specifies whether to search subdirectories under Path.
	Recursive bool `yaml:"recursive,omitempty"`
	// IsDirectory indicates whether the whole directory should be collected as an entity.
	IsDirectory bool `yaml:"is_directory,omitempty"`
	// RawNTFS indicates that the target is expected to be locked by the OS and
	// requires low-level volume access (e.g. $MFT, active registry hives).
	RawNTFS bool `yaml:"raw_ntfs,omitempty"`
	// AlwaysCollect forces collection even if file size filters are set.
	AlwaysCollect bool `yaml:"always_collect,omitempty"`
	// Comment provides forensic context for this specific target.
	Comment string `yaml:"comment,omitempty"`
}

// Rule defines a forensic artefact rule or a compound rule.
type Rule struct {
	// ID is the unique identifier of the rule (e.g. "win.eventlogs").
	ID string `yaml:"id"`
	// Name is a human-readable title.
	Name string `yaml:"name"`
	// Description explains what the artefact is and its forensic value.
	Description string `yaml:"description"`
	// Category categorises the artefact (e.g. "EventLogs", "Registry", "FileSystem").
	Category string `yaml:"category"`
	// OS specifies the target OS: "windows", "linux" or "all".
	OS string `yaml:"os"`
	// Compound indicates that this rule groups other rules rather than targeting files directly.
	Compound bool `yaml:"compound,omitempty"`
	// Rules lists rule IDs included by this compound rule.
	Rules []string `yaml:"rules,omitempty"`
	// Targets lists target paths and patterns to collect when not compound.
	Targets []Target `yaml:"targets,omitempty"`
}

// Registry stores all available rules and resolves dependencies.
type Registry struct {
	mu    sync.RWMutex
	rules map[string]*Rule
}

// NewRegistry creates an empty rule registry.
func NewRegistry() *Registry {
	return &Registry{
		rules: make(map[string]*Rule),
	}
}

// Register adds one rule to the registry. Returns an error on duplicate IDs.
func (r *Registry) Register(rule *Rule) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := strings.ToLower(strings.TrimSpace(rule.ID))
	if id == "" {
		return errors.New("rules: rule ID cannot be empty")
	}
	if _, exists := r.rules[id]; exists {
		return fmt.Errorf("rules: duplicate rule ID %q", id)
	}
	rule.ID = id
	r.rules[id] = rule
	return nil
}

// ParseYAML parses a YAML document into a Rule and registers it.
func (r *Registry) ParseYAML(data []byte) (*Rule, error) {
	var rule Rule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, fmt.Errorf("rules: failed to unmarshal YAML: %w", err)
	}
	if err := r.Register(&rule); err != nil {
		return nil, err
	}
	return &rule, nil
}

// Get returns the rule with the given ID, or nil if not found.
func (r *Registry) Get(id string) *Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.rules[strings.ToLower(strings.TrimSpace(id))]
}

// All returns a slice of all registered rules.
func (r *Registry) All() []*Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	list := make([]*Rule, 0, len(r.rules))
	for _, rule := range r.rules {
		list = append(list, rule)
	}
	return list
}

// Resolve expands requested rule IDs, resolving compound rules and deduplicating
// targets while detecting circular dependencies.
func (r *Registry) Resolve(requestedIDs []string, targetOS string) ([]*Rule, []Target, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var resolvedRules []*Rule
	visitedRules := make(map[string]bool)
	activeStack := make(map[string]bool)

	var resolveRule func(id string) error
	resolveRule = func(id string) error {
		id = strings.ToLower(strings.TrimSpace(id))
		if visitedRules[id] {
			return nil
		}
		if activeStack[id] {
			return fmt.Errorf("rules: circular reference detected in rule %q", id)
		}
		rule, exists := r.rules[id]
		if !exists {
			return fmt.Errorf("rules: rule %q not found", id)
		}
		if rule.OS != "" && rule.OS != "all" && targetOS != "" && !strings.EqualFold(rule.OS, targetOS) {
			// Rule does not apply to the target OS; skip gracefully.
			return nil
		}

		activeStack[id] = true
		if rule.Compound {
			for _, subID := range rule.Rules {
				if err := resolveRule(subID); err != nil {
					return err
				}
			}
		}
		delete(activeStack, id)

		visitedRules[id] = true
		resolvedRules = append(resolvedRules, rule)
		return nil
	}

	for _, id := range requestedIDs {
		if err := resolveRule(id); err != nil {
			return nil, nil, err
		}
	}

	// Flatten all targets from non-compound rules
	var targets []Target
	for _, rule := range resolvedRules {
		if !rule.Compound {
			targets = append(targets, rule.Targets...)
		}
	}

	return resolvedRules, targets, nil
}

// MatchPattern tests whether a filename matches a glob pattern.
func MatchPattern(pattern, name string) (bool, error) {
	return filepath.Match(strings.ToLower(pattern), strings.ToLower(name))
}
