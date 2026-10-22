// Package i18n provides the translations used by every user-facing string of
// the collector (CLI help, GUI, TUI, error messages).
//
// Catalogs are flat JSON objects (key -> message) stored in locales/*.json and
// embedded into the binary, so the collector stays a single self-contained
// executable. Messages may contain fmt verbs; arguments are applied with
// fmt.Sprintf.
//
// Adding a language:
//  1. create locales/<code>.json with exactly the same keys as en.json;
//  2. add the code to Supported;
//  3. run the tests: TestCatalogsHaveSameKeys guarantees no key is missing.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"
)

// DefaultLanguage is used when the requested or detected language is not
// supported. English is also the fallback for any key missing in a catalog.
const DefaultLanguage = "en"

// Supported lists the ISO 639-1 codes of the shipped catalogs.
var Supported = []string{"it", "en", "es", "fr", "de"}

//go:embed locales/*.json
var localeFS embed.FS

// Translator resolves message keys for one language.
// It is immutable after creation and therefore safe for concurrent use.
type Translator struct {
	lang     string
	messages map[string]string
	fallback map[string]string
}

// New returns a Translator for lang. The tag is normalised first
// (see Normalize); unsupported languages fall back to DefaultLanguage.
func New(lang string) (*Translator, error) {
	code := Normalize(lang)
	if !IsSupported(code) {
		code = DefaultLanguage
	}
	fallback, err := loadCatalog(DefaultLanguage)
	if err != nil {
		return nil, err
	}
	messages := fallback
	if code != DefaultLanguage {
		if messages, err = loadCatalog(code); err != nil {
			return nil, err
		}
	}
	return &Translator{lang: code, messages: messages, fallback: fallback}, nil
}

// MustNew is like New but panics on error. Catalogs are embedded at build
// time, so an error here is a programming mistake caught by the tests.
func MustNew(lang string) *Translator {
	t, err := New(lang)
	if err != nil {
		panic(err)
	}
	return t
}

// Lang returns the effective language code of the translator.
func (t *Translator) Lang() string { return t.lang }

// T returns the message for key formatted with args. Lookup order is:
// selected language, English fallback, and finally the key itself, so a
// missing translation is visible but never crashes the tool.
func (t *Translator) T(key string, args ...interface{}) string {
	msg, ok := t.messages[key]
	if !ok {
		if msg, ok = t.fallback[key]; !ok {
			msg = key
		}
	}
	if len(args) == 0 {
		return msg
	}
	return fmt.Sprintf(msg, args...)
}

// Normalize converts a locale tag such as "it_IT.UTF-8", "de-DE" or "FR" to
// its lower-case two-letter language code ("it", "de", "fr").
// The POSIX "C" / "POSIX" locales and empty strings map to "".
func Normalize(tag string) string {
	tag = strings.TrimSpace(tag)
	// Strip encoding (".UTF-8") and modifier ("@euro").
	if i := strings.IndexAny(tag, ".@"); i >= 0 {
		tag = tag[:i]
	}
	// Keep only the language part of "it_IT" / "it-IT".
	if i := strings.IndexAny(tag, "_-"); i >= 0 {
		tag = tag[:i]
	}
	tag = strings.ToLower(tag)
	if tag == "c" || tag == "posix" {
		return ""
	}
	return tag
}

// IsSupported reports whether code (already normalised) has a catalog.
func IsSupported(code string) bool {
	for _, s := range Supported {
		if s == code {
			return true
		}
	}
	return false
}

// Detect returns the best supported language for the current user, based on
// the operating-system locale (see detectSystemLocale, implemented per OS).
func Detect() string {
	for _, tag := range detectSystemLocale() {
		if code := Normalize(tag); IsSupported(code) {
			return code
		}
	}
	return DefaultLanguage
}

// loadCatalog reads and decodes the embedded catalog for code.
func loadCatalog(code string) (map[string]string, error) {
	data, err := localeFS.ReadFile("locales/" + code + ".json")
	if err != nil {
		return nil, fmt.Errorf("i18n: catalog %q not found: %w", code, err)
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("i18n: catalog %q is not valid JSON: %w", code, err)
	}
	return m, nil
}
