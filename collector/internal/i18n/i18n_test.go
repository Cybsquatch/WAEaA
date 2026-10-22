package i18n

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestCatalogsHaveSameKeys guarantees that every shipped language translates
// exactly the same set of keys as the English reference catalog.
func TestCatalogsHaveSameKeys(t *testing.T) {
	ref, err := loadCatalog(DefaultLanguage)
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range Supported {
		cat, err := loadCatalog(code)
		if err != nil {
			t.Fatalf("%s: %v", code, err)
		}
		for k := range ref {
			if _, ok := cat[k]; !ok {
				t.Errorf("%s: missing key %q", code, k)
			}
		}
		for k := range cat {
			if _, ok := ref[k]; !ok {
				t.Errorf("%s: extra key %q not present in %s", code, k, DefaultLanguage)
			}
		}
	}
}

// verbRe matches fmt verbs, including explicit argument indexes (%[1]s).
var verbRe = regexp.MustCompile(`%(\[\d+\])?[a-zA-Z]`)

// TestCatalogsHaveSameFormatVerbs prevents translations that would break
// fmt.Sprintf (e.g. a %s forgotten or added in one language).
func TestCatalogsHaveSameFormatVerbs(t *testing.T) {
	ref, _ := loadCatalog(DefaultLanguage)
	for _, code := range Supported {
		cat, _ := loadCatalog(code)
		for k, refMsg := range ref {
			want := sortedVerbs(refMsg)
			got := sortedVerbs(cat[k])
			if strings.Join(want, ",") != strings.Join(got, ",") {
				t.Errorf("%s/%s: verbs %v, want %v", code, k, got, want)
			}
		}
	}
}

func sortedVerbs(s string) []string {
	v := verbRe.FindAllString(s, -1)
	sort.Strings(v)
	return v
}

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"it_IT.UTF-8": "it",
		"de-DE":       "de",
		"FR":          "fr",
		"es_ES@euro":  "es",
		"C":           "",
		"POSIX":       "",
		"":            "",
		"  en_US  ":   "en",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewFallsBackToEnglish(t *testing.T) {
	tr := MustNew("ja_JP")
	if tr.Lang() != DefaultLanguage {
		t.Fatalf("Lang() = %q, want %q", tr.Lang(), DefaultLanguage)
	}
}

func TestTranslate(t *testing.T) {
	it := MustNew("it")
	if got := it.T("err.invalid_lang", "xx"); got != "lingua non supportata: xx" {
		t.Errorf("unexpected translation: %q", got)
	}
	// Unknown keys are returned verbatim instead of panicking.
	if got := it.T("does.not.exist"); got != "does.not.exist" {
		t.Errorf("unknown key: got %q", got)
	}
}

func TestDetectReturnsSupported(t *testing.T) {
	if code := Detect(); !IsSupported(code) {
		t.Errorf("Detect() = %q, not supported", code)
	}
}
