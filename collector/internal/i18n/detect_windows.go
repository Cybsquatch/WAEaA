//go:build windows

package i18n

import (
	"syscall"
	"unsafe"
)

// kernel32.dll is a "KnownDLL": Windows always maps it from System32, so
// loading it by name is not subject to DLL search-order hijacking.
var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procGetUserDefaultLocaleName = kernel32.NewProc("GetUserDefaultLocaleName")
)

// localeNameMaxLength is LOCALE_NAME_MAX_LENGTH from winnls.h.
const localeNameMaxLength = 85

// detectSystemLocale returns the user's default locale name (e.g. "it-IT").
// GetUserDefaultLocaleName is available since Windows Vista, so it is safe
// for the Windows 7 legacy build.
func detectSystemLocale() []string {
	if err := procGetUserDefaultLocaleName.Find(); err != nil {
		return nil
	}
	buf := make([]uint16, localeNameMaxLength)
	r, _, _ := procGetUserDefaultLocaleName.Call(
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if r == 0 {
		return nil
	}
	return []string{syscall.UTF16ToString(buf)}
}
