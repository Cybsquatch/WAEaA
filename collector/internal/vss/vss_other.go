//go:build !windows

package vss

// ListSnapshots returns an empty slice on non-Windows platforms.
func ListSnapshots(volume string) ([]Snapshot, error) {
	return nil, nil
}
