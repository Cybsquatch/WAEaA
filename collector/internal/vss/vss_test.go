package vss

import (
	"testing"
)

func TestVSSSmoke(t *testing.T) {
	snapshots, err := ListSnapshots("C:")
	t.Logf("Snapshots found: %d, err: %v", len(snapshots), err)
	for _, s := range snapshots {
		t.Logf("  Snapshot: %s -> %s", s.ID, s.DeviceObject)
	}
}
