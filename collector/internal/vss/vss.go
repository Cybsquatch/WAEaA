// Package vss handles discovery and access to Volume Shadow Copies on Windows
// for point-in-time forensic artefact recovery.
package vss

import (
	"time"
)

// Snapshot represents an enumerated Volume Shadow Copy snapshot.
type Snapshot struct {
	ID           string
	DeviceObject string // e.g. \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
	Volume       string // e.g. C:
	CreationTime time.Time
}
