//go:build !windows

package ntfs

import (
	"errors"
	"io"
)

// BootSector stub for non-windows.
type BootSector struct {
	BytesPerSector    uint16
	SectorsPerCluster uint8
	BytesPerMFTRecord uint32
	ClusterSize       uint32
}

// VolumeReader stub for non-windows.
type VolumeReader struct {
	Boot BootSector
}

// OpenVolume returns an unsupported error on non-Windows platforms.
func OpenVolume(drive string) (*VolumeReader, error) {
	return nil, errors.New("ntfs: raw volume reading is only supported on Windows")
}

// Close is a stub.
func (v *VolumeReader) Close() error {
	return nil
}

// ReadAt is a stub.
func (v *VolumeReader) ReadAt(p []byte, off int64) (n int, err error) {
	return 0, errors.New("ntfs: unsupported on this platform")
}

// ReadInitialMFTStream is a stub.
func (v *VolumeReader) ReadInitialMFTStream(recordLimit int) io.Reader {
	return nil
}
