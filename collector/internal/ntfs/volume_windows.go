//go:build windows

package ntfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

// BootSector represents the essential fields of an NTFS Volume Boot Record.
type BootSector struct {
	BytesPerSector    uint16
	SectorsPerCluster uint8
	MFTClusterStart   int64
	ClustersPerRecord int8
	BytesPerMFTRecord uint32
	ClusterSize       uint32
}

// VolumeReader provides raw sector-level read access to an NTFS partition.
type VolumeReader struct {
	drive  string
	handle syscall.Handle
	file   *os.File
	Boot   BootSector
}

// OpenVolume opens the raw volume device for drive (e.g. "C:" or "C:\").
func OpenVolume(drive string) (*VolumeReader, error) {
	driveLetter := strings.ToUpper(strings.TrimRight(strings.TrimSpace(drive), `\/.`))
	if len(driveLetter) != 2 || driveLetter[1] != ':' {
		return nil, fmt.Errorf("ntfs: invalid drive specifier %q", drive)
	}

	devicePath := `\\.\` + driveLetter
	ptr, err := syscall.UTF16PtrFromString(devicePath)
	if err != nil {
		return nil, err
	}

	h, err := syscall.CreateFile(
		ptr,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		fileFlagBackupSemantics,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("ntfs: failed opening raw volume %s: %w", devicePath, err)
	}

	f := os.NewFile(uintptr(h), devicePath)
	vr := &VolumeReader{
		drive:  driveLetter,
		handle: h,
		file:   f,
	}

	if err := vr.readBootSector(); err != nil {
		_ = f.Close()
		return nil, err
	}

	return vr, nil
}

// Close closes the raw volume handle.
func (v *VolumeReader) Close() error {
	return v.file.Close()
}

// readBootSector parses sector 0 of the NTFS volume.
func (v *VolumeReader) readBootSector() error {
	buf := make([]byte, 512)
	if _, err := v.file.ReadAt(buf, 0); err != nil {
		return fmt.Errorf("ntfs: failed to read boot sector: %w", err)
	}

	// Verify NTFS signature
	if !bytes.Equal(buf[3:11], []byte("NTFS    ")) {
		return errors.New("ntfs: signature 'NTFS    ' not found in boot sector")
	}

	bps := binary.LittleEndian.Uint16(buf[0x0B:0x0D])
	spc := buf[0x0D]
	mftClust := int64(binary.LittleEndian.Uint64(buf[0x30:0x38]))
	clustersPerRec := int8(buf[0x40])

	if bps == 0 || spc == 0 {
		return errors.New("ntfs: invalid boot sector parameters")
	}

	clusterSize := uint32(bps) * uint32(spc)
	var bytesPerMFTRecord uint32
	if clustersPerRec > 0 {
		bytesPerMFTRecord = uint32(clustersPerRec) * clusterSize
	} else {
		// If negative, size is 2^(-clustersPerRec) bytes (typically -10 -> 1024 bytes)
		shift := uint32(-clustersPerRec)
		bytesPerMFTRecord = 1 << shift
	}

	v.Boot = BootSector{
		BytesPerSector:    bps,
		SectorsPerCluster: spc,
		MFTClusterStart:   mftClust,
		ClustersPerRecord: clustersPerRec,
		BytesPerMFTRecord: bytesPerMFTRecord,
		ClusterSize:       clusterSize,
	}

	return nil
}

// ReadAt reads raw bytes from the volume at the given offset.
func (v *VolumeReader) ReadAt(p []byte, off int64) (n int, err error) {
	return v.file.ReadAt(p, off)
}

// ReadInitialMFTStream copies the starting chunks of the MFT using the volume handle.
// This allows forensic acquisition of $MFT records without external drivers.
func (v *VolumeReader) ReadInitialMFTStream(recordLimit int) io.Reader {
	if recordLimit <= 0 {
		recordLimit = 100000 // default chunk
	}

	mftByteOffset := v.Boot.MFTClusterStart * int64(v.Boot.ClusterSize)
	totalBytes := int64(recordLimit) * int64(v.Boot.BytesPerMFTRecord)

	return io.NewSectionReader(v.file, mftByteOffset, totalBytes)
}
