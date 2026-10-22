//go:build windows

package vss

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// ListSnapshots discovers existing Volume Shadow Copies for the given volume.
// If volume is empty or "C:", it queries for C:.
func ListSnapshots(volume string) ([]Snapshot, error) {
	vol := strings.ToUpper(strings.TrimRight(volume, `\/`))
	if vol == "" {
		vol = "C:"
	}

	// First try vssadmin list shadows
	snapshots, err := listViaVssadmin(vol)
	if err == nil && len(snapshots) > 0 {
		return snapshots, nil
	}

	// Fallback: probe HarddiskVolumeShadowCopy devices directly
	return probeShadowCopyDevices(vol), nil
}

func listViaVssadmin(volume string) ([]Snapshot, error) {
	cmd := exec.Command("vssadmin", "list", "shadows", "/for="+volume)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var snapshots []Snapshot
	scanner := bufio.NewScanner(bytes.NewReader(out))

	var currentDevice string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Shadow Copy Volume:") || strings.HasPrefix(line, "Volume copia shadow:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				currentDevice = strings.TrimSpace(parts[1])
			}
		} else if (strings.HasPrefix(line, "Original Volume:") || strings.HasPrefix(line, "Volume originale:")) && currentDevice != "" {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				origVol := strings.TrimSpace(parts[1])
				snapshots = append(snapshots, Snapshot{
					ID:           filepath.Base(currentDevice),
					DeviceObject: currentDevice,
					Volume:       origVol,
				})
				currentDevice = ""
			}
		}
	}

	return snapshots, nil
}

// probeShadowCopyDevices checks device numbers 1 to 32 under the NT GLOBALROOT
// namespace to see which shadow copies are active.
func probeShadowCopyDevices(volume string) []Snapshot {
	var snapshots []Snapshot

	for i := 1; i <= 32; i++ {
		devPath := fmt.Sprintf(`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy%d`, i)
		ptr, err := syscall.UTF16PtrFromString(devPath + `\`)
		if err != nil {
			continue
		}

		// Try opening root directory of shadow copy device
		h, err := syscall.CreateFile(
			ptr,
			syscall.GENERIC_READ,
			syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
			nil,
			syscall.OPEN_EXISTING,
			0x02000000, // FILE_FLAG_BACKUP_SEMANTICS
			0,
		)
		if err == nil {
			_ = syscall.CloseHandle(h)
			snapshots = append(snapshots, Snapshot{
				ID:           fmt.Sprintf("HarddiskVolumeShadowCopy%d", i),
				DeviceObject: devPath,
				Volume:       volume,
			})
		}
	}

	return snapshots
}
