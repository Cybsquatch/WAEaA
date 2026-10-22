// Package engine implements the forensic acquisition and archiving pipeline.
package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"os"
	"runtime"
)

// SystemInfo encapsulates environmental details about the host running the acquisition.
type SystemInfo struct {
	Hostname     string
	OS           string
	Platform     string
	Architecture string
	IPAddresses  []string
	MACAddresses []string
	BinaryPath   string
	BinarySHA256 string
}

// GatherSystemInfo queries local network and system properties.
func GatherSystemInfo() (*SystemInfo, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	info := &SystemInfo{
		Hostname:     hostname,
		OS:           runtime.GOOS,
		Platform:     runtime.GOOS,
		Architecture: runtime.GOARCH,
	}

	// Gather network interfaces, IPs and MAC addresses
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			if mac := iface.HardwareAddr.String(); mac != "" {
				info.MACAddresses = append(info.MACAddresses, mac)
			}
			if addrs, err := iface.Addrs(); err == nil {
				for _, addr := range addrs {
					if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
						info.IPAddresses = append(info.IPAddresses, ipNet.IP.String())
					}
				}
			}
		}
	}

	// Binary location and SHA-256 hash
	if exePath, err := os.Executable(); err == nil {
		info.BinaryPath = exePath
		if f, err := os.Open(exePath); err == nil {
			defer f.Close()
			h := sha256.New()
			if _, err := io.Copy(h, f); err == nil {
				info.BinarySHA256 = hex.EncodeToString(h.Sum(nil))
			}
		}
	}

	return info, nil
}
