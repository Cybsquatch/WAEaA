package distro

import (
	"testing"
)

func TestParseOSReleaseDebianUbuntu(t *testing.T) {
	ubuntuData := []byte(`
NAME="Ubuntu"
VERSION="24.04 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 24.04 LTS"
VERSION_ID="24.04"
`)
	info := ParseOSRelease(ubuntuData)
	if info.Family != FamilyDebian {
		t.Errorf("expected FamilyDebian, got %s", info.Family)
	}
	if info.ID != "ubuntu" || info.VersionID != "24.04" {
		t.Errorf("unexpected info: %+v", info)
	}
}

func TestParseOSReleaseRHEL(t *testing.T) {
	rockyData := []byte(`
NAME="Rocky Linux"
VERSION="9.4 (Blue Onyx)"
ID="rocky"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.4"
PRETTY_NAME="Rocky Linux 9.4 (Blue Onyx)"
`)
	info := ParseOSRelease(rockyData)
	if info.Family != FamilyRHEL {
		t.Errorf("expected FamilyRHEL, got %s", info.Family)
	}
	if info.ID != "rocky" {
		t.Errorf("expected ID rocky, got %s", info.ID)
	}
}

func TestParseOSReleaseSUSE(t *testing.T) {
	suseData := []byte(`
NAME="openSUSE Leap"
VERSION="15.5"
ID="opensuse-leap"
ID_LIKE="suse opensuse"
PRETTY_NAME="openSUSE Leap 15.5"
`)
	info := ParseOSRelease(suseData)
	if info.Family != FamilySUSE {
		t.Errorf("expected FamilySUSE, got %s", info.Family)
	}
}

func TestParseOSReleaseArch(t *testing.T) {
	archData := []byte(`
NAME="Arch Linux"
PRETTY_NAME="Arch Linux"
ID=arch
BUILD_ID=rolling
`)
	info := ParseOSRelease(archData)
	if info.Family != FamilyArch {
		t.Errorf("expected FamilyArch, got %s", info.Family)
	}
}

func TestDetectSmoke(t *testing.T) {
	info := Detect()
	if info == nil {
		t.Fatal("Detect returned nil")
	}
	t.Logf("Detected: %+v", info)
}
