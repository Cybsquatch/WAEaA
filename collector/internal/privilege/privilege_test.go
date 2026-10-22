package privilege

import (
	"testing"
)

func TestPrivilegeSmoke(t *testing.T) {
	// Call IsAdmin and EnableBackupPrivilege; should execute without panicking
	isAdmin := IsAdmin()
	t.Logf("IsAdmin: %v", isAdmin)

	err := EnableBackupPrivilege()
	t.Logf("EnableBackupPrivilege err: %v", err)
}
