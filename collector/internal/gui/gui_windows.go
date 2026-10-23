//go:build windows

package gui

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/Cybsquatch/WAEaA/collector/internal/cli"
	"github.com/Cybsquatch/WAEaA/collector/internal/engine"
	"github.com/Cybsquatch/WAEaA/collector/internal/i18n"
	"github.com/Cybsquatch/WAEaA/collector/internal/logging"
	"github.com/Cybsquatch/WAEaA/collector/internal/version"
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")

	procRegisterClassExW        = user32.NewProc("RegisterClassExW")
	procCreateWindowExW         = user32.NewProc("CreateWindowExW")
	procDefWindowProcW          = user32.NewProc("DefWindowProcW")
	procDestroyWindow           = user32.NewProc("DestroyWindow")
	procPostQuitMessage         = user32.NewProc("PostQuitMessage")
	procShowWindow              = user32.NewProc("ShowWindow")
	procUpdateWindow            = user32.NewProc("UpdateWindow")
	procGetMessageW             = user32.NewProc("GetMessageW")
	procTranslateMessage        = user32.NewProc("TranslateMessage")
	procDispatchMessageW        = user32.NewProc("DispatchMessageW")
	procSendMessageW            = user32.NewProc("SendMessageW")
	procSetWindowTextW          = user32.NewProc("SetWindowTextW")
	procGetWindowTextW          = user32.NewProc("GetWindowTextW")
	procGetWindowTextLength     = user32.NewProc("GetWindowTextLengthW")
	procEnableWindow            = user32.NewProc("EnableWindow")
	procMessageBoxW             = user32.NewProc("MessageBoxW")
	procLoadCursorW             = user32.NewProc("LoadCursorW")
	procGetStockObject          = gdi32.NewProc("GetStockObject")
	procGetModuleHandleW        = kernel32.NewProc("GetModuleHandleW")
	procGetLogicalDriveStringsW = kernel32.NewProc("GetLogicalDriveStringsW")
	procGetDriveTypeW           = kernel32.NewProc("GetDriveTypeW")
	procGetVolumeInformationW   = kernel32.NewProc("GetVolumeInformationW")
	procGetDiskFreeSpaceExW     = kernel32.NewProc("GetDiskFreeSpaceExW")
	procSHBrowseForFolderW      = shell32.NewProc("SHBrowseForFolderW")
	procSHGetPathFromIDListW    = shell32.NewProc("SHGetPathFromIDListW")
)

// Win32 Constants
const (
	wsOverlappedWindow = 0x00CF0000
	wsVisible          = 0x10000000
	wsChild            = 0x40000000
	wsBorder           = 0x00800000
	wsVScroll          = 0x00200000
	wsGroup            = 0x00020000

	esLeft        = 0x0000
	esMultiline   = 0x0004
	esAutoVScroll = 0x0040
	esReadOnly    = 0x0800

	bsPushButton   = 0x00000000
	bsAutoCheckBox = 0x00000003
	bsGroupBox     = 0x00000007

	bmGetCheck = 0x00F0
	bmSetCheck = 0x00F1
	bstChecked = 1

	wmDestroy      = 0x0002
	wmClose        = 0x0010
	wmCommand      = 0x0111
	wmSetFont      = 0x0030
	defaultGuiFont = 17 // DEFAULT_GUI_FONT

	emSetSel     = 0x00B1
	emReplaceSel = 0x00C2
)

// Control IDs
const (
	idBtnBrowseSrc       = 101
	idBtnBrowseOut       = 102
	idBtnStart           = 103
	idChkAuth            = 104
	idBtnSelectAllDrives = 105
)

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   syscall.Handle
	Icon       syscall.Handle
	Cursor     syscall.Handle
	Background syscall.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     syscall.Handle
}

type winMsg struct {
	Hwnd     syscall.Handle
	Message  uint32
	_pad1    uint32 // 4-byte padding for 64-bit alignment of WParam
	WParam   uintptr
	LParam   uintptr
	Time     uint32
	Pt       struct{ X, Y int32 }
	LPrivate uint32
}

type browseInfo struct {
	HwndOwner      syscall.Handle
	PidlRoot       uintptr
	PszDisplayName *uint16
	LpszTitle      *uint16
	UlFlags        uint32
	Lpfn           uintptr
	LParam         uintptr
	IImage         int32
}

type DriveItem struct {
	Letter     string // "C:\"
	Label      string // "SSD Windows"
	FileSystem string // "NTFS"
	TotalGB    float64
	Hwnd       syscall.Handle
}

type guiState struct {
	mu         sync.Mutex
	hwndMain   syscall.Handle
	hSrcEdit   syscall.Handle
	hOutEdit   syscall.Handle
	hCaseEdit  syscall.Handle
	hExamEdit  syscall.Handle
	hNotesEdit syscall.Handle
	hLogEdit   syscall.Handle
	hBtnStart  syscall.Handle
	hChkAuth   syscall.Handle
	hChkVSS    syscall.Handle
	hChkDedup  syscall.Handle
	hChkMD5    syscall.Handle
	hChkSHA1   syscall.Handle

	// Detected Drives
	drives      []DriveItem
	driveChecks map[string]syscall.Handle // Drive letter -> checkbox hwnd

	// Rule checkboxes map rule ID -> hwnd
	ruleChecks map[string]syscall.Handle
	tr         *i18n.Translator
	running    bool
}

var state guiState

// Run starts the native Windows GUI.
func Run() int {
	// Lock the OS thread: mandatory for Win32 GUI message loops in Go.
	// Prevents the scheduler from migrating the goroutine to another OS thread,
	// which causes GetMessage to hang and the window to show "(Not Responding)".
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	state.tr = i18n.MustNew(i18n.Detect())
	state.ruleChecks = make(map[string]syscall.Handle)
	state.driveChecks = make(map[string]syscall.Handle)

	hInstance, _, _ := procGetModuleHandleW.Call(0)
	className, _ := syscall.UTF16PtrFromString("WAEaA_Collector_Window")
	title, _ := syscall.UTF16PtrFromString(fmt.Sprintf("%s - Forensic Triage %s", version.Name, version.Version))

	hCursor, _, _ := procLoadCursorW.Call(0, 32512) // IDC_ARROW

	wcex := wndClassEx{
		Size:       uint32(unsafe.Sizeof(wndClassEx{})),
		Style:      0x0003, // CS_HREDRAW | CS_VREDRAW
		WndProc:    syscall.NewCallback(windowProc),
		Instance:   syscall.Handle(hInstance),
		Cursor:     syscall.Handle(hCursor),
		Background: 16, // COLOR_BTNFACE + 1
		ClassName:  className,
	}

	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wcex)))

	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(title)),
		wsOverlappedWindow|wsVisible,
		80, 60, 940, 780,
		0, 0, hInstance, 0,
	)

	if hwnd == 0 {
		return 1
	}

	state.hwndMain = syscall.Handle(hwnd)
	buildControls(state.hwndMain, syscall.Handle(hInstance))

	procShowWindow.Call(hwnd, 1)
	procUpdateWindow.Call(hwnd)

	// Windows Message Loop
	var msg winMsg
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if r == 0 || int32(r) == -1 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}

	return 0
}

func detectDrives() []DriveItem {
	buf := make([]uint16, 512)
	r, _, _ := procGetLogicalDriveStringsW.Call(uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])))
	if r == 0 {
		return nil
	}

	var items []DriveItem
	var current []uint16
	for _, ch := range buf[:r] {
		if ch == 0 {
			if len(current) > 0 {
				driveStr := syscall.UTF16ToString(current)
				current = nil

				drivePtr, _ := syscall.UTF16PtrFromString(driveStr)
				dt, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(drivePtr)))
				// Skip CD-ROM (5)
				if dt == 5 {
					continue
				}

				volNameBuf := make([]uint16, 260)
				fsNameBuf := make([]uint16, 260)
				var serial, maxComponentLen, flags uint32

				procGetVolumeInformationW.Call(
					uintptr(unsafe.Pointer(drivePtr)),
					uintptr(unsafe.Pointer(&volNameBuf[0])),
					uintptr(len(volNameBuf)),
					uintptr(unsafe.Pointer(&serial)),
					uintptr(unsafe.Pointer(&maxComponentLen)),
					uintptr(unsafe.Pointer(&flags)),
					uintptr(unsafe.Pointer(&fsNameBuf[0])),
					uintptr(len(fsNameBuf)),
				)

				label := syscall.UTF16ToString(volNameBuf)
				fs := syscall.UTF16ToString(fsNameBuf)

				var freeBytes, totalBytes, totalFree uint64
				procGetDiskFreeSpaceExW.Call(
					uintptr(unsafe.Pointer(drivePtr)),
					uintptr(unsafe.Pointer(&freeBytes)),
					uintptr(unsafe.Pointer(&totalBytes)),
					uintptr(unsafe.Pointer(&totalFree)),
				)

				totalGB := float64(totalBytes) / (1024 * 1024 * 1024)

				items = append(items, DriveItem{
					Letter:     driveStr,
					Label:      label,
					FileSystem: fs,
					TotalGB:    totalGB,
				})
			}
		} else {
			current = append(current, ch)
		}
	}
	return items
}

func buildControls(parent, hInstance syscall.Handle) {
	hFont, _, _ := procGetStockObject.Call(defaultGuiFont)

	// Helper to create controls
	createCtrl := func(class, text string, style uint32, x, y, w, h int, id int) syscall.Handle {
		cPtr, _ := syscall.UTF16PtrFromString(class)
		tPtr, _ := syscall.UTF16PtrFromString(text)
		hw, _, _ := procCreateWindowExW.Call(
			0,
			uintptr(unsafe.Pointer(cPtr)),
			uintptr(unsafe.Pointer(tPtr)),
			uintptr(wsChild|wsVisible|style),
			uintptr(x), uintptr(y), uintptr(w), uintptr(h),
			uintptr(parent),
			uintptr(id),
			uintptr(hInstance),
			0,
		)
		procSendMessageW.Call(hw, wmSetFont, hFont, 1)
		return syscall.Handle(hw)
	}

	// 1. Source and Output Path Selection
	createCtrl("BUTTON", " Acquisition Scope & Target Drives ", bsGroupBox, 15, 8, 895, 145, 0)

	// Drive Checkboxes
	createCtrl("STATIC", "Select Drive(s) to acquire:", 0, 30, 28, 200, 18, 0)
	createCtrl("BUTTON", "Select / Invert All", bsPushButton, 755, 24, 135, 22, idBtnSelectAllDrives)

	state.drives = detectDrives()
	sysDrive := os.Getenv("SystemDrive")
	if sysDrive == "" {
		sysDrive = "C:"
	}
	sysDrive = strings.ToUpper(strings.TrimRight(sysDrive, `\/`)) + `\`

	driveX := 30
	driveY := 48
	for i, d := range state.drives {
		labelStr := d.Letter
		if d.Label != "" {
			labelStr += fmt.Sprintf(" [%s]", d.Label)
		}
		if d.FileSystem != "" {
			labelStr += fmt.Sprintf(" (%s", d.FileSystem)
			if d.TotalGB > 0 {
				labelStr += fmt.Sprintf(", %.1f GB)", d.TotalGB)
			} else {
				labelStr += ")"
			}
		}

		chk := createCtrl("BUTTON", labelStr, bsAutoCheckBox, driveX, driveY, 275, 22, 0)
		// Check system drive by default
		if strings.EqualFold(d.Letter, sysDrive) {
			procSendMessageW.Call(uintptr(chk), bmSetCheck, bstChecked, 0)
		}
		state.driveChecks[d.Letter] = chk
		state.drives[i].Hwnd = chk

		driveX += 285
		if (i+1)%3 == 0 {
			driveX = 30
			driveY += 24
		}
	}

	// Optional Custom Path & Evidence Output
	createCtrl("STATIC", "Or custom path:", 0, 30, 96, 110, 20, 0)
	state.hSrcEdit = createCtrl("EDIT", "", wsBorder|esLeft, 145, 93, 620, 22, 0)
	createCtrl("BUTTON", "Browse...", bsPushButton, 775, 92, 115, 23, idBtnBrowseSrc)

	createCtrl("STATIC", "Evidence Output:", 0, 30, 122, 110, 20, 0)
	state.hOutEdit = createCtrl("EDIT", "", wsBorder|esLeft, 145, 120, 620, 22, 0)
	createCtrl("BUTTON", "Browse...", bsPushButton, 775, 119, 115, 23, idBtnBrowseOut)

	// 2. Forensic Artefact Rules Group
	createCtrl("BUTTON", " Artefact Rules Selection ", bsGroupBox, 15, 160, 540, 215, 0)

	// Add Checkboxes for Built-in Forensic Rules
	ruleList := []struct{ id, label string }{
		{"triage", "Standard Triage (Comprehensive IR Bundle)"},
		{"win.eventlogs", "Windows Event Logs (.evtx)"},
		{"win.registry", "Registry Hives (System, SAM, Software, NTUSER)"},
		{"win.prefetch", "Windows Prefetch Execution Evidence"},
		{"win.amcache", "Amcache & Application Compatibility"},
		{"win.srum", "System Resource Usage Monitor (SRUM)"},
		{"win.lnk_jumplists", "Recent Shortcuts & JumpLists"},
		{"win.scheduled_tasks", "Scheduled Tasks XML Definitions"},
		{"win.powershell_history", "PowerShell Console History"},
		{"win.recycle_bin", "Recycle Bin Records ($I*)"},
		{"win.browser_history", "Browser History (Chrome, Edge, Firefox)"},
		{"win.rdp_cache", "RDP Bitmap Cache (.bmc, .bin tiles)"},
		{"win.filesystem_mft", "NTFS Metadata ($MFT, $LogFile, $UsnJrnl)"},
	}

	colX := 30
	rowY := 182
	for i, r := range ruleList {
		chk := createCtrl("BUTTON", r.label, bsAutoCheckBox, colX, rowY, 250, 20, 0)
		if r.id == "triage" {
			procSendMessageW.Call(uintptr(chk), bmSetCheck, bstChecked, 0)
		}
		state.ruleChecks[r.id] = chk
		rowY += 24
		if i == 6 {
			colX = 290
			rowY = 182
		}
	}

	// 3. Acquisition Options Group
	createCtrl("BUTTON", " Forensic Options ", bsGroupBox, 570, 160, 340, 215, 0)
	state.hChkVSS = createCtrl("BUTTON", "Process Volume Shadow Copies (VSS)", bsAutoCheckBox, 585, 185, 310, 22, 0)
	state.hChkDedup = createCtrl("BUTTON", "De-duplication Enabled (SHA-1)", bsAutoCheckBox, 585, 215, 310, 22, 0)
	procSendMessageW.Call(uintptr(state.hChkDedup), bmSetCheck, bstChecked, 0)

	state.hChkMD5 = createCtrl("BUTTON", "Calculate MD5 hash", bsAutoCheckBox, 585, 245, 310, 22, 0)
	state.hChkSHA1 = createCtrl("BUTTON", "Calculate SHA-1 hash", bsAutoCheckBox, 585, 275, 310, 22, 0)

	// 4. Chain of Custody & Authorisation
	createCtrl("BUTTON", " Chain of Custody & Authorisation ", bsGroupBox, 15, 382, 895, 110, 0)
	createCtrl("STATIC", "Case Identifier:", 0, 30, 405, 110, 20, 0)
	state.hCaseEdit = createCtrl("EDIT", "", wsBorder|esLeft, 145, 402, 280, 22, 0)

	createCtrl("STATIC", "Examiner:", 0, 450, 405, 90, 20, 0)
	state.hExamEdit = createCtrl("EDIT", "", wsBorder|esLeft, 545, 402, 345, 22, 0)

	createCtrl("STATIC", "Notes / Scope:", 0, 30, 434, 110, 20, 0)
	state.hNotesEdit = createCtrl("EDIT", "", wsBorder|esLeft, 145, 431, 745, 22, 0)

	state.hChkAuth = createCtrl("BUTTON", "AUTHORISATION CONFIRMATION: I confirm explicit, lawful authorisation to collect forensic artefacts from this host.", bsAutoCheckBox, 30, 460, 860, 20, idChkAuth)

	// 5. Execution Button
	state.hBtnStart = createCtrl("BUTTON", "START FORENSIC ACQUISITION", bsPushButton, 15, 500, 895, 38, idBtnStart)

	// 6. Live Log Output
	createCtrl("STATIC", "Live Acquisition Log:", 0, 15, 545, 300, 18, 0)
	state.hLogEdit = createCtrl("EDIT", "", wsBorder|esLeft|esMultiline|esAutoVScroll|esReadOnly|wsVScroll, 15, 565, 895, 160, 0)

	appendLog("WAEaA Forensic Collector initialized. Administrative privileges active.\r\nDetected volumes ready for acquisition. Confirm authorisation and start.")
}

func windowProc(hwnd syscall.Handle, msg uintptr, wParam, lParam uintptr) uintptr {
	switch msg {
	case wmCommand:
		id := int(wParam & 0xFFFF)
		switch id {
		case idBtnBrowseSrc:
			browseFolder(state.hwndMain, state.hSrcEdit, "Select Source Volume or Directory")
		case idBtnBrowseOut:
			browseFolder(state.hwndMain, state.hOutEdit, "Select Evidence Output Destination")
		case idBtnSelectAllDrives:
			toggleAllDrives()
		case idBtnStart:
			startAcquisition()
		}
		return 0
	case wmClose:
		procDestroyWindow.Call(uintptr(hwnd))
		return 0
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}

	r, _, _ := procDefWindowProcW.Call(uintptr(hwnd), msg, wParam, lParam)
	return r
}

func toggleAllDrives() {
	allChecked := true
	for _, chk := range state.driveChecks {
		if !isChecked(chk) {
			allChecked = false
			break
		}
	}
	targetState := bstChecked
	if allChecked {
		targetState = 0
	}
	for _, chk := range state.driveChecks {
		procSendMessageW.Call(uintptr(chk), bmSetCheck, uintptr(targetState), 0)
	}
}

func browseFolder(owner, hEdit syscall.Handle, title string) {
	titlePtr, _ := syscall.UTF16PtrFromString(title)
	displayName := make([]uint16, 260)
	bi := browseInfo{
		HwndOwner:      owner,
		PszDisplayName: &displayName[0],
		LpszTitle:      titlePtr,
		UlFlags:        0x00000001 | 0x00000040, // BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE
	}

	pidl, _, _ := procSHBrowseForFolderW.Call(uintptr(unsafe.Pointer(&bi)))
	if pidl != 0 {
		pathBuf := make([]uint16, 260)
		r, _, _ := procSHGetPathFromIDListW.Call(pidl, uintptr(unsafe.Pointer(&pathBuf[0])))
		if r != 0 {
			path := syscall.UTF16ToString(pathBuf)
			setWindowText(hEdit, path)
		}
	}
}

func startAcquisition() {
	state.mu.Lock()
	if state.running {
		state.mu.Unlock()
		return
	}

	// 1. Gather Selected Drive(s) and Custom Source
	var selectedSources []string
	for letter, chk := range state.driveChecks {
		if isChecked(chk) {
			selectedSources = append(selectedSources, letter)
		}
	}

	customPath := strings.TrimSpace(getWindowText(state.hSrcEdit))
	if customPath != "" {
		selectedSources = append(selectedSources, customPath)
	}

	if len(selectedSources) == 0 {
		state.mu.Unlock()
		showMsg(state.hwndMain, "Validation Error", "Please select at least one drive checkbox or specify a custom source path.")
		return
	}

	// 2. Output Destination Validation
	outDir := strings.TrimSpace(getWindowText(state.hOutEdit))
	if outDir == "" {
		state.mu.Unlock()
		showMsg(state.hwndMain, "Validation Error", "Please specify an Evidence Output destination folder.")
		return
	}

	// 3. Lawful Authorisation Confirmation
	isAuth := isChecked(state.hChkAuth)
	if !isAuth {
		state.mu.Unlock()
		showMsg(state.hwndMain, "Authorisation Required", "You must confirm lawful authorisation before proceeding.")
		return
	}

	// 4. Artefact Rules Selection
	var selectedRules []string
	for id, chk := range state.ruleChecks {
		if isChecked(chk) {
			selectedRules = append(selectedRules, id)
		}
	}
	if len(selectedRules) == 0 {
		state.mu.Unlock()
		showMsg(state.hwndMain, "Validation Error", "Please select at least one artefact rule.")
		return
	}

	state.running = true
	procEnableWindow.Call(uintptr(state.hBtnStart), 0)
	state.mu.Unlock()

	opts := cli.Options{
		Source:     strings.Join(selectedSources, ", "),
		Output:     outDir,
		Rules:      selectedRules,
		VSS:        isChecked(state.hChkVSS),
		NoDedup:    !isChecked(state.hChkDedup),
		CaseID:     getWindowText(state.hCaseEdit),
		Examiner:   getWindowText(state.hExamEdit),
		Notes:      getWindowText(state.hNotesEdit),
		Authorized: true,
		Lang:       state.tr.Lang(),
	}

	if isChecked(state.hChkMD5) {
		opts.ExtraHashes = append(opts.ExtraHashes, "md5")
	}
	if isChecked(state.hChkSHA1) {
		opts.ExtraHashes = append(opts.ExtraHashes, "sha1")
	}

	appendLog("\r\n--- Starting Forensic Acquisition ---")
	appendLog(fmt.Sprintf("Source(s): %s | Output: %s", opts.Source, opts.Output))
	appendLog(fmt.Sprintf("Rules: %s", strings.Join(opts.Rules, ", ")))

	// Run in background goroutine to keep Win32 UI responsive
	go func() {
		defer func() {
			state.mu.Lock()
			state.running = false
			procEnableWindow.Call(uintptr(state.hBtnStart), 1)
			state.mu.Unlock()
		}()

		guiLogger := logging.New(&guiLogWriter{}, logging.LevelInfo)
		err := engine.Run(&opts, guiLogger, state.tr)
		if err != nil {
			appendLog(fmt.Sprintf("\r\n[ERROR] Acquisition failed: %v", err))
			showMsg(state.hwndMain, "Acquisition Error", fmt.Sprintf("Acquisition failed:\n%v", err))
			return
		}

		appendLog("\r\n[SUCCESS] Acquisition finished and evidence sealed successfully!")
		showMsg(state.hwndMain, "Acquisition Complete", "Forensic acquisition completed successfully.\nEvidence archive and chain of custody generated.")
	}()
}

type guiLogWriter struct{}

func (w *guiLogWriter) Write(p []byte) (n int, err error) {
	appendLog(strings.ReplaceAll(string(p), "\n", "\r\n"))
	return len(p), nil
}

func appendLog(msg string) {
	if state.hLogEdit == 0 {
		return
	}
	text := msg + "\r\n"
	textPtr, _ := syscall.UTF16PtrFromString(text)

	// Append text to the end of edit box and scroll down
	lenText, _, _ := procGetWindowTextLength.Call(uintptr(state.hLogEdit))
	procSendMessageW.Call(uintptr(state.hLogEdit), emSetSel, lenText, lenText)
	procSendMessageW.Call(uintptr(state.hLogEdit), emReplaceSel, 0, uintptr(unsafe.Pointer(textPtr)))
}

func getWindowText(h syscall.Handle) string {
	lenText, _, _ := procGetWindowTextLength.Call(uintptr(h))
	if lenText == 0 {
		return ""
	}
	buf := make([]uint16, lenText+1)
	procGetWindowTextW.Call(uintptr(h), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return syscall.UTF16ToString(buf)
}

func setWindowText(h syscall.Handle, text string) {
	ptr, _ := syscall.UTF16PtrFromString(text)
	procSetWindowTextW.Call(uintptr(h), uintptr(unsafe.Pointer(ptr)))
}

func isChecked(h syscall.Handle) bool {
	r, _, _ := procSendMessageW.Call(uintptr(h), bmGetCheck, 0, 0)
	return r == bstChecked
}

func showMsg(owner syscall.Handle, title, msg string) {
	tPtr, _ := syscall.UTF16PtrFromString(title)
	mPtr, _ := syscall.UTF16PtrFromString(msg)
	// MB_OK | MB_ICONINFORMATION = 0x40
	procMessageBoxW.Call(uintptr(owner), uintptr(unsafe.Pointer(mPtr)), uintptr(unsafe.Pointer(tPtr)), 0x40)
}
