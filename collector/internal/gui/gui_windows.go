//go:build windows

package gui

import (
	"fmt"
	"os"
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

	procRegisterClassExW     = user32.NewProc("RegisterClassExW")
	procCreateWindowExW      = user32.NewProc("CreateWindowExW")
	procDefWindowProcW       = user32.NewProc("DefWindowProcW")
	procDestroyWindow        = user32.NewProc("DestroyWindow")
	procPostQuitMessage      = user32.NewProc("PostQuitMessage")
	procShowWindow           = user32.NewProc("ShowWindow")
	procUpdateWindow         = user32.NewProc("UpdateWindow")
	procGetMessageW          = user32.NewProc("GetMessageW")
	procTranslateMessage     = user32.NewProc("TranslateMessage")
	procDispatchMessageW     = user32.NewProc("DispatchMessageW")
	procSendMessageW         = user32.NewProc("SendMessageW")
	procSetWindowTextW       = user32.NewProc("SetWindowTextW")
	procGetWindowTextW       = user32.NewProc("GetWindowTextW")
	procGetWindowTextLength  = user32.NewProc("GetWindowTextLengthW")
	procEnableWindow         = user32.NewProc("EnableWindow")
	procMessageBoxW          = user32.NewProc("MessageBoxW")
	procGetStockObject       = gdi32.NewProc("GetStockObject")
	procGetModuleHandleW     = kernel32.NewProc("GetModuleHandleW")
	procSHBrowseForFolderW   = shell32.NewProc("SHBrowseForFolderW")
	procSHGetPathFromIDListW = shell32.NewProc("SHGetPathFromIDListW")
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
	wmCommand      = 0x0111
	wmSetFont      = 0x0030
	defaultGuiFont = 17 // DEFAULT_GUI_FONT

	emSetSel     = 0x00B1
	emReplaceSel = 0x00C2
)

// Control IDs
const (
	idBtnBrowseSrc = 101
	idBtnBrowseOut = 102
	idBtnStart     = 103
	idChkAuth      = 104
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

	// Rule checkboxes map rule ID -> hwnd
	ruleChecks map[string]syscall.Handle
	tr         *i18n.Translator
	running    bool
}

var state guiState

// Run starts the native Windows GUI.
func Run() int {
	state.tr = i18n.MustNew(i18n.Detect())
	state.ruleChecks = make(map[string]syscall.Handle)

	hInstance, _, _ := procGetModuleHandleW.Call(0)
	className, _ := syscall.UTF16PtrFromString("WAEaA_Collector_Window")
	title, _ := syscall.UTF16PtrFromString(fmt.Sprintf("%s - Forensic Triage %s", version.Name, version.Version))

	wcex := wndClassEx{
		Size:       uint32(unsafe.Sizeof(wndClassEx{})),
		Style:      0x0003, // CS_HREDRAW | CS_VREDRAW
		WndProc:    syscall.NewCallback(windowProc),
		Instance:   syscall.Handle(hInstance),
		Cursor:     0,
		Background: 16, // COLOR_BTNFACE + 1
		ClassName:  className,
	}

	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wcex)))

	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(title)),
		wsOverlappedWindow|wsVisible,
		100, 100, 920, 720,
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
	var msg struct {
		Hwnd    syscall.Handle
		Message uint32
		WParam  uintptr
		LParam  uintptr
		Time    uint32
		Pt      struct{ X, Y int32 }
	}

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
	createCtrl("BUTTON", " Acquisition Scope ", bsGroupBox, 15, 10, 875, 95, 0)
	createCtrl("STATIC", "Source Volume:", 0, 30, 35, 120, 20, 0)
	sysDrive := os.Getenv("SystemDrive")
	if sysDrive == "" {
		sysDrive = "C:"
	}
	state.hSrcEdit = createCtrl("EDIT", sysDrive+`\`, wsBorder|esLeft, 150, 32, 600, 24, 0)
	createCtrl("BUTTON", "Browse...", bsPushButton, 760, 32, 110, 24, idBtnBrowseSrc)

	createCtrl("STATIC", "Evidence Output:", 0, 30, 68, 120, 20, 0)
	state.hOutEdit = createCtrl("EDIT", "", wsBorder|esLeft, 150, 65, 600, 24, 0)
	createCtrl("BUTTON", "Browse...", bsPushButton, 760, 65, 110, 24, idBtnBrowseOut)

	// 2. Forensic Artefact Rules Group
	createCtrl("BUTTON", " Artefact Rules Selection ", bsGroupBox, 15, 115, 530, 225, 0)

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
		{"win.browser_history", "Browser History & Downloads (Chrome, Edge, Firefox)"},
		{"win.filesystem_mft", "NTFS Metadata ($MFT, $LogFile, $UsnJrnl)"},
	}

	colX := 30
	rowY := 140
	for i, r := range ruleList {
		chk := createCtrl("BUTTON", r.label, bsAutoCheckBox, colX, rowY, 240, 22, 0)
		if r.id == "triage" {
			procSendMessageW.Call(uintptr(chk), bmSetCheck, bstChecked, 0)
		}
		state.ruleChecks[r.id] = chk
		rowY += 26
		if i == 5 {
			colX = 285
			rowY = 140
		}
	}

	// 3. Acquisition Options Group
	createCtrl("BUTTON", " Forensic Options ", bsGroupBox, 560, 115, 330, 225, 0)
	state.hChkVSS = createCtrl("BUTTON", "Process Volume Shadow Copies (VSS)", bsAutoCheckBox, 580, 140, 300, 22, 0)
	state.hChkDedup = createCtrl("BUTTON", "De-duplication Enabled (SHA-1)", bsAutoCheckBox, 580, 170, 300, 22, 0)
	procSendMessageW.Call(uintptr(state.hChkDedup), bmSetCheck, bstChecked, 0)

	state.hChkMD5 = createCtrl("BUTTON", "Calculate MD5 hash", bsAutoCheckBox, 580, 200, 300, 22, 0)
	state.hChkSHA1 = createCtrl("BUTTON", "Calculate SHA-1 hash", bsAutoCheckBox, 580, 230, 300, 22, 0)

	// 4. Chain of Custody & Authorisation
	createCtrl("BUTTON", " Chain of Custody & Authorisation ", bsGroupBox, 15, 350, 875, 110, 0)
	createCtrl("STATIC", "Case Identifier:", 0, 30, 375, 110, 20, 0)
	state.hCaseEdit = createCtrl("EDIT", "", wsBorder|esLeft, 145, 372, 280, 24, 0)

	createCtrl("STATIC", "Examiner:", 0, 450, 375, 90, 20, 0)
	state.hExamEdit = createCtrl("EDIT", "", wsBorder|esLeft, 545, 372, 325, 24, 0)

	createCtrl("STATIC", "Notes / Scope:", 0, 30, 408, 110, 20, 0)
	state.hNotesEdit = createCtrl("EDIT", "", wsBorder|esLeft, 145, 405, 725, 24, 0)

	state.hChkAuth = createCtrl("BUTTON", "AUTHORISATION CONFIRMATION: I confirm explicit, lawful authorisation to collect forensic artefacts from this host.", bsAutoCheckBox, 30, 434, 840, 20, idChkAuth)

	// 5. Execution Button
	state.hBtnStart = createCtrl("BUTTON", "START FORENSIC ACQUISITION", bsPushButton, 15, 470, 875, 40, idBtnStart)

	// 6. Live Log Output
	createCtrl("STATIC", "Live Acquisition Log:", 0, 15, 520, 300, 18, 0)
	state.hLogEdit = createCtrl("EDIT", "", wsBorder|esLeft|esMultiline|esAutoVScroll|esReadOnly|wsVScroll, 15, 540, 875, 125, 0)

	appendLog("WAEaA Forensic Collector initialized. Administrative privileges active.\r\nSelect source, destination and rules, then confirm authorisation to start.")
}

func windowProc(hwnd syscall.Handle, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case wmCommand:
		id := int(wParam & 0xFFFF)
		switch id {
		case idBtnBrowseSrc:
			browseFolder(state.hwndMain, state.hSrcEdit, "Select Source Volume or Directory")
		case idBtnBrowseOut:
			browseFolder(state.hwndMain, state.hOutEdit, "Select Evidence Output Destination")
		case idBtnStart:
			startAcquisition()
		}
		return 0
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}

	r, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
	return r
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

	// Validation
	outDir := getWindowText(state.hOutEdit)
	if strings.TrimSpace(outDir) == "" {
		state.mu.Unlock()
		showMsg(state.hwndMain, "Validation Error", "Please specify an Evidence Output destination.")
		return
	}

	isAuth := isChecked(state.hChkAuth)
	if !isAuth {
		state.mu.Unlock()
		showMsg(state.hwndMain, "Authorisation Required", "You must confirm lawful authorisation before proceeding.")
		return
	}

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
		Source:     getWindowText(state.hSrcEdit),
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
	appendLog(fmt.Sprintf("Source: %s | Output: %s", opts.Source, opts.Output))
	appendLog(fmt.Sprintf("Rules: %s", strings.Join(opts.Rules, ", ")))

	// Run in background goroutine to keep UI responsive
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
