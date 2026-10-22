package engine

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Cybsquatch/WAEaA/collector/internal/cli"
	"github.com/Cybsquatch/WAEaA/collector/internal/evidence"
	"github.com/Cybsquatch/WAEaA/collector/internal/i18n"
	"github.com/Cybsquatch/WAEaA/collector/internal/logging"
	"github.com/Cybsquatch/WAEaA/collector/internal/ntfs"
	"github.com/Cybsquatch/WAEaA/collector/internal/privilege"
	"github.com/Cybsquatch/WAEaA/collector/internal/rules"
	"github.com/Cybsquatch/WAEaA/collector/internal/vss"
	rulesfs "github.com/Cybsquatch/WAEaA/collector/rules"
)

// Run executes the forensic acquisition workflow according to opts.
func Run(opts *cli.Options, logger *logging.Logger, tr *i18n.Translator) error {
	startTime := time.Now().UTC()
	logger.Info("Starting WAEaA acquisition", "start_utc", startTime.Format(time.RFC3339))

	// Ensure forensic bypass privileges are enabled for reading locked files
	if err := privilege.EnableBackupPrivilege(); err != nil {
		logger.Debug("Could not enable backup privileges", "err", err)
	}

	// In-memory buffer to mirror the collection log for the evidence package
	var logBuf bytes.Buffer
	logger.AttachFile(&logBuf)

	// Gather host details
	sysInfo, err := GatherSystemInfo()
	if err != nil {
		logger.Warn("Failed to gather full system info", "err", err)
	}

	baseName := opts.ZipName
	if baseName == "" {
		baseName = sysInfo.Hostname
	}
	if !cli.ValidArchiveName(baseName) {
		baseName = "evidence_" + startTime.Format("20060102_150405")
	}

	// Load rule registry
	reg, err := rulesfs.LoadDefaultRegistry()
	if err != nil {
		return fmt.Errorf("engine: failed to load built-in rules: %w", err)
	}
	if opts.RulesDir != "" {
		if err := rulesfs.LoadCustomRulesDirectory(reg, opts.RulesDir); err != nil {
			logger.Warn("Failed loading custom rules directory", "dir", opts.RulesDir, "err", err)
		}
	}

	// Resolve targets
	resolvedRules, targets, err := reg.Resolve(opts.Rules, runtime.GOOS)
	if err != nil {
		return fmt.Errorf("engine: rule resolution failed: %w", err)
	}
	if len(targets) == 0 {
		return fmt.Errorf("engine: no targets found for rules %v on %s", opts.Rules, runtime.GOOS)
	}

	ruleIDs := make([]string, len(resolvedRules))
	for i, r := range resolvedRules {
		ruleIDs[i] = r.ID
	}
	logger.Info("Rules resolved successfully", "rule_count", len(resolvedRules), "target_count", len(targets))

	// Initialise archive sink
	var sink ArchiveSink
	if opts.NoZip {
		sink, err = NewFolderArchiveSink(opts.Output, baseName)
	} else {
		sink, err = NewZipArchiveSink(opts.Output, baseName)
	}
	if err != nil {
		return fmt.Errorf("engine: failed to initialise archive sink: %w", err)
	}

	manifest := evidence.NewManifest()
	dedupMap := make(map[string]string) // sha1 -> original archive path
	dedupCount := 0

	wantMD5 := contains(opts.ExtraHashes, "md5")
	wantSHA1 := contains(opts.ExtraHashes, "sha1")

	// Process each target definition
	for _, target := range targets {
		logger.Debug("Evaluating target", "path", target.Path, "mask", target.Mask, "recursive", target.Recursive)
		expandedPaths, err := ExpandPath(opts.Source, target.Path)
		if err != nil {
			logger.Trace("Path expansion error", "path", target.Path, "err", err)
			continue
		}

		for _, basePath := range expandedPaths {
			fi, err := os.Stat(basePath)
			if err != nil {
				logger.Trace("Target path not accessible", "path", basePath, "err", err)
				continue
			}

			if !fi.IsDir() {
				// Single file target
				if shouldCollectFile(basePath, fi, target, opts) {
					collectFile(basePath, fi, target, opts, sink, manifest, dedupMap, &dedupCount, wantMD5, wantSHA1, logger)
				}
				continue
			}

			// Directory target
			if target.Recursive {
				_ = filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
					if err != nil || info.IsDir() {
						return nil
					}
					if shouldCollectFile(path, info, target, opts) {
						collectFile(path, info, target, opts, sink, manifest, dedupMap, &dedupCount, wantMD5, wantSHA1, logger)
					}
					return nil
				})
			} else {
				entries, err := os.ReadDir(basePath)
				if err != nil {
					logger.Trace("Could not read directory", "dir", basePath, "err", err)
					continue
				}
				for _, entry := range entries {
					if entry.IsDir() {
						continue
					}
					info, err := entry.Info()
					if err != nil {
						continue
					}
					path := filepath.Join(basePath, entry.Name())
					if shouldCollectFile(path, info, target, opts) {
						collectFile(path, info, target, opts, sink, manifest, dedupMap, &dedupCount, wantMD5, wantSHA1, logger)
					}
				}
			}
		}
	}

	// Process Volume Shadow Copies if requested
	if opts.VSS {
		snapshots, err := vss.ListSnapshots(opts.Source)
		if err != nil {
			logger.Warn("Failed querying Volume Shadow Copies", "err", err)
		} else {
			logger.Info("Discovered Volume Shadow Copies", "count", len(snapshots))
			for _, snap := range snapshots {
				logger.Info("Processing Shadow Copy", "id", snap.ID, "device", snap.DeviceObject)
				vssSource := snap.DeviceObject + `\`
				for _, target := range targets {
					expandedPaths, err := ExpandPath(vssSource, target.Path)
					if err != nil {
						continue
					}
					vssTarget := target
					vssTarget.Comment = fmt.Sprintf("%s [VSS: %s]", target.Comment, snap.ID)
					for _, basePath := range expandedPaths {
						fi, err := os.Stat(basePath)
						if err != nil {
							continue
						}
						if !fi.IsDir() {
							if shouldCollectFile(basePath, fi, vssTarget, opts) {
								collectFile(basePath, fi, vssTarget, opts, sink, manifest, dedupMap, &dedupCount, wantMD5, wantSHA1, logger)
							}
							continue
						}
						if vssTarget.Recursive {
							_ = filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
								if err != nil || info.IsDir() {
									return nil
								}
								if shouldCollectFile(path, info, vssTarget, opts) {
									collectFile(path, info, vssTarget, opts, sink, manifest, dedupMap, &dedupCount, wantMD5, wantSHA1, logger)
								}
								return nil
							})
						} else {
							entries, err := os.ReadDir(basePath)
							if err != nil {
								continue
							}
							for _, entry := range entries {
								if entry.IsDir() {
									continue
								}
								info, err := entry.Info()
								if err != nil {
									continue
								}
								path := filepath.Join(basePath, entry.Name())
								if shouldCollectFile(path, info, vssTarget, opts) {
									collectFile(path, info, vssTarget, opts, sink, manifest, dedupMap, &dedupCount, wantMD5, wantSHA1, logger)
								}
							}
						}
					}
				}
			}
		}
	}

	endTime := time.Now().UTC()
	durationSec := endTime.Sub(startTime).Seconds()

	// Metadata serialization
	var csvBuf, jsonBuf bytes.Buffer
	_ = manifest.WriteCSV(&csvBuf)
	_ = manifest.WriteJSON(&jsonBuf)

	_ = sink.AddMetaFile("manifest.csv", csvBuf.Bytes())
	_ = sink.AddMetaFile("manifest.json", jsonBuf.Bytes())
	_ = sink.AddMetaFile("collection.log", logBuf.Bytes())

	// Preliminary Chain of Custody (hash of archive will be finalized)
	custodyRecord := &evidence.Record{
		CaseID:             opts.CaseID,
		Examiner:           opts.Examiner,
		Notes:              opts.Notes,
		Hostname:           sysInfo.Hostname,
		OS:                 sysInfo.OS,
		Platform:           sysInfo.Platform,
		Architecture:       sysInfo.Architecture,
		IPAddresses:        sysInfo.IPAddresses,
		MACAddresses:       sysInfo.MACAddresses,
		CollectorVersion:   sysInfo.BinaryPath,
		CollectorHash:      sysInfo.BinarySHA256,
		CollectionStartUTC: startTime.Format(time.RFC3339Nano),
		CollectionEndUTC:   endTime.Format(time.RFC3339Nano),
		DurationSeconds:    durationSec,
		TotalItems:         manifest.Count(),
		TotalBytes:         manifest.TotalBytes(),
		DeduplicatedItems:  dedupCount,
		ArchiveName:        baseName,
		RulesExecuted:      ruleIDs,
		Authorized:         opts.Authorized,
	}

	custodyHTML, _ := custodyRecord.GenerateHTML()
	var custodyJSON bytes.Buffer
	_ = custodyRecord.WriteJSON(&custodyJSON)

	_ = sink.AddMetaFile("chain_of_custody.html", custodyHTML)
	_ = sink.AddMetaFile("chain_of_custody.json", custodyJSON.Bytes())

	// Close sink and seal archive
	finalPath, archiveHash, err := sink.Close()
	if err != nil {
		return fmt.Errorf("engine: failed to seal archive: %w", err)
	}

	custodyRecord.ArchiveName = filepath.Base(finalPath)
	custodyRecord.ArchiveSHA256 = archiveHash

	// Also write sidecar chain_of_custody files next to the archive for analyst convenience
	sidecarDir := filepath.Dir(finalPath)
	sidecarBase := strings.TrimSuffix(filepath.Base(finalPath), filepath.Ext(finalPath))
	_ = os.WriteFile(filepath.Join(sidecarDir, sidecarBase+"_custody.json"), custodyJSON.Bytes(), 0644)
	if updatedHTML, err := custodyRecord.GenerateHTML(); err == nil {
		_ = os.WriteFile(filepath.Join(sidecarDir, sidecarBase+"_custody.html"), updatedHTML, 0644)
	}

	logger.Info("Acquisition completed successfully",
		"destination", finalPath,
		"sha256", archiveHash,
		"total_files", manifest.Count(),
		"deduplicated", dedupCount,
		"total_bytes", manifest.TotalBytes(),
		"duration_sec", fmt.Sprintf("%.2f", durationSec),
	)
	return nil
}

func shouldCollectFile(path string, info os.FileInfo, target rules.Target, opts *cli.Options) bool {
	name := info.Name()

	// Check target mask
	if target.Mask != "" && target.Mask != "*" {
		matched, err := rules.MatchPattern(target.Mask, name)
		if err != nil || !matched {
			return false
		}
	}

	// Check file size limits
	if opts.MaxFileSizeMB > 0 && !target.AlwaysCollect {
		maxBytes := opts.MaxFileSizeMB * 1024 * 1024
		if info.Size() > maxBytes {
			return false
		}
	}

	// Check include filters
	if len(opts.Include) > 0 {
		matchedAny := false
		for _, inc := range opts.Include {
			if m, err := rules.MatchPattern(inc, name); err == nil && m {
				matchedAny = true
				break
			}
		}
		if !matchedAny {
			return false
		}
	}

	// Check exclude filters
	for _, exc := range opts.Exclude {
		if m, err := rules.MatchPattern(exc, name); err == nil && m {
			return false
		}
	}

	return true
}

func collectFile(
	path string,
	info os.FileInfo,
	target rules.Target,
	opts *cli.Options,
	sink ArchiveSink,
	manifest *evidence.Manifest,
	dedupMap map[string]string,
	dedupCount *int,
	wantMD5, wantSHA1 bool,
	logger *logging.Logger,
) {
	relPath := makeArchiveRelativePath(path)

	// Attempt forensic open with backup semantics and full share flags
	f, err := ntfs.OpenForensic(path)
	if err != nil {
		// If raw NTFS reading is advised and target is $MFT, attempt raw volume stream
		if target.RawNTFS && strings.HasSuffix(strings.ToUpper(path), `\$MFT`) {
			vol := filepath.VolumeName(path)
			if vol == "" {
				vol = opts.Source
			}
			if vr, vErr := ntfs.OpenVolume(vol); vErr == nil {
				defer vr.Close()
				logger.Info("Acquiring $MFT via raw NTFS volume reader", "volume", vol)
				stream := vr.ReadInitialMFTStream(50000)
				collectRawStream(path, relPath, stream, target, sink, manifest, dedupMap, dedupCount, wantMD5, wantSHA1, logger)
				return
			}
		}
		logger.Debug("Failed opening file (may be locked)", "path", path, "err", err)
		return
	}
	defer f.Close()

	// Read content into buffer or hash stream
	hSHA256 := sha256.New()
	hSHA1 := sha1.New()
	var hMD5 io.Writer
	if wantMD5 {
		hMD5 = md5.New()
	}

	var writers []io.Writer
	writers = append(writers, hSHA256, hSHA1)
	if wantMD5 {
		writers = append(writers, hMD5)
	}

	mw := io.MultiWriter(writers...)
	var buf bytes.Buffer
	tee := io.TeeReader(f, mw)

	// Stream to buffer for writing into archive
	if _, err := io.Copy(&buf, tee); err != nil {
		logger.Debug("Read error while hashing", "path", path, "err", err)
		return
	}

	sha256Hex := hex.EncodeToString(hSHA256.Sum(nil))
	sha1Hex := hex.EncodeToString(hSHA1.Sum(nil))
	md5Hex := ""
	if wantMD5 {
		md5Hex = hex.EncodeToString(hMD5.(interface{ Sum([]byte) []byte }).Sum(nil))
	}

	nowUTC := time.Now().UTC().Format(time.RFC3339Nano)
	modTime := info.ModTime().UTC().Format(time.RFC3339)

	item := evidence.Item{
		SourcePath:   path,
		ArchivePath:  relPath,
		Size:         info.Size(),
		SHA256:       sha256Hex,
		ModifiedUTC:  modTime,
		AcquiredUTC:  nowUTC,
		RuleID:       target.Comment,
		Deduplicated: false,
	}
	if wantSHA1 {
		item.SHA1 = sha1Hex
	}
	if wantMD5 {
		item.MD5 = md5Hex
	}

	// De-duplication check
	if !opts.NoDedup {
		if original, exists := dedupMap[sha1Hex]; exists {
			item.Deduplicated = true
			item.OriginalArchivePath = original
			manifest.Add(item)
			*dedupCount++
			logger.Trace("Deduplicated file", "path", path, "original", original)
			return
		}
		dedupMap[sha1Hex] = relPath
	}

	// Write file to sink
	if err := sink.AddFile(relPath, &buf, info.Size(), info.ModTime()); err != nil {
		logger.Warn("Failed writing file to archive", "path", relPath, "err", err)
		return
	}

	manifest.Add(item)
	logger.Trace("Acquired file", "path", path, "size", info.Size(), "sha256", sha256Hex)
}

func collectRawStream(
	sourcePath, archiveRelPath string,
	r io.Reader,
	target rules.Target,
	sink ArchiveSink,
	manifest *evidence.Manifest,
	dedupMap map[string]string,
	dedupCount *int,
	wantMD5, wantSHA1 bool,
	logger *logging.Logger,
) {
	hSHA256 := sha256.New()
	hSHA1 := sha1.New()
	var hMD5 io.Writer
	if wantMD5 {
		hMD5 = md5.New()
	}

	var writers []io.Writer
	writers = append(writers, hSHA256, hSHA1)
	if wantMD5 {
		writers = append(writers, hMD5)
	}

	mw := io.MultiWriter(writers...)
	var buf bytes.Buffer
	tee := io.TeeReader(r, mw)

	n, err := io.Copy(&buf, tee)
	if err != nil && err != io.EOF {
		logger.Warn("Error copying raw stream", "path", sourcePath, "err", err)
		return
	}

	sha256Hex := hex.EncodeToString(hSHA256.Sum(nil))
	sha1Hex := hex.EncodeToString(hSHA1.Sum(nil))
	md5Hex := ""
	if wantMD5 {
		md5Hex = hex.EncodeToString(hMD5.(interface{ Sum([]byte) []byte }).Sum(nil))
	}

	now := time.Now().UTC()
	nowUTC := now.Format(time.RFC3339Nano)

	item := evidence.Item{
		SourcePath:   sourcePath,
		ArchivePath:  archiveRelPath,
		Size:         n,
		SHA256:       sha256Hex,
		ModifiedUTC:  now.Format(time.RFC3339),
		AcquiredUTC:  nowUTC,
		RuleID:       target.Comment + " [Raw NTFS]",
		Deduplicated: false,
	}
	if wantSHA1 {
		item.SHA1 = sha1Hex
	}
	if wantMD5 {
		item.MD5 = md5Hex
	}

	if err := sink.AddFile(archiveRelPath, &buf, n, now); err != nil {
		logger.Warn("Failed writing raw stream to archive", "path", archiveRelPath, "err", err)
		return
	}

	manifest.Add(item)
	logger.Info("Acquired raw NTFS stream", "path", sourcePath, "size", n, "sha256", sha256Hex)
}
// makeArchiveRelativePath standardises full paths to relative archive paths
// e.g. "C:\Windows\System32" -> "C/Windows/System32"
// or "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows" -> "VSS/HarddiskVolumeShadowCopy1/Windows"
func makeArchiveRelativePath(fullPath string) string {
	clean := filepath.Clean(fullPath)

	// Handle Volume Shadow Copy NT device paths
	const vssPrefix = `GLOBALROOT\Device\`
	if idx := strings.Index(clean, vssPrefix); idx >= 0 {
		sub := clean[idx+len(vssPrefix):]
		parts := strings.SplitN(sub, string(filepath.Separator), 2)
		if len(parts) == 2 {
			return filepath.ToSlash(filepath.Join("VSS", parts[0], parts[1]))
		}
		return filepath.ToSlash(filepath.Join("VSS", parts[0]))
	}

	vol := filepath.VolumeName(clean)
	if vol != "" {
		drive := strings.TrimSuffix(vol, ":")
		rest := clean[len(vol):]
		rest = strings.TrimPrefix(rest, string(filepath.Separator))
		return filepath.ToSlash(filepath.Join(drive, rest))
	}
	clean = strings.TrimPrefix(clean, string(filepath.Separator))
	return filepath.ToSlash(clean)
}

func contains(list []string, item string) bool {
	for _, s := range list {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}
