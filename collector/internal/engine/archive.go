package engine

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ArchiveSink defines the destination for collected artefacts and metadata.
type ArchiveSink interface {
	// AddFile writes an acquired file into the archive at the given relative path.
	AddFile(archiveRelPath string, r io.Reader, size int64, modTime time.Time) error
	// AddMetaFile writes a metadata file (manifest, log, chain of custody).
	AddMetaFile(name string, data []byte) error
	// Close finalises the sink, returning the output path and its SHA-256 hash.
	Close() (string, string, error)
}

// ZipArchiveSink writes files into a compressed .zip archive.
type ZipArchiveSink struct {
	finalPath string
	tmpPath   string
	file      *os.File
	zipWriter *zip.Writer
}

// NewZipArchiveSink creates a new ZIP sink in outDir named zipName + ".zip".
func NewZipArchiveSink(outDir, zipName string) (*ZipArchiveSink, error) {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return nil, fmt.Errorf("archive: failed to create output dir: %w", err)
	}

	finalPath := filepath.Join(outDir, zipName+".zip")
	tmpPath := filepath.Join(outDir, zipName+".tmp")

	f, err := os.Create(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("archive: failed to create temporary zip: %w", err)
	}

	zw := zip.NewWriter(f)
	return &ZipArchiveSink{
		finalPath: finalPath,
		tmpPath:   tmpPath,
		file:      f,
		zipWriter: zw,
	}, nil
}

// AddFile streams an acquired file into the ZIP archive.
func (z *ZipArchiveSink) AddFile(archiveRelPath string, r io.Reader, size int64, modTime time.Time) error {
	// Standardise path separators to forward slash in ZIP entries
	cleanPath := filepath.ToSlash(filepath.Clean(archiveRelPath))
	cleanPath = strings.TrimPrefix(cleanPath, "/")

	header := &zip.FileHeader{
		Name:     cleanPath,
		Method:   zip.Deflate,
		Modified: modTime.UTC(),
	}

	w, err := z.zipWriter.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("archive: failed to create zip entry for %s: %w", cleanPath, err)
	}

	if _, err := io.Copy(w, r); err != nil {
		return fmt.Errorf("archive: error writing data to zip entry %s: %w", cleanPath, err)
	}
	return nil
}

// AddMetaFile stores metadata files into a _meta folder in the ZIP.
func (z *ZipArchiveSink) AddMetaFile(name string, data []byte) error {
	entryName := filepath.ToSlash(filepath.Join("_meta", name))
	header := &zip.FileHeader{
		Name:     entryName,
		Method:   zip.Deflate,
		Modified: time.Now().UTC(),
	}
	w, err := z.zipWriter.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// Close flushes the ZIP, renames it to its final destination and computes its SHA-256.
func (z *ZipArchiveSink) Close() (string, string, error) {
	if err := z.zipWriter.Close(); err != nil {
		_ = z.file.Close()
		_ = os.Remove(z.tmpPath)
		return "", "", fmt.Errorf("archive: failed to close zip writer: %w", err)
	}
	if err := z.file.Close(); err != nil {
		_ = os.Remove(z.tmpPath)
		return "", "", fmt.Errorf("archive: failed to close file: %w", err)
	}

	// Rename .tmp to final .zip
	// If final destination exists, rename with timestamp suffix to never overwrite
	dest := z.finalPath
	if _, err := os.Stat(dest); err == nil {
		ts := time.Now().UTC().Format("20060102_150405")
		ext := filepath.Ext(dest)
		base := strings.TrimSuffix(dest, ext)
		dest = fmt.Sprintf("%s_%s%s", base, ts, ext)
	}

	if err := os.Rename(z.tmpPath, dest); err != nil {
		return "", "", fmt.Errorf("archive: failed to rename archive to %s: %w", dest, err)
	}

	// Calculate SHA-256 of final archive
	finalF, err := os.Open(dest)
	if err != nil {
		return dest, "", err
	}
	defer finalF.Close()

	h := sha256.New()
	if _, err := io.Copy(h, finalF); err != nil {
		return dest, "", err
	}
	hashStr := hex.EncodeToString(h.Sum(nil))

	// Write sidecar .sha256 file
	sidecarPath := dest + ".sha256"
	sidecarContent := fmt.Sprintf("%s  %s\n", hashStr, filepath.Base(dest))
	_ = os.WriteFile(sidecarPath, []byte(sidecarContent), 0644)

	return dest, hashStr, nil
}

// FolderArchiveSink writes files directly to a folder (used when --no-zip is set).
type FolderArchiveSink struct {
	rootPath string
}

// NewFolderArchiveSink creates a folder-based sink.
func NewFolderArchiveSink(outDir, folderName string) (*FolderArchiveSink, error) {
	rootPath := filepath.Join(outDir, folderName)
	if _, err := os.Stat(rootPath); err == nil {
		ts := time.Now().UTC().Format("20060102_150405")
		rootPath = fmt.Sprintf("%s_%s", rootPath, ts)
	}
	if err := os.MkdirAll(rootPath, 0755); err != nil {
		return nil, err
	}
	return &FolderArchiveSink{rootPath: rootPath}, nil
}

func (f *FolderArchiveSink) AddFile(archiveRelPath string, r io.Reader, size int64, modTime time.Time) error {
	dest := filepath.Join(f.rootPath, archiveRelPath)
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, r); err != nil {
		return err
	}
	_ = os.Chtimes(dest, modTime, modTime)
	return nil
}

func (f *FolderArchiveSink) AddMetaFile(name string, data []byte) error {
	metaDir := filepath.Join(f.rootPath, "_meta")
	if err := os.MkdirAll(metaDir, 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(metaDir, name), data, 0644)
}

func (f *FolderArchiveSink) Close() (string, string, error) {
	return f.rootPath, "DIRECTORY", nil
}
