// Module github.com/Cybsquatch/WAEaA/collector contains the WAEaA artefact
// collector for Windows and Linux.
//
// The "go" directive is deliberately pinned to 1.20: it is the last Go release
// able to produce binaries that run on Windows 7 / Server 2008 R2, and the
// legacy build (waeaa-legacy.exe) is compiled with that toolchain. Do not use
// language features or standard-library APIs introduced after Go 1.20
// (e.g. log/slog, min/max builtins, slices/maps packages, range-over-int).
module github.com/Cybsquatch/WAEaA/collector

go 1.20

require gopkg.in/yaml.v3 v3.0.1 // indirect
