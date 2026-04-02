# HookSentry Changelog

## [0.5.1] - 2026-04-02

### Added
- **Output to file**: New `-o <file>` / `--output <file>` flag to redirect all output to a file
- **Aggregate report for multi-PID**: Aggregate report now auto-enabled when `-p` targets multiple processes (not just `-a`)


## [0.5] - 2026-03-31

### Added
- **Jump target resolution**: Shows absolute jump target address and target module for each hook
- **Trampoline following**: Follows one level of indirection when jump target is in unknown module
- **Multiple process targeting**: `-p` now accepts comma-separated PIDs and process names (e.g. `-p 1234,notepad.exe,5678`)
- **Module mapping**: Infrastructure to resolve addresses to their containing modules

### Changed
- **Output format**: 
  - Functions show as `module!function`
  - Jump targets display as `0xaddr @ module` or `0xaddr -> trampoline -> 0xaddr @ module`
- **False positive filtering**: Better detection of intra-module jumps (CFG, import forwarding)
- **Verbose control**: Hook details only with `-v`, summary always shown
- **Error handling**: Skip unreadable modules instead of aborting scan

### Fixed
- **"Task failed" error**: No longer aborts entire scan for individual module read failures
- **Memory leaks**: Proper cleanup of module map resources
