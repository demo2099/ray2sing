package ray2sing

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// crashLogDir optionally overrides where ECH crash dumps are written. The host
// (hcore) can call SetCrashLogDir(sWorkingPath) during setup so the file lands
// in the core's data folder next to box.log / stderr.log. When empty, the
// process working directory is used — hcore chdir()s to sWorkingPath before any
// config is parsed, so this still resolves to the right place in production.
var crashLogDir string

// SetCrashLogDir directs ECH crash dumps to a known location. Safe to call once
// at setup; the value is only ever read at crash time.
func SetCrashLogDir(dir string) {
	if dir != "" {
		crashLogDir = dir
	}
}

func echCrashLogPath() string {
	dir := crashLogDir
	if dir == "" {
		dir = "."
	}
	return filepath.Join(dir, "data", "ech-crash.log")
}

// writeCrashLog persists a recovered panic from a background ECH goroutine.
//
// Background-goroutine panics in the in-process gomobile core abort the whole
// process with no tombstone and no Go stack in logcat — which is exactly the
// "enabling a node sometimes flash-closes the app" symptom. Wrapping the ECH
// fetch/refresh goroutines in recover() stops the crash; this routine makes the
// otherwise-invisible reason diagnosable by writing the stack to disk.
//
// Each crash is appended (not overwritten) so a recurring fault leaves a
// history, and the file is opened with O_CREATE so it appears on first failure.
func writeCrashLog(scope string, errStr string, stack []byte) {
	path := echCrashLogPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fmt.Printf("[ray2sing] ECH: could not create crash log dir for %s: %v\n", path, err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fmt.Printf("[ray2sing] ECH: could not open crash log %s: %v\n", path, err)
		return
	}
	defer f.Close()
	ts := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(f, "=== ECH panic recovered at %s (scope: %s) ===\n", ts, scope)
	fmt.Fprintf(f, "error: %s\n", errStr)
	f.Write(stack)
	f.WriteString("\n")
	fmt.Printf("[ray2sing] ECH: recovered panic in %s; stack appended to %s\n", scope, path)
}
