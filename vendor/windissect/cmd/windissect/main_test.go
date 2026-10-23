package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSymbolKeyUsesHexAge(t *testing.T) {
	got := symbolKey("00112233445566778899AABBCCDDEEFF", 0xA)
	if got != "00112233445566778899AABBCCDDEEFFA" {
		t.Fatalf("unexpected symbol key: %s", got)
	}
}

func TestSafePDBNameStripsBuildPath(t *testing.T) {
	got, err := safePDBName(`D:\build\obj\dwmcore.pdb`)
	if err != nil || got != "dwmcore.pdb" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestSafePDBNameRejectsNonPDB(t *testing.T) {
	if _, err := safePDBName("payload.exe"); err == nil {
		t.Fatal("expected non-PDB name to be rejected")
	}
}

func TestFixGuidLegacyEncodingUsesHexAge(t *testing.T) {
	got := fixGuid("00112233445566778899AABBCCDDEEFF10")
	if got != "33221100554477668899AABBCCDDEEFFA" {
		t.Fatalf("unexpected legacy key: %s", got)
	}
}

func TestReplaceFileOverwritesExistingDestination(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "new.json")
	destination := filepath.Join(dir, "canonical.json")
	if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replaceFile(source, destination); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "new" {
		t.Fatalf("unexpected replacement contents: %q", contents)
	}
	if _, err := os.Stat(destination + ".previous"); !os.IsNotExist(err) {
		t.Fatalf("backup was not removed: %v", err)
	}
}

func TestInstalledNotepadPackageCanBeResolved(t *testing.T) {
	programFiles := os.Getenv("ProgramFiles")
	root := filepath.Join(programFiles, "WindowsApps")
	installed := resolveTargetPath(targetSpec{File: "Notepad.exe", Source: "notepad-app-x64"}, os.Getenv("SystemRoot"), t.TempDir())
	if installed == "" {
		t.Skip("modern Notepad x64 package is not installed")
	}
	got := resolveTargetPath(targetSpec{File: "Notepad.exe", Source: "notepad-app-x64"}, os.Getenv("SystemRoot"), t.TempDir())
	if got == "" {
		t.Fatalf("installed Notepad did not resolve from %q", root)
	}
}

// A shallow corpus entry is indistinguishable from a deep one by hash: the
// binary did not change, only how far it was taken. The whole taskbar group
// was reused this way once, finishing a deep run in zero seconds.
func TestShallowResultDoesNotSatisfyDeepRun(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "target.dll")
	if err := os.WriteFile(binary, []byte("MZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	ir := filepath.Join(dir, "target.ir.json")
	if err := os.WriteFile(ir, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	hash, err := fileSHA256(binary)
	if err != nil {
		t.Fatal(err)
	}
	shallowEntry := corpusResult{
		Status: "verified-pdb",
		IR:     ir,
		SHA256: hash,
		Depth:  depthShallow,
	}

	if !reusableResult(shallowEntry, binary, true) {
		t.Fatal("a shallow entry should still satisfy a shallow run")
	}
	if reusableResult(shallowEntry, binary, false) {
		t.Fatal("a shallow entry must not satisfy a deep run")
	}

	// Entries written before depth was recorded read as shallow, which is
	// what the first taskbar pull actually was.
	legacy := shallowEntry
	legacy.Depth = ""
	if reusableResult(legacy, binary, false) {
		t.Fatal("a depth-less legacy entry must not satisfy a deep run")
	}

	deepEntry := shallowEntry
	deepEntry.Depth = depthFull
	if !reusableResult(deepEntry, binary, false) {
		t.Fatal("a deep entry should satisfy a deep run")
	}
}

// The shape of the record that has been silently passing: a PDB resolved, the
// IR is well-formed JSON, and there is nothing in it. The published ReWindows
// taskbar build is exactly this - 3 symbols, 0 classes.
func TestGateRejectsEmptyExtraction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.json")
	body := `{"pdb_present":true,"symbols":3,"functions":0,"vtables":0,"classes":0}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := gateCompleteness(path, "taskbar.dll"); err == nil {
		t.Fatal("expected an empty extraction to be rejected")
	}
}

// Classes are 0 on a complete extraction too - they come from the later
// semantic stage - so the gate must not key on them.
func TestGateAcceptsRealExtractionWithZeroClasses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.json")
	body := `{"pdb_present":true,"symbols":206365,"functions":48066,"vtables":16107,"classes":0}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := gateCompleteness(path, "Microsoft.UI.Xaml.dll"); err != nil {
		t.Fatalf("rejected a complete extraction: %v", err)
	}
}

// A module with no PDB legitimately yields few symbols; that is unavailable,
// not a failed extraction, and must not be failed here.
func TestGateIgnoresTargetsWithoutPDB(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.json")
	body := `{"pdb_present":false,"symbols":2,"functions":0,"vtables":0}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := gateCompleteness(path, "vendor.dll"); err != nil {
		t.Fatalf("failed a target that never had symbols to begin with: %v", err)
	}
}

// A missing summary is not evidence of failure.
func TestGateIsSilentWithoutInventory(t *testing.T) {
	if err := gateCompleteness(filepath.Join(t.TempDir(), "absent.json"), "x.dll"); err != nil {
		t.Fatalf("absence of a summary failed the target: %v", err)
	}
}
