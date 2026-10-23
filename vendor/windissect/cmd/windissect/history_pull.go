package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Pull every historical build of a module and archive it.
//
// The fleet could only ever analyse what was installed on the machine running
// it, which is one build of each module. That makes a per-build archive
// impossible to populate and a cross-version diff impossible to run, which is
// the thing the archive exists for.
//
// Two public sources close that gap. Winbindex indexes every Windows binary by
// build, including the timestamp and virtual size that identify it. Microsoft's
// symbol server serves both the binary and its PDB keyed by exactly that pair -
// it is not only a symbol store, and it keeps builds long after they leave
// support. So the whole history of a module is fetchable without ever
// installing the Windows versions it came from.
//
// Everything after the download is unchanged: processDLL already fetches the
// PDB, extracts at full depth, runs the semantic projection and records the
// build into history.

const winbindexBase = "https://raw.githubusercontent.com/m417z/winbindex/gh-pages/data/by_filename_compressed"

type buildIdentity struct {
	// Key is the symbol-server identity: PE timestamp and SizeOfImage, the
	// pair Microsoft indexes both the binary and its PDB by.
	Key            string
	Version        string
	WindowsVersion string
	SHA256         string
	Size           int64
}

type winbindexEntry struct {
	FileInfo struct {
		Timestamp   *int64  `json:"timestamp"`
		VirtualSize *int64  `json:"virtualSize"`
		Size        int64   `json:"size"`
		Version     string  `json:"version"`
		SHA256      *string `json:"sha256"`
	} `json:"fileInfo"`
	WindowsVersions map[string]json.RawMessage `json:"windowsVersions"`
}

// winbindexIdentities lists every known build of a module, oldest first.
func winbindexIdentities(module string) ([]buildIdentity, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	var lastErr error
	// Winbindex filenames carry the casing Microsoft ships; try what we were
	// given, then lowercase, before giving up.
	for _, name := range []string{module + ".dll", strings.ToLower(module) + ".dll"} {
		url := fmt.Sprintf("%s/%s.json.gz", winbindexBase, name)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "windissect")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %s for %s", resp.Status, name)
			continue
		}
		zr, err := gzip.NewReader(resp.Body)
		if err != nil {
			resp.Body.Close()
			return nil, err
		}
		var raw map[string]winbindexEntry
		err = json.NewDecoder(zr).Decode(&raw)
		zr.Close()
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("decode %s: %w", name, err)
		}

		var out []buildIdentity
		for sha, entry := range raw {
			fi := entry.FileInfo
			// No timestamp or virtual size means no symbol-server key, and
			// therefore no way to fetch it. Winbindex knows of the file; it
			// cannot be retrieved.
			if fi.Timestamp == nil || fi.VirtualSize == nil {
				continue
			}
			versions := make([]string, 0, len(entry.WindowsVersions))
			for v := range entry.WindowsVersions {
				versions = append(versions, v)
			}
			sort.Strings(versions)
			id := buildIdentity{
				Key:     fmt.Sprintf("%08X%x", *fi.Timestamp, *fi.VirtualSize),
				Version: fi.Version,
				SHA256:  sha,
				Size:    fi.Size,
			}
			if len(versions) > 0 {
				id.WindowsVersion = versions[0]
			}
			out = append(out, id)
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].WindowsVersion != out[j].WindowsVersion {
				return out[i].WindowsVersion < out[j].WindowsVersion
			}
			return out[i].Version < out[j].Version
		})
		return out, nil
	}
	return nil, fmt.Errorf("no winbindex data for %s: %v", module, lastErr)
}

// downloadBinary fetches a PE from the symbol server by its identity key.
func downloadBinary(name, key, outPath string) error {
	url := fmt.Sprintf("%s/%s/%s/%s", strings.TrimRight(symbolServer, "/"), name, key, name)
	client := &http.Client{Timeout: 10 * time.Minute}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Microsoft-Symbol-Server/10.0.0.0")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %s", resp.Status)
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(outPath), ".bin-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// A symbol server that does not have a file still answers 200 with an
	// error page, so confirm this is actually a PE before keeping it.
	head, err := os.ReadFile(tmp.Name())
	if err != nil || len(head) < 2 || head[0] != 'M' || head[1] != 'Z' {
		return fmt.Errorf("not a PE image")
	}
	return os.Rename(tmp.Name(), outPath)
}

// historyPull archives every available build of each module.
func historyPull(modules []string, root, extractorPath string, limit int, skipExisting bool) error {
	probeDir := filepath.Join(root, "probe")
	irDir := filepath.Join(root, "ir")
	binDir := filepath.Join(root, "binaries")
	for _, d := range []string{probeDir, irDir, binDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}

	pulled, failed, skipped := 0, 0, 0
	start := time.Now()

	for _, module := range modules {
		ids, err := winbindexIdentities(module)
		if err != nil {
			fmt.Printf("[!] %s: %v\n", module, err)
			continue
		}
		fmt.Printf("\n=== %s: %d builds ===\n", module, len(ids))

		for i, id := range ids {
			if limit > 0 && pulled >= limit {
				fmt.Printf("\n[*] reached the limit of %d builds\n", limit)
				goto done
			}
			outputID := fmt.Sprintf("%s-%s", strings.ToLower(module), id.Key)
			if skipExisting {
				if _, err := os.Stat(filepath.Join(irDir, outputID+".json")); err == nil {
					skipped++
					continue
				}
			}

			binPath := filepath.Join(binDir, module+".dll")
			if err := downloadBinary(module+".dll", id.Key, binPath); err != nil {
				fmt.Printf("  [%d/%d] %s %s: %v\n", i+1, len(ids), id.WindowsVersion, id.Version, err)
				failed++
				continue
			}

			outcome, err := processDLL(binPath, outputID, probeDir, irDir, extractorPath, false)
			if err != nil {
				fmt.Printf("  [%d/%d] %s %s: %v\n", i+1, len(ids), id.WindowsVersion, id.Version, err)
				failed++
				os.Remove(binPath)
				continue
			}
			pulled++
			elapsed := time.Since(start).Seconds()
			fmt.Printf("  [%d/%d] %s %-26s pdb=%v  %d done, %.1fs each\n",
				i+1, len(ids), id.WindowsVersion, id.Version, outcome.PDBUsed,
				pulled, elapsed/float64(pulled))
			// The binary is reproducible from its key; the IR is the artefact.
			os.Remove(binPath)
		}
	}

done:
	fmt.Printf("\n%d pulled, %d failed, %d already present, %.1f min elapsed\n",
		pulled, failed, skipped, time.Since(start).Minutes())
	return nil
}
