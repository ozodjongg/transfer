package transfer

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

type resumeState struct {
	Version      int    `json:"version"`
	TransferID   string `json:"transfer_id"`
	CipherOffset int64  `json:"cipher_offset"`
}

type receiverStaging struct {
	root       string
	contentDir string
	statePath  string
	state      resumeState
}

func openReceiverStaging(outputDir, room, transferID string, manifest Manifest, plans []chunkPlan, payloadSize int64) (*receiverStaging, int, error) {
	shortID := transferID
	if len(shortID) > 12 {
		shortID = shortID[:12]
	}
	root := filepath.Join(outputDir, ".protransfer-"+strings.ToLower(room)+"-"+shortID)
	content := filepath.Join(root, "content")
	statePath := filepath.Join(root, "state.json")

	st := &receiverStaging{root: root, contentDir: content, statePath: statePath}
	if err := os.MkdirAll(content, 0o700); err != nil {
		return nil, 0, err
	}

	state, exists, err := loadResumeState(statePath)
	if err != nil {
		return nil, 0, err
	}
	if !exists {
		state = resumeState{Version: 1, TransferID: transferID, CipherOffset: 0}
		if err := clearContentDir(content); err != nil {
			return nil, 0, err
		}
		if err := materializeDirectories(content, manifest); err != nil {
			return nil, 0, err
		}
		if err := saveResumeState(statePath, state); err != nil {
			return nil, 0, err
		}
	} else {
		if state.Version != 1 || state.TransferID != transferID {
			return nil, 0, errors.New("mavjud resume state boshqa transferga tegishli")
		}
		if state.CipherOffset < 0 || state.CipherOffset > payloadSize {
			return nil, 0, errors.New("resume state offset noto'g'ri")
		}
	}
	idx, err := chunkIndexForCipherOffset(plans, payloadSize, state.CipherOffset)
	if err != nil {
		return nil, 0, fmt.Errorf("resume state buzilgan: %w", err)
	}
	if err := restoreContentToPlanIndex(content, manifest, plans, idx); err != nil {
		return nil, 0, err
	}
	st.state = state
	return st, idx, nil
}

func loadResumeState(path string) (resumeState, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return resumeState{}, false, nil
	}
	if err != nil {
		return resumeState{}, false, err
	}
	var state resumeState
	if err := json.Unmarshal(data, &state); err != nil {
		return resumeState{}, false, fmt.Errorf("resume state JSON buzilgan: %w", err)
	}
	return state, true, nil
}

func saveResumeState(path string, state resumeState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	// Windows does not replace an existing destination with Rename.
	_ = os.Remove(path)
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func clearContentDir(content string) error {
	if err := os.RemoveAll(content); err != nil {
		return err
	}
	return os.MkdirAll(content, 0o700)
}

func materializeDirectories(content string, manifest Manifest) error {
	for _, e := range manifest.Entries {
		if e.Type != "dir" {
			continue
		}
		target, err := safeOutputPath(content, e.Path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(target, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// restoreContentToPlanIndex makes staging files exactly match the persisted
// chunk boundary. If the process/network died after writing a chunk but before
// state.json was committed, the extra bytes are safely truncated.
func restoreContentToPlanIndex(content string, manifest Manifest, plans []chunkPlan, idx int) error {
	if err := materializeDirectories(content, manifest); err != nil {
		return err
	}
	expected := make(map[int]int64)
	for i := 0; i < idx; i++ {
		p := plans[i]
		end := p.FileOffset + int64(p.PlainSize)
		if end > expected[p.ManifestIndex] {
			expected[p.ManifestIndex] = end
		}
	}
	for i, e := range manifest.Entries {
		if e.Type != "file" {
			continue
		}
		target, err := safeOutputPath(content, e.Path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		want := expected[i]
		f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return err
		}
		if err := f.Truncate(want); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (s *receiverStaging) commitOffset(offset int64) error {
	s.state.CipherOffset = offset
	return saveResumeState(s.statePath, s.state)
}

func verifyStaging(content string, manifest Manifest) error {
	for _, e := range manifest.Entries {
		if e.Type != "file" {
			continue
		}
		target, err := safeOutputPath(content, e.Path)
		if err != nil {
			return err
		}
		st, err := os.Stat(target)
		if err != nil {
			return fmt.Errorf("%s: %w", e.Path, err)
		}
		if st.Size() != e.Size {
			return fmt.Errorf("%s size mismatch: %d != %d", e.Path, st.Size(), e.Size)
		}
		sum, err := hashFile(target)
		if err != nil {
			return err
		}
		if !strings.EqualFold(sum, e.SHA256) {
			return fmt.Errorf("%s SHA-256 mismatch", e.Path)
		}
	}
	return nil
}

func manifestRoots(manifest Manifest) []string {
	set := map[string]struct{}{}
	for _, e := range manifest.Entries {
		root := strings.Split(e.Path, "/")[0]
		set[root] = struct{}{}
	}
	roots := make([]string, 0, len(set))
	for r := range set {
		roots = append(roots, r)
	}
	sort.Strings(roots)
	return roots
}

func finalizeStaging(s *receiverStaging, outputDir string, manifest Manifest) ([]string, error) {
	roots := manifestRoots(manifest)
	finalPaths := make([]string, 0, len(roots))
	for _, rootName := range roots {
		src, err := safeOutputPath(s.contentDir, rootName)
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(src); err != nil {
			return nil, fmt.Errorf("yakuniy root topilmadi %s: %w", rootName, err)
		}
		dst := uniquePath(filepath.Join(outputDir, filepath.FromSlash(rootName)))
		if err := os.Rename(src, dst); err != nil {
			return nil, err
		}
		finalPaths = append(finalPaths, dst)
	}
	_ = os.RemoveAll(s.root)
	return finalPaths, nil
}

func uniquePath(p string) string {
	if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
		return p
	}
	ext := filepath.Ext(p)
	base := strings.TrimSuffix(p, ext)
	// Directories may contain a dot; only treat ext as a file extension when
	// the existing source/destination is not a directory where possible.
	if st, err := os.Stat(p); err == nil && st.IsDir() {
		ext = ""
		base = p
	}
	for i := 1; ; i++ {
		candidate := fmt.Sprintf("%s (%d)%s", base, i, ext)
		if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
			return candidate
		}
	}
}

func topLevelForPath(p string) string {
	return strings.Split(path.Clean(p), "/")[0]
}
