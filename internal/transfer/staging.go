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
	"sync"
)

type resumeState struct {
	Version       int     `json:"version"`
	TransferID    string  `json:"transfer_id"`
	CipherOffsets []int64 `json:"cipher_offsets"`
}

type receiverStaging struct {
	mu         sync.Mutex
	root       string
	contentDir string
	statePath  string
	state      resumeState
}

func openReceiverStaging(outputDir, room, transferID string, manifest Manifest, plans []chunkPlan, payloadSize int64, streamSizesOpt ...[]int64) (*receiverStaging, int, error) {
	streamSizes := []int64{payloadSize}
	if len(streamSizesOpt) > 0 && len(streamSizesOpt[0]) > 0 {
		streamSizes = append([]int64(nil), streamSizesOpt[0]...)
	}
	var sum int64
	for _, n := range streamSizes {
		if n < 0 {
			return nil, 0, errors.New("negative stream payload size")
		}
		sum += n
	}
	if sum != payloadSize {
		return nil, 0, errors.New("stream payload sizes total payload bilan mos emas")
	}
	ranges := splitPlanRanges(plans, len(streamSizes))
	if len(ranges) != len(streamSizes) {
		return nil, 0, errors.New("stream range count mismatch")
	}
	for i := range ranges {
		if ranges[i].CipherSize != streamSizes[i] {
			return nil, 0, errors.New("stream payload size manifest chunk plan bilan mos emas")
		}
	}

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
		state = resumeState{Version: 2, TransferID: transferID, CipherOffsets: make([]int64, len(streamSizes))}
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
		if state.Version != 2 || state.TransferID != transferID {
			return nil, 0, errors.New("mavjud resume state boshqa transfer/protocolga tegishli")
		}
		if len(state.CipherOffsets) != len(streamSizes) {
			return nil, 0, errors.New("resume stream count original transfer bilan mos emas")
		}
		for i, off := range state.CipherOffsets {
			if off < 0 || off > streamSizes[i] {
				return nil, 0, errors.New("resume stream offset noto'g'ri")
			}
			if _, err := streamPlanIndexForOffset(plans, ranges[i], off); err != nil {
				return nil, 0, fmt.Errorf("resume state buzilgan: %w", err)
			}
		}
	}
	if err := restoreContentToStreamOffsets(content, manifest, plans, ranges, state.CipherOffsets); err != nil {
		return nil, 0, err
	}
	st.state = state
	firstIdx, err := streamPlanIndexForOffset(plans, ranges[0], state.CipherOffsets[0])
	if err != nil {
		return nil, 0, err
	}
	return st, firstIdx, nil
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
	ranges := []planRange{{Start: 0, End: len(plans)}}
	var off int64
	for i := 0; i < idx && i < len(plans); i++ {
		off += plans[i].CipherSize
	}
	return restoreContentToStreamOffsets(content, manifest, plans, ranges, []int64{off})
}

func restoreContentToStreamOffsets(content string, manifest Manifest, plans []chunkPlan, ranges []planRange, offsets []int64) error {
	if err := materializeDirectories(content, manifest); err != nil {
		return err
	}
	if len(ranges) != len(offsets) {
		return errors.New("restore stream count mismatch")
	}
	expected := make(map[int]int64)
	for streamID, r := range ranges {
		idx, err := streamPlanIndexForOffset(plans, r, offsets[streamID])
		if err != nil {
			return err
		}
		for i := r.Start; i < idx; i++ {
			p := plans[i]
			end := p.FileOffset + int64(p.PlainSize)
			if end > expected[p.ManifestIndex] {
				expected[p.ManifestIndex] = end
			}
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
	return s.commitStreamOffset(0, offset)
}

func (s *receiverStaging) commitStreamOffset(streamID int, offset int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if streamID < 0 || streamID >= len(s.state.CipherOffsets) {
		return errors.New("invalid resume stream id")
	}
	if offset < s.state.CipherOffsets[streamID] {
		return errors.New("resume stream offset orqaga ketishi mumkin emas")
	}
	s.state.CipherOffsets[streamID] = offset
	return saveResumeState(s.statePath, s.state)
}

func (s *receiverStaging) streamOffsets() []int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int64(nil), s.state.CipherOffsets...)
}

func (s *receiverStaging) streamOffset(streamID int) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if streamID < 0 || streamID >= len(s.state.CipherOffsets) {
		return 0
	}
	return s.state.CipherOffsets[streamID]
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
