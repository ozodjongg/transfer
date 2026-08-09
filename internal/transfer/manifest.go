package transfer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const (
	manifestVersion  = 1
	defaultChunkSize = 512 * 1024 // 512 KiB: good progress/resume granularity
	maxManifestItems = 12000
)

type Manifest struct {
	Version   int             `json:"version"`
	ChunkSize int             `json:"chunk_size"`
	TotalSize int64           `json:"total_size"`
	Entries   []ManifestEntry `json:"entries"`
}

type ManifestEntry struct {
	Path   string `json:"path"`
	Type   string `json:"type"` // file | dir
	Size   int64  `json:"size,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

type sourceFile struct {
	ManifestIndex int
	ManifestPath  string
	LocalPath     string
	Size          int64
}

type chunkPlan struct {
	Index         uint64
	ManifestIndex int
	ManifestPath  string
	LocalPath     string
	FileOffset    int64
	PlainSize     int
	CipherOffset  int64
	CipherSize    int64
	PlainBefore   int64
}

func buildManifest(inputs []string) (Manifest, []sourceFile, error) {
	if len(inputs) == 0 {
		return Manifest{}, nil, errors.New("kamida bitta file yoki folder kerak")
	}
	manifest := Manifest{Version: manifestVersion, ChunkSize: defaultChunkSize}
	var sources []sourceFile
	rootNames := map[string]struct{}{}

	fmt.Println("[i] Fayl/folderlar skan qilinmoqda va SHA-256 hisoblanmoqda...")

	for _, input := range inputs {
		input = strings.TrimSpace(input)
		if input == "" {
			return Manifest{}, nil, errors.New("bo'sh path berildi")
		}
		abs, err := filepath.Abs(input)
		if err != nil {
			return Manifest{}, nil, err
		}
		info, err := os.Lstat(abs)
		if err != nil {
			return Manifest{}, nil, fmt.Errorf("%s: %w", input, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return Manifest{}, nil, fmt.Errorf("symlink yuborilmaydi: %s", input)
		}
		root := filepath.Base(filepath.Clean(abs))
		if root == "." || root == string(filepath.Separator) || root == "" {
			return Manifest{}, nil, fmt.Errorf("noto'g'ri root nomi: %s", input)
		}
		key := strings.ToLower(root)
		if _, exists := rootNames[key]; exists {
			return Manifest{}, nil, fmt.Errorf("bir xil root nomi takrorlangan: %s", root)
		}
		rootNames[key] = struct{}{}

		if info.IsDir() {
			err = filepath.WalkDir(abs, func(current string, d os.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if len(manifest.Entries) >= maxManifestItems {
					return fmt.Errorf("juda ko'p element: limit %d", maxManifestItems)
				}
				if d.Type()&os.ModeSymlink != 0 {
					return fmt.Errorf("symlink yuborilmaydi: %s", current)
				}
				rel, err := filepath.Rel(abs, current)
				if err != nil {
					return err
				}
				manifestPath := root
				if rel != "." {
					manifestPath = path.Join(filepath.ToSlash(root), filepath.ToSlash(rel))
				}
				if err := validateManifestPath(manifestPath); err != nil {
					return err
				}
				if d.IsDir() {
					manifest.Entries = append(manifest.Entries, ManifestEntry{Path: manifestPath, Type: "dir"})
					return nil
				}
				fi, err := d.Info()
				if err != nil {
					return err
				}
				if !fi.Mode().IsRegular() {
					return fmt.Errorf("faqat regular file yuboriladi: %s", current)
				}
				sum, err := hashFile(current)
				if err != nil {
					return err
				}
				idx := len(manifest.Entries)
				manifest.Entries = append(manifest.Entries, ManifestEntry{Path: manifestPath, Type: "file", Size: fi.Size(), SHA256: sum})
				sources = append(sources, sourceFile{ManifestIndex: idx, ManifestPath: manifestPath, LocalPath: current, Size: fi.Size()})
				manifest.TotalSize += fi.Size()
				return nil
			})
			if err != nil {
				return Manifest{}, nil, err
			}
			continue
		}
		if !info.Mode().IsRegular() {
			return Manifest{}, nil, fmt.Errorf("faqat regular file yoki folder yuboriladi: %s", input)
		}
		manifestPath := root
		if err := validateManifestPath(manifestPath); err != nil {
			return Manifest{}, nil, err
		}
		sum, err := hashFile(abs)
		if err != nil {
			return Manifest{}, nil, err
		}
		idx := len(manifest.Entries)
		manifest.Entries = append(manifest.Entries, ManifestEntry{Path: manifestPath, Type: "file", Size: info.Size(), SHA256: sum})
		sources = append(sources, sourceFile{ManifestIndex: idx, ManifestPath: manifestPath, LocalPath: abs, Size: info.Size()})
		manifest.TotalSize += info.Size()
	}

	if len(manifest.Entries) == 0 {
		return Manifest{}, nil, errors.New("yuboriladigan element topilmadi")
	}
	return manifest, sources, nil
}

func hashFile(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buf, put := getTransferBuffer()
	defer put()
	if _, err := io.CopyBuffer(h, f, *buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func marshalManifest(m Manifest) ([]byte, error) {
	return json.Marshal(m)
}

func unmarshalManifest(data []byte) (Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("manifest noto'g'ri: %w", err)
	}
	if err := validateManifest(m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func validateManifest(m Manifest) error {
	if m.Version != manifestVersion {
		return errors.New("manifest version qo'llab-quvvatlanmaydi")
	}
	if m.ChunkSize < 64*1024 || m.ChunkSize > 4*1024*1024 {
		return errors.New("manifest chunk_size noto'g'ri")
	}
	if len(m.Entries) == 0 || len(m.Entries) > maxManifestItems {
		return errors.New("manifest entries soni noto'g'ri")
	}
	var total int64
	seen := map[string]struct{}{}
	for _, e := range m.Entries {
		if err := validateManifestPath(e.Path); err != nil {
			return err
		}
		key := strings.ToLower(e.Path)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("manifest path takrorlangan: %s", e.Path)
		}
		seen[key] = struct{}{}
		switch e.Type {
		case "dir":
			if e.Size != 0 || e.SHA256 != "" {
				return fmt.Errorf("dir metadata noto'g'ri: %s", e.Path)
			}
		case "file":
			if e.Size < 0 || len(e.SHA256) != 64 {
				return fmt.Errorf("file metadata noto'g'ri: %s", e.Path)
			}
			total += e.Size
			if total < 0 {
				return errors.New("manifest total overflow")
			}
		default:
			return fmt.Errorf("manifest entry type noto'g'ri: %s", e.Type)
		}
	}
	if total != m.TotalSize {
		return fmt.Errorf("manifest total_size mismatch: %d != %d", total, m.TotalSize)
	}
	return nil
}

func validateManifestPath(p string) error {
	if p == "" || strings.ContainsRune(p, '\x00') || strings.Contains(p, "\\") {
		return fmt.Errorf("xavfsiz bo'lmagan path: %q", p)
	}
	if strings.HasPrefix(p, "/") || path.IsAbs(p) {
		return fmt.Errorf("absolute path taqiqlangan: %q", p)
	}
	clean := path.Clean(p)
	if clean != p || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("path traversal taqiqlangan: %q", p)
	}
	if len(p) > 4096 {
		return errors.New("path juda uzun")
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("xavfsiz bo'lmagan path component: %q", p)
		}
		if runtime.GOOS == "windows" {
			if strings.ContainsAny(part, `<>:"|?*`) || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
				return fmt.Errorf("Windows uchun yaroqsiz file nomi: %q", part)
			}
		}
	}
	return nil
}

func buildChunkPlan(m Manifest, sources []sourceFile, overhead int) ([]chunkPlan, int64, error) {
	sourceByIndex := make(map[int]sourceFile, len(sources))
	for _, s := range sources {
		sourceByIndex[s.ManifestIndex] = s
	}
	var plans []chunkPlan
	var cipherOffset, plainBefore int64
	var chunkIndex uint64
	for i, e := range m.Entries {
		if e.Type != "file" || e.Size == 0 {
			continue
		}
		src := sourceByIndex[i]
		for off := int64(0); off < e.Size; {
			n := int64(m.ChunkSize)
			if remain := e.Size - off; remain < n {
				n = remain
			}
			plans = append(plans, chunkPlan{
				Index: chunkIndex, ManifestIndex: i, ManifestPath: e.Path,
				LocalPath: src.LocalPath, FileOffset: off, PlainSize: int(n),
				CipherOffset: cipherOffset, CipherSize: n + int64(overhead), PlainBefore: plainBefore,
			})
			cipherOffset += n + int64(overhead)
			plainBefore += n
			off += n
			chunkIndex++
		}
	}
	return plans, cipherOffset, nil
}

func chunkIndexForCipherOffset(plans []chunkPlan, payloadSize, offset int64) (int, error) {
	if offset < 0 || offset > payloadSize {
		return 0, fmt.Errorf("resume offset limitdan tashqarida: %d", offset)
	}
	if offset == payloadSize {
		return len(plans), nil
	}
	i := sort.Search(len(plans), func(i int) bool { return plans[i].CipherOffset >= offset })
	if i >= len(plans) || plans[i].CipherOffset != offset {
		return 0, fmt.Errorf("resume offset chunk boundary emas: %d", offset)
	}
	return i, nil
}

func plainDoneAtPlanIndex(plans []chunkPlan, idx int, total int64) int64 {
	if idx >= len(plans) {
		return total
	}
	if idx < 0 {
		return 0
	}
	return plans[idx].PlainBefore
}

func safeOutputPath(base, manifestPath string) (string, error) {
	if err := validateManifestPath(manifestPath); err != nil {
		return "", err
	}
	target := filepath.Join(base, filepath.FromSlash(manifestPath))
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", errors.New("output path staging papkadan chiqib ketmoqda")
	}
	return target, nil
}
