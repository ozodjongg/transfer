package transfer

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// V7 uses four human-readable tokens. Each token is selected from a generated
// 4096-entry compound-word dictionary (64 prefixes × 64 suffixes), giving
// 12 bits per token / 48 bits total. A small routing slice selects the public
// rendezvous room; the remaining uncertainty is authenticated by PAKE. The
// phrase is never used directly as an encryption key.
var codePrefixes = [...]string{
	"amber", "aqua", "astro", "autumn", "azure", "berry", "blaze", "bloom",
	"blue", "bright", "cedar", "cherry", "cloud", "coral", "crystal", "dawn",
	"delta", "dream", "echo", "ember", "fern", "fire", "flora", "forest",
	"frost", "gold", "green", "harbor", "hazel", "honey", "ivory", "jade",
	"lake", "lemon", "light", "lunar", "mango", "maple", "mist", "moon",
	"moss", "night", "north", "ocean", "olive", "orbit", "pearl", "pine",
	"plum", "rain", "river", "rose", "ruby", "sand", "silver", "sky",
	"snow", "solar", "star", "stone", "sun", "velvet", "wave", "willow",
}

var codeSuffixes = [...]string{
	"bird", "brook", "castle", "comet", "creek", "crown", "dance", "field",
	"flame", "flower", "fox", "garden", "gate", "glow", "grove", "hill",
	"kite", "lamp", "leaf", "lion", "meadow", "mint", "mountain", "oak",
	"panda", "path", "peak", "pond", "rabbit", "ridge", "road", "rocket",
	"sail", "shell", "shore", "spark", "spring", "stream", "table", "tiger",
	"tower", "trail", "tree", "valley", "wind", "wing", "wolf", "wood",
	"world", "yard", "beacon", "bridge", "canyon", "harvest", "island", "lotus",
	"marble", "orchard", "ribbon", "shadow", "summit", "thunder", "voyage", "water",
}

var (
	codeWordSet   = buildCodeWordSet()
	codeWordIndex = buildCodeWordIndex()
)

func buildCodeWordSet() map[string]struct{} {
	out := make(map[string]struct{}, len(codePrefixes)*len(codeSuffixes))
	for _, p := range codePrefixes {
		for _, s := range codeSuffixes {
			w := p + s
			if _, exists := out[w]; exists {
				panic("duplicate generated transfer-code word: " + w)
			}
			out[w] = struct{}{}
		}
	}
	if len(out) != 4096 {
		panic(fmt.Sprintf("transfer-code dictionary has %d words, want 4096", len(out)))
	}
	return out
}

func buildCodeWordIndex() map[string]uint16 {
	out := make(map[string]uint16, 4096)
	for pi, p := range codePrefixes {
		for si, s := range codeSuffixes {
			out[p+s] = uint16(pi*len(codeSuffixes) + si)
		}
	}
	return out
}

func generateCodePhrase() (string, error) {
	words := make([]string, 4)
	for i := range words {
		pi, err := rand.Int(rand.Reader, big.NewInt(int64(len(codePrefixes))))
		if err != nil {
			return "", err
		}
		si, err := rand.Int(rand.Reader, big.NewInt(int64(len(codeSuffixes))))
		if err != nil {
			return "", err
		}
		words[i] = codePrefixes[pi.Int64()] + codeSuffixes[si.Int64()]
	}
	return strings.Join(words, "-"), nil
}

func normalizeCodePhrase(code string) (string, error) {
	code = strings.ToLower(strings.TrimSpace(code))
	// Accept a quoted "word word word word" form too, while always printing
	// the canonical dash-separated form.
	code = strings.Join(strings.Fields(code), "-")
	parts := strings.Split(code, "-")
	if len(parts) != 4 {
		return "", errors.New("transfer code 4 ta word formatida bo'lishi kerak: word-word-word-word")
	}
	for _, w := range parts {
		if _, ok := codeWordSet[w]; !ok {
			return "", fmt.Errorf("transfer code word noma'lum: %s", w)
		}
	}
	return strings.Join(parts, "-"), nil
}

func roomFromCodePhrase(code string) (string, error) {
	normalized, err := normalizeCodePhrase(code)
	if err != nil {
		return "", err
	}
	parts := strings.Split(normalized, "-")
	first := uint32(codeWordIndex[parts[0]])
	second := uint32(codeWordIndex[parts[1]])

	// The public rendezvous selector intentionally exposes only ~20 bits:
	// all 12 bits of word #1 plus the high 8 bits of word #2. The remaining
	// 4 bits of word #2 and all of words #3/#4 stay behind PAKE, yielding
	// ~28 bits of online-only PAKE uncertainty while keeping room collisions
	// negligible for a small relay. Crucially, the public room is NOT a
	// verifier for the complete four-word phrase.
	selector := (first << 8) | (second >> 4)
	raw := []byte{byte(selector >> 16), byte(selector >> 8), byte(selector)}
	h := sha256.New()
	_, _ = h.Write([]byte("pro-transfer/v7/room"))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(raw)
	sum := h.Sum(nil)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return enc.EncodeToString(sum[:10]), nil
}

func pakePassphraseFromCodePhrase(code string) (string, error) {
	normalized, err := normalizeCodePhrase(code)
	if err != nil {
		return "", err
	}
	parts := strings.Split(normalized, "-")
	// Word #1 is purely rendezvous material. Words #2-#4 authenticate the
	// PAKE; the room selector leaks only 8 of word #2's 12 index bits.
	return strings.Join(parts[1:], "-"), nil
}
