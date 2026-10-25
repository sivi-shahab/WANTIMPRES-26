// Package similarity finds registered confidential documents in text (spec §9.1 L3, §9.2, FR-CLS-1 "Source Code /
// IP"). Fingerprints are winnowed word shingles (Schleimer, Wilkerson, Aiken, "Winnowing", SIGMOD 2003): any run of
// at least Guarantee words shared verbatim with a registered document yields a shared fingerprint, however much
// other text surrounds it. That is what a leak looks like (an excerpt pasted into a prompt), and what MinHash or
// SimHash, which estimate whole-document resemblance, miss. Paraphrase is out of reach without an embedding model.
//
// Fingerprints are keyed with the tenant pepper (HMAC), so the stored set cannot be checked against guessed text
// without the key. Document text is never stored.
package similarity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"math"
	"sort"
	"unicode"
	"unicode/utf8"

	"wantimpres26/internal/detect"
)

const (
	K         = 5         // words per shingle
	W         = 4         // winnowing window, in shingles
	Guarantee = K + W - 1 // a shared run this many words long is always found
	// A hit needs MinShared shared fingerprints within Cluster consecutive fingerprints of the text (~40 words):
	// a copied passage of ~15+ words. Chance collisions between unrelated texts are scattered single fingerprints.
	MinShared = 3
	Cluster   = 16
	// MaxDocFreq: a fingerprint in this many registered documents is a template phrase (letterhead, standard
	// clauses), not evidence of one document, and is ignored when matching.
	MaxDocFreq = 3
	Type       = "CODE.CONFIDENTIAL_DOC"
)

type token struct {
	h          uint64 // FNV-1a of the lower-cased word
	start, end int
}

// tokens splits text into lower-cased letter/digit runs, so case, punctuation, whitespace and line breaks do not
// change fingerprints.
func tokens(s string) []token {
	var out []token
	start := -1
	var h uint64
	for i := 0; i <= len(s); {
		r, n := utf8.RuneError, 1
		if i < len(s) {
			r, n = utf8.DecodeRuneInString(s[i:])
		}
		if i < len(s) && (unicode.IsLetter(r) || unicode.IsDigit(r)) {
			if start < 0 {
				start, h = i, 14695981039346656037
			}
			var b [utf8.UTFMax]byte
			for _, c := range b[:utf8.EncodeRune(b[:], unicode.ToLower(r))] {
				h = (h ^ uint64(c)) * 1099511628211
			}
		} else if start >= 0 {
			out = append(out, token{h, start, i})
			start = -1
		}
		i += n
	}
	return out
}

type print struct {
	h    uint64 // keyed
	span [2]int // byte range of the shingle in the text
}

// prints winnows the shingle hashes of text and keys the selected ones.
func prints(key []byte, s string) []print {
	ts := tokens(s)
	if len(ts) < K {
		return nil
	}
	hs := make([]uint64, len(ts)-K+1)
	for i := range hs {
		h := uint64(14695981039346656037)
		for _, t := range ts[i : i+K] {
			h = (h ^ t.h) * 1099511628211
			h ^= h >> 29
		}
		hs[i] = h
	}
	mac := hmac.New(sha256.New, key)
	var out []print
	last := -1
	for lo := 0; ; lo++ {
		hi := min(lo+W, len(hs))
		m := lo
		for j := lo + 1; j < hi; j++ {
			if hs[j] <= hs[m] { // rightmost minimum
				m = j
			}
		}
		if m != last {
			last = m
			out = append(out, print{keyed(mac, hs[m]), [2]int{ts[m].start, ts[m+K-1].end}})
		}
		if hi == len(hs) {
			break
		}
	}
	return out
}

func keyed(m hash.Hash, h uint64) uint64 {
	m.Reset()
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], h)
	m.Write(b[:])
	var sum [sha256.Size]byte
	return binary.BigEndian.Uint64(m.Sum(sum[:0]))
}

// Fingerprints is the distinct keyed fingerprint set of a document, for registration.
func Fingerprints(key []byte, text string) []int64 {
	seen := map[uint64]bool{}
	out := []int64{}
	for _, p := range prints(key, text) {
		if !seen[p.h] {
			seen[p.h] = true
			out = append(out, int64(p.h))
		}
	}
	return out
}

// Doc is a registered document. Size is its fingerprint count.
type Doc struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Sensitivity string `json:"sensitivity"`
	Size        int    `json:"fingerprints"`
}

// Hit is one registered document found in a text. Containment is the share of the text's fingerprints that come
// from the document (1 = the text is all document); Coverage the share of the document present in the text. Span is
// the byte range from the first to the last shared shingle.
type Hit struct {
	Doc         Doc     `json:"doc"`
	Shared      int     `json:"shared"`
	Containment float64 `json:"containment"`
	Coverage    float64 `json:"coverage"`
	Span        [2]int  `json:"span_offsets"`
}

// Index is an immutable in-memory index; build it with Build.
// ponytail: whole corpus in memory per replica (~16 KB per 5k-word document); shard or move to a KV store past
// ~100k documents.
type Index struct {
	key  []byte
	docs []Doc
	post map[uint64][]int32 // fingerprint -> doc indexes
}

// Build indexes docs with their fingerprints (fps[i] belongs to docs[i]).
func Build(key []byte, docs []Doc, fps [][]int64) *Index {
	ix := &Index{key: key, docs: docs, post: map[uint64][]int32{}}
	for i, fs := range fps {
		for _, f := range fs {
			ix.post[uint64(f)] = append(ix.post[uint64(f)], int32(i))
		}
	}
	return ix
}

// Len is the number of registered documents.
func (ix *Index) Len() int {
	if ix == nil {
		return 0
	}
	return len(ix.docs)
}

// Match returns the registered documents found in text, best first.
func (ix *Index) Match(text string) []Hit {
	if ix.Len() == 0 {
		return nil
	}
	ps := prints(ix.key, text)
	distinct := map[uint64]bool{}
	hits := map[int32]*Hit{}
	at := map[int32][]int{} // positions in ps of the shared fingerprints, per doc
	for i, p := range ps {
		if distinct[p.h] {
			continue
		}
		distinct[p.h] = true
		ds := ix.post[p.h]
		if len(ds) >= MaxDocFreq {
			continue
		}
		for _, d := range ds {
			h := hits[d]
			if h == nil {
				h = &Hit{Doc: ix.docs[d], Span: p.span}
				hits[d] = h
			}
			h.Shared++
			at[d] = append(at[d], i)
			h.Span = [2]int{min(h.Span[0], p.span[0]), max(h.Span[1], p.span[1])}
		}
	}
	var out []Hit
	for d, h := range hits {
		if !clustered(at[d]) {
			continue
		}
		h.Containment = round(float64(h.Shared) / float64(len(distinct)))
		h.Coverage = round(float64(h.Shared) / float64(max(h.Doc.Size, 1)))
		out = append(out, *h)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Shared != out[j].Shared {
			return out[i].Shared > out[j].Shared
		}
		return out[i].Doc.ID < out[j].Doc.ID
	})
	return out
}

func clustered(at []int) bool {
	for i := 0; i+MinShared-1 < len(at); i++ {
		if at[i+MinShared-1]-at[i] < Cluster {
			return true
		}
	}
	return false
}

func round(f float64) float64 { return math.Round(f*1000) / 1000 }

var order = map[string]int{"public": 0, "internal": 1, "confidential": 2, "restricted": 3}

// Apply adds the hits to an L1 result: a CODE.CONFIDENTIAL_DOC class (count = documents found), one match per
// document, and sensitivity raised to the most sensitive document found. A verbatim run of Guarantee+ words is
// proof of copying, so confidence starts at detect.Threshold and grows with containment.
func Apply(r *detect.Result, hits []Hit) {
	if len(hits) == 0 {
		return
	}
	c := detect.Class{Type: Type, Count: len(hits)}
	for _, h := range hits {
		conf := round(detect.Threshold + (1-detect.Threshold)*h.Containment)
		c.Confidence = max(c.Confidence, conf)
		r.Matches = append(r.Matches, detect.Match{Type: Type, Confidence: conf, Span: h.Span, ValidatorPassed: true, ContextScore: 1})
		if order[h.Doc.Sensitivity] > order[r.Sensitivity] {
			r.Sensitivity = h.Doc.Sensitivity
		}
	}
	r.Classes = append(r.Classes, c)
	sort.Slice(r.Classes, func(i, j int) bool { return r.Classes[i].Type < r.Classes[j].Type })
	sort.SliceStable(r.Matches, func(i, j int) bool { return r.Matches[i].Span[0] < r.Matches[j].Span[0] })
}
