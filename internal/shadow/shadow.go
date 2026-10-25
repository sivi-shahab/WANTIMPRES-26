// Package shadow builds the shadow AI baseline (ticket 03, spec FR-SHADOW-1, FR-SHADOW-4, §1.5) from batch
// SWG/proxy/firewall/DNS logs: every request line is fingerprinted against the AI app catalog, users are
// pseudonymised with the tenant HMAC before anything is kept, and the result is a report of top apps, top users and
// units, the weekly trend, and a review queue for detections under 0.6 confidence or ambiguous between apps.
package shadow

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"wantimpres26/internal/catalog"
)

// Record is one request seen in a log.
type Record struct {
	Time      time.Time
	User      string // proxy user, or the client IP when the log has none
	Client    string // client IP, when the log has one (gateway bypass, ticket 43)
	Host      string
	Method    string
	Path      string
	UserAgent string
}

// Parser reads one log line. ok=false means the line is not a request (headers, comments); err means it should
// have been one and could not be read.
type Parser func(line string) (r Record, ok bool, err error)

var errLine = errors.New("unreadable log line")

// Squid native access.log, also behind a syslog prefix:
// "1759651200.123    120 10.0.0.5 TCP_TUNNEL/200 3946 CONNECT api.openai.com:443 alice HIER_DIRECT/1.2.3.4 -".
var squidRe = regexp.MustCompile(`(\d{9,11})(?:\.\d+)?\s+\d+\s+(\S+)\s+\S+\s+\d+\s+(\S+)\s+(\S+)\s+(\S+)`)

func Squid(line string) (Record, bool, error) {
	if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
		return Record{}, false, nil
	}
	m := squidRe.FindStringSubmatch(line)
	if m == nil {
		return Record{}, false, errLine
	}
	sec, _ := strconv.ParseInt(m[1], 10, 64)
	r := Record{Time: time.Unix(sec, 0).UTC(), User: m[5], Client: m[2], Method: m[3]}
	if r.User == "-" {
		r.User = m[2]
	}
	r.Host, r.Path = splitURL(m[4])
	return r, true, nil
}

// BIND query log, also behind a syslog prefix:
// "05-Oct-2026 08:00:01.123 queries: info: client @0x7f 10.0.0.5#53211 (api.openai.com): query: api.openai.com IN A +E(0)K (10.0.0.1)".
var (
	dnsRe     = regexp.MustCompile(`client (?:@\S+ )?([0-9A-Fa-f.:]+)#\d+.*?query: (\S+) IN `)
	bindTime  = regexp.MustCompile(`\d{2}-[A-Z][a-z]{2}-\d{4} \d{2}:\d{2}:\d{2}`)
	isoTimeRe = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})`)
)

func DNS(line string) (Record, bool, error) {
	if !strings.Contains(line, "query: ") {
		return Record{}, false, nil
	}
	m := dnsRe.FindStringSubmatch(line)
	if m == nil {
		return Record{}, false, errLine
	}
	var t time.Time
	var err error
	if s := bindTime.FindString(line); s != "" {
		t, err = time.Parse("02-Jan-2006 15:04:05", s)
	} else if s := isoTimeRe.FindString(line); s != "" {
		t, err = time.Parse(time.RFC3339Nano, s)
	} else {
		err = errLine // a BSD syslog stamp has no year
	}
	if err != nil {
		return Record{}, false, errLine
	}
	return Record{Time: t.UTC(), User: m[1], Client: m[1], Host: strings.TrimSuffix(m[2], ".")}, true, nil
}

// JSONFields names the keys of a JSON-lines export (Zscaler NSS, Netskope, Palo Alto, Fortinet can all emit one).
type JSONFields struct{ Time, User, Client, Host, URL, Method, UserAgent string }

var DefaultJSONFields = JSONFields{Time: "time", User: "user", Client: "client_ip", Host: "host", URL: "url", Method: "method", UserAgent: "user_agent"}

// ParseJSONFields reads "time=ts,user=login,..." over the defaults.
func ParseJSONFields(s string) (JSONFields, error) {
	f := DefaultJSONFields
	for kv := range strings.SplitSeq(s, ",") {
		if kv = strings.TrimSpace(kv); kv == "" {
			continue
		}
		k, v, ok := strings.Cut(kv, "=")
		dst := map[string]*string{"time": &f.Time, "user": &f.User, "client": &f.Client, "host": &f.Host, "url": &f.URL, "method": &f.Method, "user_agent": &f.UserAgent}[k]
		if !ok || dst == nil || v == "" {
			return f, fmt.Errorf("field mapping %q: want name=key with name in time,user,client,host,url,method,user_agent", kv)
		}
		*dst = v
	}
	return f, nil
}

// JSONL returns a parser for one JSON object per line. Time is RFC 3339 or Unix seconds/milliseconds.
func JSONL(f JSONFields) Parser {
	return func(line string) (Record, bool, error) {
		if strings.TrimSpace(line) == "" {
			return Record{}, false, nil
		}
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil {
			return Record{}, false, errLine
		}
		str := func(k string) string { s, _ := m[k].(string); return s }
		r := Record{User: str(f.User), Client: str(f.Client), Host: str(f.Host), Method: str(f.Method), UserAgent: str(f.UserAgent)}
		if u := str(f.URL); u != "" {
			h, p := splitURL(u)
			r.Path = p
			if r.Host == "" {
				r.Host = h
			}
		}
		switch t := m[f.Time].(type) {
		case string:
			tt, err := time.Parse(time.RFC3339Nano, t)
			if err != nil {
				return Record{}, false, errLine
			}
			r.Time = tt.UTC()
		case float64:
			if t > 1e12 {
				t /= 1000
			}
			r.Time = time.Unix(int64(t), 0).UTC()
		default:
			return Record{}, false, errLine
		}
		if r.Host == "" {
			return Record{}, false, errLine
		}
		return r, true, nil
	}
}

// splitURL handles "host:443" (CONNECT), "host/path" and full URLs; the path is kept only when TLS inspection
// exposed it.
func splitURL(s string) (host, path string) {
	if !strings.Contains(s, "://") {
		s = "//" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", ""
	}
	return strings.ToLower(u.Hostname()), u.Path
}

// --- baseline -------------------------------------------------------------------------------------------------

// WeightNameHeuristic: a host outside the catalog whose name says AI (".ai", "gpt", "llm", …). Far under
// catalog.ReviewBelow, so it only ever lands in the review queue: that is how uncatalogued shadow AI shows up.
const WeightNameHeuristic = 0.3

var aiNameRe = regexp.MustCompile(`(^|[.-])(gpt|llm|chatbot|copilot|genai)([.-]|$)|\.ai$`)

// MinDays is the observation window ticket 03 asks the baseline to cover.
const MinDays = 30

// Baseline aggregates records. Raw users are turned into HMACs on arrival and never stored.
type Baseline struct {
	apps   map[string]catalog.App
	list   []catalog.App
	pepper []byte
	units  map[string]string // raw user (lower case) → unit

	lines, unparsed, requests, aiRequests, reviewRequests int
	days                                                  map[string]bool
	app                                                   map[string]*appAgg
	review                                                map[string]*reviewAgg
	user                                                  map[string]*userAgg
	unit                                                  map[string]*unitAgg
	week                                                  map[string]*weekAgg
	cache                                                 map[string]match

	// Gateway bypass (ticket 43): server subnets, the AI gateway's egress addresses, and what was seen.
	servers  []netip.Prefix
	gateways map[netip.Addr]bool
	egress   []catalog.EgressEntry
	bypass   map[[2]string]*catalog.Bypass
}

type match struct {
	d  catalog.Detection
	ok bool
}

type appAgg struct {
	requests    int
	users, days map[string]bool
	first, last time.Time
}

type reviewAgg struct {
	d        catalog.Detection
	requests int
	users    map[string]bool
}

type userAgg struct {
	unit     string
	requests int
	apps     map[string]int
}

type unitAgg struct {
	requests int
	users    map[string]bool
	apps     map[string]int
}

type weekAgg struct {
	requests int
	users    map[string]bool
	apps     map[string]int
}

// NewBaseline needs the tenant pepper (the same HMAC key the platform uses for principal ids, spec §10.2).
// units maps a raw user or client IP to an organisational unit; it may be nil.
func NewBaseline(apps []catalog.App, pepper []byte, units map[string]string) (*Baseline, error) {
	if len(pepper) < 16 {
		return nil, errors.New("tenant pepper shorter than 16 bytes: user pseudonyms would be guessable")
	}
	b := &Baseline{apps: map[string]catalog.App{}, list: apps, pepper: pepper, units: map[string]string{},
		days: map[string]bool{}, app: map[string]*appAgg{}, review: map[string]*reviewAgg{}, user: map[string]*userAgg{},
		unit: map[string]*unitAgg{}, week: map[string]*weekAgg{}, cache: map[string]match{}}
	for _, a := range apps {
		b.apps[a.ID] = a
	}
	for k, v := range units {
		b.units[strings.ToLower(k)] = v
	}
	return b, nil
}

// WatchBypass turns on gateway bypass findings: a client in one of the server subnets, other than a gateway
// egress address, reaching a provider API domain (catalog.ProviderDomains). Logs without client addresses (some
// JSON exports) cannot show it.
func (b *Baseline) WatchBypass(servers []netip.Prefix, gateways []netip.Addr) {
	b.servers, b.gateways, b.egress, b.bypass = servers, map[netip.Addr]bool{}, catalog.ProviderDomains(b.list), map[[2]string]*catalog.Bypass{}
	for _, g := range gateways {
		b.gateways[g.Unmap()] = true
	}
}

func (b *Baseline) checkBypass(r Record) {
	if len(b.servers) == 0 {
		return
	}
	ip, err := netip.ParseAddr(r.Client)
	if err != nil || b.gateways[ip.Unmap()] || !slices.ContainsFunc(b.servers, func(p netip.Prefix) bool { return p.Contains(ip.Unmap()) }) {
		return
	}
	e, ok := catalog.ProviderFor(b.egress, r.Host)
	if !ok {
		return
	}
	k := [2]string{ip.Unmap().String(), e.Domain}
	f := b.bypass[k]
	if f == nil {
		f = &catalog.Bypass{Server: k[0], Domain: e.Domain, AppID: e.AppID, FirstSeen: r.Time, LastSeen: r.Time}
		b.bypass[k] = f
	}
	f.Requests++
	f.FirstSeen, f.LastSeen = minTime(f.FirstSeen, r.Time), maxTime(f.LastSeen, r.Time)
}

// Line feeds one log line through p.
func (b *Baseline) Line(p Parser, line string) {
	r, ok, err := p(line)
	switch {
	case err != nil:
		b.lines++
		b.unparsed++
	case ok:
		b.lines++
		b.Add(r)
	}
}

// Add counts one request.
func (b *Baseline) Add(r Record) {
	b.requests++
	b.days[r.Time.Format(time.DateOnly)] = true
	b.checkBypass(r)
	m := b.detect(r)
	if !m.ok {
		return
	}
	pseudo := b.pseudonym(r.User)
	if m.d.NeedsReview {
		b.reviewRequests++
		key := r.Host
		if key == "" {
			key = strings.Join(m.d.Candidates, ",")
		}
		ra := b.review[key]
		if ra == nil {
			ra = &reviewAgg{d: m.d, users: map[string]bool{}}
			b.review[key] = ra
		}
		ra.requests++
		ra.users[pseudo] = true
		return
	}
	id := m.d.AppID
	b.aiRequests++
	a := b.app[id]
	if a == nil {
		a = &appAgg{users: map[string]bool{}, days: map[string]bool{}, first: r.Time}
		b.app[id] = a
	}
	a.requests++
	a.users[pseudo] = true
	a.days[r.Time.Format(time.DateOnly)] = true
	a.first, a.last = minTime(a.first, r.Time), maxTime(a.last, r.Time)

	unit := b.units[strings.ToLower(r.User)]
	if unit == "" {
		unit = "unknown"
	}
	u := b.user[pseudo]
	if u == nil {
		u = &userAgg{unit: unit, apps: map[string]int{}}
		b.user[pseudo] = u
	}
	u.requests++
	u.apps[id]++
	un := b.unit[unit]
	if un == nil {
		un = &unitAgg{users: map[string]bool{}, apps: map[string]int{}}
		b.unit[unit] = un
	}
	un.requests++
	un.users[pseudo] = true
	un.apps[id]++
	y, w := r.Time.ISOWeek()
	wk := fmt.Sprintf("%d-W%02d", y, w)
	wa := b.week[wk]
	if wa == nil {
		wa = &weekAgg{users: map[string]bool{}, apps: map[string]int{}}
		b.week[wk] = wa
	}
	wa.requests++
	wa.users[pseudo] = true
	wa.apps[id]++
}

// maxCache bounds the fingerprint cache; DNS logs are mostly the same few thousand hosts.
const maxCache = 200_000

func (b *Baseline) detect(r Record) match {
	key := r.Host + "\x00" + r.Method + "\x00" + r.Path + "\x00" + r.UserAgent
	if m, ok := b.cache[key]; ok {
		return m
	}
	d, ok := catalog.Match(b.list, catalog.Signals{Host: r.Host, Method: r.Method, Path: r.Path, UserAgent: r.UserAgent})
	if !ok && r.Host != "" && aiNameRe.MatchString(r.Host) {
		d, ok = catalog.Detection{Confidence: WeightNameHeuristic, Signals: []string{"name_heuristic"}, NeedsReview: true}, true
	}
	if len(b.cache) >= maxCache {
		clear(b.cache)
	}
	m := match{d, ok}
	b.cache[key] = m
	return m
}

func (b *Baseline) pseudonym(user string) string {
	h := hmac.New(sha256.New, b.pepper)
	h.Write([]byte(strings.ToLower(user)))
	return hex.EncodeToString(h.Sum(nil))
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
