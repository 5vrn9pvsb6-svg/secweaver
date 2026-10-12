package core

import (
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Catalog is an explicit local-field registry. Arbitrary JSON pointers, SLS
// __source__ and cloud index names are never executable rule inputs.
var Catalog = map[string][]string{
	"audit-port-execmon":         {"/listener_process", "/listener_port", "/listener_address", "/listener_exe", "/pid_name", "/exe", "/command_line", "/uid", "/uid_name", "/file_paths", "/connect_ip", "/connect_port", "/severity"},
	"windows-eventlog-risk-json": {"/listener_process", "/pid_name", "/exe", "/command_line", "/file_paths", "/user", "/windows_event_id", "/dst_ip", "/dst_port", "/provider", "/channel", "/event_id", "/user_sid", "/command", "/script_sha256", "/severity", "/message"},
	"windows-process-execmon":    {"/listener_process", "/pid_name", "/exe", "/command_line", "/file_paths", "/user", "/windows_event_id", "/dst_ip", "/dst_port", "/severity"},
	"syslog-risk-json":           {"/program", "/user", "/src_ip", "/severity", "/message", "/event_type"},
	"host-persistence":           {"/path", "/category", "/persistence_type", "/action", "/size", "/severity"},
}

type truth uint8

const (
	unknown truth = iota
	no
	yes
)

type node struct {
	op, field   string
	value       any
	insensitive bool
	re          *regexp.Regexp
	cidr        netip.Prefix
	children    []*node
}
type compiledRule struct {
	rule        Rule
	root        *node
	from, until time.Time
}
type Engine struct {
	policy      Policy
	from, until time.Time
	index       map[string][]*compiledRule
}
type limits struct{ leaves, regex, instructions int }
type budget struct {
	bytes    int
	exceeded bool
}

// Compile owns all parsing, validation and RE2 work. The returned engine is
// immutable and safe for concurrent events without locks or filesystem access.
func Compile(p Policy) (*Engine, error) {
	// Canonical escaping must not enlarge a signed policy beyond the wire limit.
	if raw, err := json.Marshal(p); err != nil || len(raw) > MaxPolicyBytes {
		return nil, fmt.Errorf("canonical policy exceeds 1 MiB")
	}
	if p.SchemaVersion != 1 || !text(p.PolicyID, 128) || p.Revision < 1 || len(p.Rules) > 256 || (p.Mode != "observe" && p.Mode != "enforce") {
		return nil, fmt.Errorf("invalid policy header or rule limit")
	}
	e := &Engine{policy: p, index: map[string][]*compiledRule{}}
	if len(p.LegacyPortMigrations) > 10000 {
		return nil, fmt.Errorf("legacy migration target limit")
	}
	for device, digest := range p.LegacyPortMigrations {
		if !text(device, 128) || len(digest) != 64 || !allHex(digest) {
			return nil, fmt.Errorf("invalid legacy migration digest")
		}
	}
	var err error
	e.from, err = parseTime(p.ValidFrom)
	if err != nil {
		return nil, err
	}
	e.until, err = parseTime(p.ExpiresAt)
	if err != nil {
		return nil, err
	}
	if !e.from.IsZero() && !e.until.IsZero() && !e.until.After(e.from) {
		return nil, fmt.Errorf("invalid policy time range")
	}
	ids := map[string]bool{}
	total := limits{}
	for _, r := range p.Rules {
		if !text(r.ID, 128) || !text(r.Name, 200) || len(r.Description) > 1024 || ids[r.ID] || r.Priority < 0 || r.Priority > 1000 || (r.Mode != "observe" && r.Mode != "enforce") {
			return nil, fmt.Errorf("invalid rule %q", r.ID)
		}
		ids[r.ID] = true
		if r.Kind == "" {
			r.Kind = "event_filter"
		}
		if len(r.Scope.DeviceIDs) > 128 || len(r.Scope.Platforms) == 0 || len(r.Scope.Platforms) > 2 || len(r.Scope.Modules) == 0 || len(r.Scope.Modules) > 5 || len(r.Scope.EventTypes) > 128 || len(r.Scope.AssetTypes) > 128 {
			return nil, fmt.Errorf("rule %s: explicit bounded scope required", r.ID)
		}
		for _, v := range r.Scope.Platforms {
			for _, device := range r.Scope.DeviceIDs {
				if !text(device, 128) {
					return nil, fmt.Errorf("invalid device scope")
				}
			}
			if v != "linux" && v != "windows" {
				return nil, fmt.Errorf("unsupported platform %s", v)
			}
		}
		for _, m := range r.Scope.Modules {
			if _, ok := Catalog[m]; !ok {
				return nil, fmt.Errorf("unsupported module %s (snapshots cannot be suppressed)", m)
			}
		}
		if r.Kind == "listener_scope" {
			if len(r.Scope.Platforms) != 1 || r.Scope.Platforms[0] != "linux" || len(r.Scope.Modules) != 1 || r.Scope.Modules[0] != "audit-port-execmon" || (r.Action != "keep_listener" && r.Action != "exclude_listener") || len(r.Scope.EventTypes) != 0 {
				return nil, fmt.Errorf("listener scope requires Linux audit TCP scope")
			}
		} else if r.Kind != "event_filter" || len(r.Scope.EventTypes) == 0 || (r.Action != "alert" && r.Action != "keep" && r.Action != "pass" && r.Action != "suppress") {
			return nil, fmt.Errorf("rule %s: invalid kind/action/event types", r.ID)
		}
		for _, v := range append(append([]string{}, r.Scope.EventTypes...), r.Scope.AssetTypes...) {
			if !text(v, 128) || v == "*" || v == "custom_risk_alert" || strings.HasPrefix(v, "internal_") {
				return nil, fmt.Errorf("unsupported event scope %s", v)
			}
		}
		if r.Action == "alert" {
			if r.Alert == nil || !text(r.Alert.Title, 256) || len(r.Alert.Description) > 1024 || severity(r.Alert.Severity) == 0 {
				return nil, fmt.Errorf("rule %s: alert title/severity required", r.ID)
			}
		} else if r.Alert != nil {
			return nil, fmt.Errorf("alert metadata requires alert action")
		}
		c := &compiledRule{rule: r}
		c.from, err = parseTime(r.ValidFrom)
		if err != nil {
			return nil, err
		}
		c.until, err = parseTime(r.ExpiresAt)
		if err != nil {
			return nil, err
		}
		if !c.from.IsZero() && !c.until.IsZero() && !c.until.After(c.from) {
			return nil, fmt.Errorf("invalid rule time range")
		}
		if r.AllowProtectedSuppression && (r.Action != "suppress" || !p.AllowProtectedSuppression || !text(r.Reason, 1024) || c.until.IsZero() || c.until.After(time.Now().Add(7*24*time.Hour))) {
			return nil, fmt.Errorf("protected override requires policy approval, reason and expiry within 7 days")
		}
		l := limits{}
		c.root, err = compileNode(r.When, 1, r, &l)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.ID, err)
		}
		if l.leaves > 16 {
			return nil, fmt.Errorf("rule %s exceeds 16 predicates", r.ID)
		}
		total.leaves += l.leaves
		total.regex += l.regex
		total.instructions += l.instructions
		if total.leaves > 4096 || total.regex > 64 || total.instructions > 32768 {
			return nil, fmt.Errorf("policy predicate/regex budget exceeded")
		}
		types := r.Scope.EventTypes
		if r.Kind == "listener_scope" {
			types = []string{"__listener"}
		}
		for _, p := range r.Scope.Platforms {
			for _, m := range r.Scope.Modules {
				for _, t := range types {
					key := p + "\x00" + m + "\x00" + t
					e.index[key] = append(e.index[key], c)
				}
			}
		}
	}
	for _, rules := range e.index {
		sort.Slice(rules, func(i, j int) bool {
			a, b := rules[i].rule, rules[j].rule
			if rank(a.Action) != rank(b.Action) {
				return rank(a.Action) > rank(b.Action)
			}
			if a.Priority != b.Priority {
				return a.Priority > b.Priority
			}
			return a.ID < b.ID
		})
	}
	return e, nil
}

func rank(s string) int {
	switch s {
	case "alert":
		return 4
	case "keep", "keep_listener":
		return 3
	case "pass":
		return 2
	case "suppress", "exclude_listener":
		return 1
	}
	return 0
}
func severity(s string) int {
	switch s {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	}
	return 0
}
func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// Decide fixes one immutable revision for the whole event. Unknown values do
// not become matches through NOT. Work-budget failures force retention rather
// than passing the event to learning, which could otherwise suppress evidence.
func (e *Engine) Decide(event Event, now time.Time) Decision {
	if event.Backfill {
		return Decision{Action: "pass", Revision: e.policy.Revision, Reason: "history_preserved"}
	}
	d := Decision{Action: "pass", Reason: "unmatched", Revision: e.policy.Revision}
	if !e.policy.Enabled {
		return Decision{Action: "pass", Reason: "disabled", Revision: d.Revision}
	}
	if !e.from.IsZero() && now.Before(e.from) || !e.until.IsZero() && !now.Before(e.until) {
		d.Reason = "policy_inactive"
		return d
	}
	rules := e.index[event.Platform+"\x00"+event.Module+"\x00"+event.EventType]
	b := &budget{}
	var selected, predicted *compiledRule
	for _, r := range rules {
		if !r.rule.Enabled || !r.from.IsZero() && now.Before(r.from) || !r.until.IsZero() && !now.Before(r.until) || len(r.rule.Scope.AssetTypes) > 0 && !contains(r.rule.Scope.AssetTypes, event.AssetType) || len(r.rule.Scope.DeviceIDs) > 0 && !contains(r.rule.Scope.DeviceIDs, event.DeviceID) {
			continue
		}
		if r.root.match(event, b) != yes {
			if b.exceeded {
				return Decision{Action: "keep", Reason: "work_budget_exceeded", Revision: d.Revision}
			}
			continue
		}
		if predicted == nil {
			predicted = r
		}
		if e.policy.Mode == "enforce" && r.rule.Mode == "enforce" && selected == nil {
			selected = r
		}
	}
	if predicted != nil {
		d.PredictedAction = predicted.rule.Action
		d.PredictedRuleID = predicted.rule.ID
	}
	if selected == nil {
		if predicted != nil {
			d.Reason = "observe"
		}
		return d
	}
	d.Action = selected.rule.Action
	d.RuleID = selected.rule.ID
	d.Reason = "matched"
	d.Alert = selected.rule.Alert
	if d.Action == "suppress" && event.Protected && !selected.rule.AllowProtectedSuppression {
		d.Action = "keep"
		d.Reason = "protected_event"
	}
	return d
}

// compileNode validates each leaf against every scoped module. A rule cannot
// work only on one of several modules while silently mismatching the others.
func compileNode(c Condition, depth int, r Rule, l *limits) (*node, error) {
	if depth > 6 {
		return nil, fmt.Errorf("condition depth exceeds 6")
	}
	shapes := 0
	if c.All != nil {
		shapes++
	}
	if c.Any != nil {
		shapes++
	}
	if c.Not != nil {
		shapes++
	}
	if c.Field != "" || c.Op != "" {
		shapes++
	}
	if shapes != 1 {
		return nil, fmt.Errorf("exactly one condition shape required")
	}
	n := &node{}
	var group []Condition
	if c.All != nil {
		n.op = "all"
		group = c.All
	}
	if c.Any != nil {
		n.op = "any"
		group = c.Any
	}
	if c.Not != nil {
		n.op = "not"
		group = []Condition{*c.Not}
	}
	if n.op != "" {
		if len(group) == 0 || len(group) > 16 || c.Value != nil || c.CaseSensitive != nil {
			return nil, fmt.Errorf("invalid condition group")
		}
		for _, v := range group {
			child, err := compileNode(v, depth+1, r, l)
			if err != nil {
				return nil, err
			}
			n.children = append(n.children, child)
		}
		return n, nil
	}
	l.leaves++
	if len(c.Field) > 256 {
		return nil, fmt.Errorf("field path too long")
	}
	for _, m := range r.Scope.Modules {
		if !contains(Catalog[m], c.Field) {
			return nil, fmt.Errorf("field %s unavailable in %s", c.Field, m)
		}
	}
	if r.Kind == "listener_scope" && !contains([]string{"/listener_port", "/listener_address", "/listener_process", "/listener_exe"}, c.Field) {
		return nil, fmt.Errorf("field not available during listener discovery")
	}
	n.op = c.Op
	n.field = c.Field
	n.value = c.Value
	n.insensitive = c.CaseSensitive != nil && !*c.CaseSensitive
	if n.insensitive && !contains([]string{"eq", "neq", "in", "not_in", "prefix", "suffix", "contains", "array_any", "array_all", "array_none", "array_eq"}, c.Op) {
		return nil, fmt.Errorf("case_sensitive unsupported for %s", c.Op)
	}
	switch c.Op {
	case "exists", "is_empty":
		if c.Value != nil {
			return nil, fmt.Errorf("operator takes no value")
		}
	case "eq", "neq":
		if !scalar(c.Value) {
			return nil, fmt.Errorf("scalar required")
		}
	case "in", "not_in", "array_eq":
		a, ok := c.Value.([]any)
		if !ok || len(a) == 0 || len(a) > 128 {
			return nil, fmt.Errorf("bounded nonempty value list required")
		}
		for _, v := range a {
			if !scalar(v) {
				return nil, fmt.Errorf("scalar list required")
			}
		}
	case "prefix", "suffix", "contains":
		if _, ok := c.Value.(string); !ok {
			return nil, fmt.Errorf("string required")
		}
	case "regex":
		s, ok := c.Value.(string)
		if !ok || len(s) > 512 {
			return nil, fmt.Errorf("regex exceeds 512 bytes")
		}
		re, err := regexp.Compile(s)
		if err != nil {
			return nil, fmt.Errorf("invalid RE2 expression: %w", err)
		}
		tree, err := syntax.Parse(s, syntax.Perl)
		if err != nil {
			return nil, err
		}
		prog, err := syntax.Compile(tree.Simplify())
		if err != nil {
			return nil, err
		}
		l.regex++
		l.instructions += len(prog.Inst)
		n.re = re
	case "cidr":
		s, ok := c.Value.(string)
		if !ok {
			return nil, fmt.Errorf("CIDR string required")
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR")
		}
		n.cidr = p
	case "gt", "gte", "lt", "lte":
		if _, ok := number(c.Value); !ok {
			return nil, fmt.Errorf("numeric value required")
		}
	case "between":
		a, ok := c.Value.([]any)
		if !ok || len(a) != 2 {
			return nil, fmt.Errorf("two numeric bounds required")
		}
		x, ok := number(a[0])
		y, ok2 := number(a[1])
		if !ok || !ok2 || x > y {
			return nil, fmt.Errorf("invalid numeric bounds")
		}
	case "array_any", "array_all", "array_none":
		raw, err := json.Marshal(c.Value)
		if err != nil {
			return nil, err
		}
		var item Condition
		d := json.NewDecoder(strings.NewReader(string(raw)))
		d.UseNumber()
		d.DisallowUnknownFields()
		if d.Decode(&item) != nil || item.Field != "" || item.All != nil || item.Any != nil || item.Not != nil || !contains([]string{"eq", "neq", "in", "not_in", "prefix", "suffix", "contains", "regex", "cidr"}, item.Op) {
			return nil, fmt.Errorf("array predicate must be scalar string operator")
		}
		item.Field = c.Field
		child, err := compileNode(item, depth, r, l)
		if err != nil {
			return nil, err
		}
		n.children = []*node{child}
	default:
		return nil, fmt.Errorf("unsupported operator %s", c.Op)
	}
	raw, _ := json.Marshal(c.Value)
	if len(raw) > 16384 {
		return nil, fmt.Errorf("condition values too large")
	}
	if s, ok := c.Value.(string); ok && len(s) > 4096 {
		return nil, fmt.Errorf("value exceeds 4096 bytes")
	}
	return n, nil
}
func scalar(v any) bool {
	if s, ok := v.(string); ok {
		return utf8.ValidString(s) && len(s) <= 4096
	}
	if _, ok := v.(bool); ok {
		return true
	}
	_, ok := number(v)
	return ok
}
func number(v any) (float64, bool) {
	var f float64
	var err error
	switch n := v.(type) {
	case json.Number:
		f, err = strconv.ParseFloat(n.String(), 64)
	case float64:
		f = n
	case int:
		f = float64(n)
	case int64:
		f = float64(n)
	default:
		return 0, false
	}
	return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
}
func boolTruth(b bool) truth {
	if b {
		return yes
	}
	return no
}
func invert(t truth) truth {
	if t == yes {
		return no
	}
	if t == no {
		return yes
	}
	return unknown
}

// match short-circuits three-valued groups but charges all inspected strings.
// Missing/type-mismatched data stays unknown, including negated predicates.
func (n *node) match(e Event, b *budget) truth {
	switch n.op {
	case "not":
		return invert(n.children[0].match(e, b))
	case "all", "any":
		result := yes
		if n.op == "any" {
			result = no
		}
		for _, child := range n.children {
			v := child.match(e, b)
			if n.op == "all" && v == no || n.op == "any" && v == yes {
				return v
			}
			if v == unknown {
				result = unknown
			}
		}
		return result
	}
	value, present := e.Fields[n.field]
	if n.op == "exists" {
		return boolTruth(present)
	}
	if !present || value == nil || e.Incomplete[n.field] {
		return unknown
	}
	if s, ok := value.(string); ok {
		b.bytes += len(s)
		if len(s) > 32768 || b.bytes > 262144 {
			b.exceeded = true
			return unknown
		}
		if !utf8.ValidString(s) {
			return unknown
		}
	}
	if n.op == "is_empty" {
		switch v := value.(type) {
		case string:
			return boolTruth(v == "")
		case []string:
			return boolTruth(len(v) == 0)
		case []any:
			return boolTruth(len(v) == 0)
		}
		return unknown
	}
	if strings.HasPrefix(n.op, "array_") {
		a, ok := array(value)
		if !ok {
			return unknown
		}
		if len(a) > 256 {
			b.exceeded = true
			return unknown
		}
		if len(a) == 0 {
			return no
		}
		if n.op == "array_eq" {
			expected := n.value.([]any)
			if len(a) != len(expected) {
				return no
			}
			result := yes
			for i, v := range a {
				s, ok := v.(string)
				if !ok || !utf8.ValidString(s) {
					return unknown
				}
				b.bytes += len(s)
				if len(s) > 32768 || b.bytes > 262144 {
					b.exceeded = true
					return unknown
				}
				t := equal(v, expected[i], n.insensitive)
				if t == no {
					return no
				}
				if t == unknown {
					result = unknown
				}
			}
			return result
		}
		result := no
		if n.op == "array_all" {
			result = yes
		}
		for _, v := range a {
			if _, ok := v.(string); !ok {
				return unknown
			}
			fields := map[string]any{n.field: v}
			t := n.children[0].match(Event{Fields: fields}, b)
			if n.op == "array_all" && t == no {
				return no
			}
			if n.op != "array_all" && t == yes {
				if n.op == "array_none" {
					return no
				}
				return yes
			}
			if t == unknown {
				result = unknown
			}
		}
		if n.op == "array_none" {
			return invert(result)
		}
		return result
	}
	switch n.op {
	case "eq":
		return equal(value, n.value, n.insensitive)
	case "neq":
		return invert(equal(value, n.value, n.insensitive))
	case "in", "not_in":
		result := no
		for _, v := range n.value.([]any) {
			t := equal(value, v, n.insensitive)
			if t == yes {
				result = yes
				break
			}
			if t == unknown {
				result = unknown
			}
		}
		if n.op == "not_in" {
			return invert(result)
		}
		return result
	case "gt", "gte", "lt", "lte", "between":
		x, ok := number(value)
		if !ok {
			return unknown
		}
		if n.op == "between" {
			bounds := n.value.([]any)
			a, _ := number(bounds[0])
			z, _ := number(bounds[1])
			return boolTruth(x >= a && x <= z)
		}
		y, _ := number(n.value)
		switch n.op {
		case "gt":
			return boolTruth(x > y)
		case "gte":
			return boolTruth(x >= y)
		case "lt":
			return boolTruth(x < y)
		default:
			return boolTruth(x <= y)
		}
	}
	s, ok := value.(string)
	if !ok {
		return unknown
	}
	v, _ := n.value.(string)
	if n.insensitive {
		s = strings.ToLower(s)
		v = strings.ToLower(v)
	}
	switch n.op {
	case "prefix":
		return boolTruth(strings.HasPrefix(s, v))
	case "suffix":
		return boolTruth(strings.HasSuffix(s, v))
	case "contains":
		return boolTruth(strings.Contains(s, v))
	case "regex":
		return boolTruth(n.re.MatchString(s))
	case "cidr":
		ip, err := netip.ParseAddr(s)
		if err != nil {
			return unknown
		}
		return boolTruth(n.cidr.Contains(ip))
	}
	return unknown
}
func array(v any) ([]any, bool) {
	if a, ok := v.([]any); ok {
		return a, true
	}
	if a, ok := v.([]string); ok {
		r := make([]any, len(a))
		for i, s := range a {
			r[i] = s
		}
		return r, true
	}
	return nil, false
}
func equal(a, b any, fold bool) truth {
	switch x := a.(type) {
	case string:
		y, ok := b.(string)
		if !ok {
			return unknown
		}
		if fold {
			return boolTruth(strings.EqualFold(x, y))
		}
		return boolTruth(x == y)
	case bool:
		y, ok := b.(bool)
		if !ok {
			return unknown
		}
		return boolTruth(x == y)
	}
	x, ok := number(a)
	y, ok2 := number(b)
	if !ok || !ok2 {
		return unknown
	}
	return boolTruth(x == y)
}
