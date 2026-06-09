package main

import (
	"reflect"
	"regexp"
)

// wafRule pairs a stable rule id with the regex that flags one OWASP risk class.
// The ids ("sql_injection", "xss", "ssrf") and detection intent mirror the
// TypeScript / Java / C# tracks so the blocked-vs-allowed contract is identical.
type wafRule struct {
	id      string
	pattern *regexp.Regexp
}

// wafRules is the ordered rule set evaluated by the gateway middleware.
var wafRules = []wafRule{
	{
		id:      "sql_injection",
		pattern: regexp.MustCompile(`(?i)('\s*or\s*'?\d|union\s+select|;\s*drop\s+table|--\s|/\*|\bor\s+1\s*=\s*1\b)`),
	},
	{
		id:      "xss",
		pattern: regexp.MustCompile(`(?i)(<\s*script|<\s*img[^>]*\son\w+\s*=|javascript:|on(error|load|click)\s*=)`),
	},
	{
		id:      "ssrf",
		pattern: regexp.MustCompile(`(?i)(169\.254\.169\.254|127\.0\.0\.1|localhost|0\.0\.0\.0|metadata\.google|file://|169\.254\.|\[::1\])`),
	},
}

// inspectValue returns the first rule id a single string trips, or "".
func inspectValue(value string) string {
	for _, rule := range wafRules {
		if rule.pattern.MatchString(value) {
			return rule.id
		}
	}
	return ""
}

// inspectPayload walks an arbitrary decoded-JSON value and inspects every leaf
// string. It returns the first rule id hit, or "" when the payload is clean.
func inspectPayload(payload interface{}) string {
	switch v := payload.(type) {
	case string:
		return inspectValue(v)
	case []interface{}:
		for _, item := range v {
			if hit := inspectPayload(item); hit != "" {
				return hit
			}
		}
	case map[string]interface{}:
		for _, val := range v {
			if hit := inspectPayload(val); hit != "" {
				return hit
			}
		}
	default:
		_ = reflect.TypeOf(v) // non-string leaves (numbers, bools, nil) are safe
	}
	return ""
}
