// WAF rule set — portable across all four language tracks.
// Each rule has a stable id and a regex that flags one OWASP risk class.
// The same id strings and the same detection intent are mirrored in the
// Java / C# / Go tracks so the blocked-vs-allowed contract is identical.

export interface WafRule {
    id: string
    pattern: RegExp
}

// Order matters only for which rule id is reported first; detection is the same.
export const WAF_RULES: WafRule[] = [
    {
        // SQL injection: tautologies, UNION SELECT, stacked DROP, SQL comments.
        id: "sql_injection",
        pattern:
            /('\s*or\s*'?\d|union\s+select|;\s*drop\s+table|--\s|\/\*|\bor\s+1\s*=\s*1\b)/i,
    },
    {
        // Cross-site scripting: script tags, inline event handlers, javascript: URIs.
        id: "xss",
        pattern: /(<\s*script|<\s*img[^>]*\bon\w+\s*=|javascript:|on(error|load|click)\s*=)/i,
    },
    {
        // SSRF: requests aimed at loopback, link-local cloud metadata, or file scheme.
        id: "ssrf",
        pattern:
            /(169\.254\.169\.254|127\.0\.0\.1|localhost|0\.0\.0\.0|metadata\.google|file:\/\/|169\.254\.|\[::1\])/i,
    },
]

// Inspect one string value against every rule; return the first rule id hit.
export function inspectValue(value: string): string | null {
    for (const rule of WAF_RULES) {
        if (rule.pattern.test(value)) {
            return rule.id
        }
    }
    return null
}

// Walk an arbitrary JSON-like payload and inspect every leaf string.
export function inspectPayload(payload: unknown): string | null {
    if (typeof payload === "string") {
        return inspectValue(payload)
    }
    if (Array.isArray(payload)) {
        for (const item of payload) {
            const hit = inspectPayload(item)
            if (hit) return hit
        }
        return null
    }
    if (payload && typeof payload === "object") {
        for (const v of Object.values(payload as Record<string, unknown>)) {
            const hit = inspectPayload(v)
            if (hit) return hit
        }
        return null
    }
    return null
}
