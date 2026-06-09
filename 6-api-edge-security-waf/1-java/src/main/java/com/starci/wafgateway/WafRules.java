package com.starci.wafgateway;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

// WAF rule set — portable across all four language tracks. Each rule has a stable
// id ("sql_injection", "xss", "ssrf") and a regex flagging one OWASP risk class,
// mirroring the TypeScript / C# / Go tracks so the contract is identical.
public final class WafRules {

    private record Rule(String id, Pattern pattern) {}

    private static final List<Rule> RULES = List.of(
            new Rule("sql_injection", Pattern.compile(
                    "('\\s*or\\s*'?\\d|union\\s+select|;\\s*drop\\s+table|--\\s|/\\*|\\bor\\s+1\\s*=\\s*1\\b)",
                    Pattern.CASE_INSENSITIVE)),
            new Rule("xss", Pattern.compile(
                    "(<\\s*script|<\\s*img[^>]*\\son\\w+\\s*=|javascript:|on(error|load|click)\\s*=)",
                    Pattern.CASE_INSENSITIVE)),
            new Rule("ssrf", Pattern.compile(
                    "(169\\.254\\.169\\.254|127\\.0\\.0\\.1|localhost|0\\.0\\.0\\.0|metadata\\.google|file://|169\\.254\\.|\\[::1\\])",
                    Pattern.CASE_INSENSITIVE)));

    private WafRules() {}

    // Return the first rule id a single string trips, or null.
    public static String inspectValue(String value) {
        if (value == null) {
            return null;
        }
        for (Rule rule : RULES) {
            if (rule.pattern().matcher(value).find()) {
                return rule.id();
            }
        }
        return null;
    }

    // Walk a decoded-JSON value and inspect every leaf string value.
    @SuppressWarnings("unchecked")
    public static String inspectPayload(Object payload) {
        if (payload instanceof String s) {
            return inspectValue(s);
        }
        if (payload instanceof List<?> list) {
            for (Object item : list) {
                String hit = inspectPayload(item);
                if (hit != null) {
                    return hit;
                }
            }
            return null;
        }
        if (payload instanceof Map<?, ?> map) {
            for (Object value : ((Map<String, Object>) map).values()) {
                String hit = inspectPayload(value);
                if (hit != null) {
                    return hit;
                }
            }
            return null;
        }
        return null;
    }
}
