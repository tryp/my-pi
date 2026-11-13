// Filter-output extension — redact secrets from tool output
// Patterns from https://github.com/spences10/nopeek
import { resolve } from 'node:path';
import { initialize_pattern_registry, MAX_REDACTION_CHUNK_CHARS, MAX_REDACTION_MATCH_CHARS, REDACTION_OVERLAP_CHARS, replace_owned_matches as replace_windowed_matches, } from './windowed-replace.js';
const MAX_FIELD_NAME_CHARS = 64;
const MAX_FORMAT_WHITESPACE_CHARS = 64;
const MAX_SSH_LINE_CHARS = 8_192;
const PRIVATE_KEY_BEGIN_PATTERN = /-----BEGIN[ \t]{1,8}[\w -]{0,64}PRIVATE[ \t]{1,8}KEY-----/;
const PRIVATE_KEY_END_PATTERN = /-----END[ \t]{1,8}[\w -]{0,64}PRIVATE[ \t]{1,8}KEY-----/;
const PRIVATE_KEY_MARKER_PATTERN = /-----BEGIN[ \t]{1,8}[\w -]{0,64}PRIVATE[ \t]{1,8}KEY-----|-----END[ \t]{1,8}[\w -]{0,64}PRIVATE[ \t]{1,8}KEY-----/g;
const PRIVATE_KEY_MARKER_TAIL_CHARS = 105 - 1;
function get_private_key_marker_tail(text) {
    const begin = text.lastIndexOf('-----BEGIN');
    const end = text.lastIndexOf('-----END');
    const marker_start = Math.max(begin, end);
    if (marker_start >= 0) {
        const suffix = text.slice(marker_start);
        if (suffix.length <= PRIVATE_KEY_MARKER_TAIL_CHARS &&
            /^-----(?:BEGIN|END)[ \tA-Za-z0-9_-]*$/.test(suffix)) {
            return suffix;
        }
    }
    for (const marker_prefix of ['-----BEGIN', '-----END']) {
        for (let length = marker_prefix.length - 1; length > 0; length--) {
            const suffix = text.slice(-length);
            if (marker_prefix.startsWith(suffix))
                return suffix;
        }
    }
    return '';
}
function scan_private_key_state(text, open_count, marker_tail) {
    const combined = marker_tail + text;
    const prior_chunk_length = marker_tail.length;
    let begin_crossed_chunk = false;
    PRIVATE_KEY_MARKER_PATTERN.lastIndex = 0;
    let marker;
    while ((marker = PRIVATE_KEY_MARKER_PATTERN.exec(combined)) !== null) {
        if (marker.index + marker[0].length <= prior_chunk_length)
            continue;
        const is_begin = marker[0].startsWith('-----BEGIN');
        if (is_begin) {
            if (marker.index < prior_chunk_length)
                begin_crossed_chunk = true;
            open_count++;
        }
        else if (open_count > 0) {
            open_count--;
        }
    }
    return {
        open_count,
        marker_tail: get_private_key_marker_tail(combined),
        begin_crossed_chunk,
    };
}
// Provider patterns consume their complete format-alphabet candidate. Fixed-
// width provider formats retain exact widths; minimum lengths remain heuristics.
const SECRET_PATTERNS = initialize_pattern_registry([
    { name: 'AWS Access Key', pattern: /AKIA[A-Z0-9]{16}(?![A-Z0-9])/g, max_match_chars: 20 },
    { name: 'AWS Temp Access Key', pattern: /ASIA[A-Z0-9]{16}(?![A-Z0-9])/g, max_match_chars: 20 },
    {
        name: 'AWS Secret Key',
        pattern: /\b(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key|secret_access_key|SecretAccessKey)\b[ \t]{0,64}[:=][ \t]{0,64}["']?[A-Za-z0-9/+=]{40,}(?![A-Za-z0-9/+=])["']?/g,
        max_match_chars: 512,
    },
    {
        name: 'Bearer Token',
        pattern: /Bearer[ \t]{1,64}[a-zA-Z0-9._-]{20,}(?![a-zA-Z0-9._-])/g,
        max_match_chars: 326,
    },
    {
        name: 'OpenAI/Anthropic API Key',
        pattern: /sk-[a-zA-Z0-9._-]{20,}(?![a-zA-Z0-9._-])/g,
        max_match_chars: 259,
    },
    {
        name: 'Stripe Live Key',
        pattern: /sk_live_[a-zA-Z0-9]{20,}(?![a-zA-Z0-9])/g,
        max_match_chars: 264,
    },
    {
        name: 'Stripe Test Key',
        pattern: /sk_test_[a-zA-Z0-9]{20,}(?![a-zA-Z0-9])/g,
        max_match_chars: 264,
    },
    {
        name: 'Hetzner Token',
        pattern: /(?:HCLOUD_TOKEN|hcloud_token|token)[ \t]{0,64}[:=][ \t]{0,64}["']?[a-f0-9]{64}\b/g,
        max_match_chars: 256,
    },
    {
        name: 'Private Key',
        pattern: /-----BEGIN[ \t]{1,8}[\w -]{0,64}PRIVATE[ \t]{1,8}KEY-----[\s\S]*?(?:-----END[ \t]{1,8}[\w -]{0,64}PRIVATE[ \t]{1,8}KEY-----|$)/g,
        max_match_chars: Number.MAX_SAFE_INTEGER,
    },
    {
        name: 'Connection String with Password',
        pattern: /\b[a-z][a-z0-9+.-]{0,63}:\/\/[^:\s/?#]+:[^@\s/?#]+@/gi,
        max_match_chars: Number.MAX_SAFE_INTEGER,
    },
    {
        name: 'Generic Secret Phrase',
        pattern: /\b(?:password|passwd|secret|token|api[_-]?key)\b[ \t]{1,64}(?:is|was|seen|value|header)[ \t]{1,64}["']?[A-Za-z0-9._:/+=@!-]{12,}(?![A-Za-z0-9._:/+=@!-])["']?/gi,
        max_match_chars: 8_192,
    },
    {
        name: 'Tavily API Key',
        pattern: /tvly-[a-zA-Z0-9_-]{20,}(?![a-zA-Z0-9_-])/g,
        max_match_chars: 261,
    },
    {
        name: 'Brave API Key',
        pattern: /BSA[A-Z0-9]{20,}(?![A-Z0-9])/g,
        max_match_chars: 259,
    },
    {
        name: 'Firecrawl API Key',
        pattern: /fc-[a-f0-9]{32}(?![a-f0-9])/g,
        max_match_chars: 35,
    },
    {
        name: 'GitHub Token',
        pattern: /gh[pousr]_[a-zA-Z0-9]{36,}(?![a-zA-Z0-9])/g,
        max_match_chars: 260,
    },
    {
        name: 'GitHub Fine-grained PAT',
        pattern: /github_pat_[a-zA-Z0-9_]{20,}(?![a-zA-Z0-9_])/g,
        max_match_chars: 267,
    },
    {
        name: 'JWT',
        pattern: new RegExp(`eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])`, 'g'),
        max_match_chars: MAX_REDACTION_MATCH_CHARS,
    },
    {
        name: 'Slack Token',
        pattern: /xox[baprs]-[A-Za-z0-9-]{20,}(?![A-Za-z0-9-])/g,
        max_match_chars: 261,
    },
    {
        name: 'GitLab Token',
        pattern: /glpat-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])/g,
        max_match_chars: 262,
    },
    {
        name: 'Google API Key',
        pattern: /AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])/g,
        max_match_chars: 39,
    },
    {
        name: 'npm Token',
        pattern: /npm_[A-Za-z0-9]{36,}(?![A-Za-z0-9])/g,
        max_match_chars: 260,
    },
    {
        name: 'SendGrid API Key',
        pattern: /SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{32,}(?![A-Za-z0-9_-])/g,
        max_match_chars: 16_388,
    },
], REDACTION_OVERLAP_CHARS);
const SECRET_FIELD_NAME = `(?:[A-Z0-9_]{0,${MAX_FIELD_NAME_CHARS}}(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY)|password|passwd|secret|token|api[_-]?key|access[_-]?token|client[_-]?secret|private[_-]?key)`;
const JSON_SECRET_FIELD_NAME = `[A-Za-z0-9_-]{0,${MAX_FIELD_NAME_CHARS}}(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)`;
const DOUBLE_QUOTED_JSON_SECRET_FIELD_PATTERN = new RegExp(`(^|[^A-Za-z0-9_-])((?:"${JSON_SECRET_FIELD_NAME}")[ \\t]{0,${MAX_FORMAT_WHITESPACE_CHARS}}:[ \\t]{0,${MAX_FORMAT_WHITESPACE_CHARS}}")((?:\\\\.|[^"\\\\]){8,})(?:"|$)`, 'gim');
const SINGLE_QUOTED_JSON_SECRET_FIELD_PATTERN = new RegExp(`(^|[^A-Za-z0-9_-])((?:'${JSON_SECRET_FIELD_NAME}')[ \\t]{0,${MAX_FORMAT_WHITESPACE_CHARS}}:[ \\t]{0,${MAX_FORMAT_WHITESPACE_CHARS}}')((?:\\\\.|[^'\\\\]){8,})(?:'|$)`, 'gim');
const DOUBLE_QUOTED_SECRET_FIELD_PATTERN = new RegExp(`(^|[^A-Za-z0-9_-])((?:"?${SECRET_FIELD_NAME}"?)[ \\t]{0,${MAX_FORMAT_WHITESPACE_CHARS}}[:=][ \\t]{0,${MAX_FORMAT_WHITESPACE_CHARS}}")((?:\\\\.|[^"\\\\]){8,})(?:"|$)`, 'gm');
const SINGLE_QUOTED_SECRET_FIELD_PATTERN = new RegExp(`(^|[^A-Za-z0-9_-])((?:'?${SECRET_FIELD_NAME}'?)[ \\t]{0,${MAX_FORMAT_WHITESPACE_CHARS}}[:=][ \\t]{0,${MAX_FORMAT_WHITESPACE_CHARS}}')((?:\\\\.|[^'\\\\]){8,})(?:'|$)`, 'gm');
const UNQUOTED_SECRET_FIELD_PATTERN = new RegExp(`(^|[^A-Za-z0-9_-])((?:${SECRET_FIELD_NAME})[ \\t]{0,${MAX_FORMAT_WHITESPACE_CHARS}}[:=][ \\t]{0,${MAX_FORMAT_WHITESPACE_CHARS}})([^\\s"',;}\\]]{8,})(?=$|[\\s"',;}\\]])`, 'gm');
// SSH directives are single physical lines; 8 KiB covers real host names,
// paths and commands while preventing an unbounded line match.
const SSH_CONFIG_VALUE_DIRECTIVE_PATTERN = new RegExp(`^([ \\t]{0,256})(HostName|User|IdentityFile|CertificateFile|ProxyJump|ProxyCommand|LocalForward|RemoteForward|DynamicForward|HostKeyAlias)([ \\t]{1,64})([^\\r\\n]{1,${MAX_SSH_LINE_CHARS}})$`, 'gim');
const SSH_CONFIG_HOST_PATTERN = new RegExp(`^([ \\t]{0,256})(Host)([ \\t]{1,64})([^\\r\\n]{1,${MAX_SSH_LINE_CHARS}})$`, 'gim');
const SSH_CONFIG_MATCH_PATTERN = new RegExp(`^([ \\t]{0,256})(Match)([ \\t]{1,64})([^\\r\\n]{1,${MAX_SSH_LINE_CHARS}})$`, 'gim');
// Keep matcher names centralized for diagnostics; max_match_chars below is
// legacy metadata and is not treated as a bound.
initialize_pattern_registry([
    { name: 'Private-key begin marker', pattern: PRIVATE_KEY_BEGIN_PATTERN, max_match_chars: 105 },
    { name: 'Private-key end marker', pattern: PRIVATE_KEY_END_PATTERN, max_match_chars: 103 },
    { name: 'JSON double-quoted secret field', pattern: DOUBLE_QUOTED_JSON_SECRET_FIELD_PATTERN, max_match_chars: 17_000 },
    { name: 'JSON single-quoted secret field', pattern: SINGLE_QUOTED_JSON_SECRET_FIELD_PATTERN, max_match_chars: 17_000 },
    { name: 'Double-quoted secret field', pattern: DOUBLE_QUOTED_SECRET_FIELD_PATTERN, max_match_chars: 17_000 },
    { name: 'Single-quoted secret field', pattern: SINGLE_QUOTED_SECRET_FIELD_PATTERN, max_match_chars: 17_000 },
    { name: 'Unquoted secret field', pattern: UNQUOTED_SECRET_FIELD_PATTERN, max_match_chars: 17_000 },
    { name: 'SSH value directive', pattern: SSH_CONFIG_VALUE_DIRECTIVE_PATTERN, max_match_chars: 8_527 },
    { name: 'SSH Host directive', pattern: SSH_CONFIG_HOST_PATTERN, max_match_chars: 8_516 },
    { name: 'SSH Match directive', pattern: SSH_CONFIG_MATCH_PATTERN, max_match_chars: 8_517 },
], REDACTION_OVERLAP_CHARS);
export function looks_like_ssh_config(text) {
    const has_scope_line = /^[\t\r\n ]{0,256}(?:Host|Match)\b/m.test(text);
    const has_sensitive_directive = /^[\t\r\n ]{0,256}(?:HostName|User|IdentityFile|CertificateFile|ProxyJump|ProxyCommand|LocalForward|RemoteForward|DynamicForward|HostKeyAlias)\b/im.test(text);
    return has_scope_line && has_sensitive_directive;
}
export function redact_ssh_config_metadata(text) {
    let result = text;
    let count = 0;
    const value_directive = replace_owned_matches(result, SSH_CONFIG_VALUE_DIRECTIVE_PATTERN, (match) => {
        const [, indent, directive, spacing, value] = match;
        if (value.includes('[REDACTED:'))
            return undefined;
        return `${indent}${directive}${spacing}[REDACTED:SSH ${directive}]`;
    });
    result = value_directive.redacted;
    count += value_directive.count;
    const host = replace_owned_matches(result, SSH_CONFIG_HOST_PATTERN, (match) => {
        const [, indent, directive, spacing, value] = match;
        if (value.trim() === '*' || value.includes('[REDACTED:'))
            return undefined;
        return `${indent}${directive}${spacing}[REDACTED:SSH Host]`;
    });
    result = host.redacted;
    count += host.count;
    const match_directive = replace_owned_matches(result, SSH_CONFIG_MATCH_PATTERN, (match) => {
        const [, indent, directive, spacing, value] = match;
        if (value.trim().toLowerCase() === 'all' ||
            value.includes('[REDACTED:'))
            return undefined;
        return `${indent}${directive}${spacing}[REDACTED:SSH Match]`;
    });
    result = match_directive.redacted;
    count += match_directive.count;
    return { redacted: result, count };
}
function redact_secret_fields(text) {
    let result = text;
    let count = 0;
    const marker = '[REDACTED:Generic Password Field]';
    const redact_quoted = (pattern, quote) => {
        const replaced = replace_owned_matches(result, pattern, (match) => {
            const [, boundary, assignment, value] = match;
            if (value.includes('[REDACTED:'))
                return undefined;
            return `${boundary}${assignment}${marker}${quote}`;
        });
        result = replaced.redacted;
        count += replaced.count;
    };
    redact_quoted(DOUBLE_QUOTED_JSON_SECRET_FIELD_PATTERN, '"');
    redact_quoted(SINGLE_QUOTED_JSON_SECRET_FIELD_PATTERN, "'");
    redact_quoted(DOUBLE_QUOTED_SECRET_FIELD_PATTERN, '"');
    redact_quoted(SINGLE_QUOTED_SECRET_FIELD_PATTERN, "'");
    const unquoted = replace_owned_matches(result, UNQUOTED_SECRET_FIELD_PATTERN, (match) => {
        const [, boundary, assignment, value] = match;
        if (value.includes('[REDACTED:'))
            return undefined;
        return `${boundary}${assignment}${marker}`;
    });
    result = unquoted.redacted;
    count += unquoted.count;
    return { redacted: result, count };
}
function redact_kagi_candidates(text) {
    let result = '';
    let cursor = 0;
    let run_start = 0;
    let count = 0;
    const is_token_char = (char) => char !== undefined && /[A-Za-z0-9_-]/.test(char);
    for (let index = 0; index <= text.length; index++) {
        if (is_token_char(text[index]))
            continue;
        if (text[index] === '.' && index - run_start >= 40) {
            let right_end = index + 1;
            while (is_token_char(text[right_end]))
                right_end++;
            if (right_end - index - 1 >= 40) {
                if (run_start > cursor)
                    result += text.slice(cursor, run_start);
                result += '[REDACTED:Kagi API Key]';
                cursor = right_end;
                count++;
                index = right_end - 1;
            }
        }
        run_start = index + 1;
    }
    result += text.slice(cursor);
    return { redacted: result, count };
}
function redact_secret_patterns(text) {
    let result = text;
    let count = 0;
    for (const sp of SECRET_PATTERNS) {
        const replaced = replace_owned_matches(result, sp.pattern, (match) => {
            const value = match[0];
            const prefix = value.slice(0, 4);
            return `${prefix}${'*'.repeat(Math.min(value.length - 4, 20))}[REDACTED:${sp.name}]`;
        });
        result = replaced.redacted;
        count += replaced.count;
    }
    return { redacted: result, count };
}
function is_ssh_config_path(path) {
    if (typeof path !== 'string')
        return false;
    const normalized = path.replaceAll('\\', '/').toLowerCase();
    return /(?:^|\/)(?:\.ssh\/(?:config|config\.d\/[\s\S]{1,4096}|conf\.d\/[\s\S]{1,4096})|ssh_config)$/.test(normalized);
}
function should_force_ssh_config_redaction(event) {
    if (event.toolName !== 'read')
        return false;
    if (!event.input || typeof event.input !== 'object')
        return false;
    return is_ssh_config_path(event.input.path);
}
function is_text_content(item) {
    return item.type === 'text';
}
// The overlap is the derived maximum match length; every owned match must fit.
function replace_owned_matches(text, pattern, replacement_for_match) {
    return replace_windowed_matches(text, pattern, replacement_for_match, MAX_REDACTION_CHUNK_CHARS, REDACTION_OVERLAP_CHARS);
}
function redact_text_chunk(text, options) {
    let count = 0;
    let result = text;
    if (options?.force_ssh_config || looks_like_ssh_config(result)) {
        const ssh_redaction = redact_ssh_config_metadata(result);
        result = ssh_redaction.redacted;
        count += ssh_redaction.count;
    }
    const field_redaction = redact_secret_fields(result);
    result = field_redaction.redacted;
    count += field_redaction.count;
    const secret_redaction = redact_secret_patterns(result);
    result = secret_redaction.redacted;
    count += secret_redaction.count;
    const kagi_redaction = redact_kagi_candidates(result);
    result = kagi_redaction.redacted;
    count += kagi_redaction.count;
    return { redacted: result, count };
}
export function redact_text(text, options) {
    if (options?.force_private_key && text) {
        return {
            redacted: '[REDACTED:Private Key continuation]',
            count: 1,
        };
    }
    try {
        return redact_text_chunk(text, options);
    }
    catch {
        return { redacted: '[REDACTED: scanning failed]', count: 1 };
    }
}
export default async function filter_output(pi) {
    let total_redacted = 0;
    const partial_private_key_paths = new Map();
    pi.on('tool_result', async (event) => {
        if (!event.content)
            return;
        const force_ssh_config = should_force_ssh_config_redaction(event);
        const input_path = event.toolName === 'read' &&
            event.input &&
            typeof event.input === 'object' &&
            typeof event.input.path === 'string'
            ? event.input.path
            : undefined;
        const normalized_input_path = input_path
            ? resolve(input_path)
            : undefined;
        const existing_private_key_state = normalized_input_path
            ? partial_private_key_paths.get(normalized_input_path)
            : undefined;
        let private_key_open_count = existing_private_key_state?.open_count ?? 0;
        let private_key_continuation = private_key_open_count > 0;
        let private_key_marker_tail = existing_private_key_state?.marker_tail ?? '';
        let modified = false;
        const new_content = event.content.map((item) => {
            if (!is_text_content(item) || !item.text)
                return item;
            const private_key_scan = scan_private_key_state(item.text, private_key_open_count, private_key_marker_tail);
            const { redacted, count } = redact_text(item.text, {
                force_ssh_config,
                force_private_key: private_key_continuation ||
                    private_key_scan.begin_crossed_chunk,
            });
            if (count > 0) {
                modified = true;
                total_redacted += count;
            }
            private_key_open_count = private_key_scan.open_count;
            private_key_continuation = private_key_open_count > 0;
            private_key_marker_tail = private_key_scan.marker_tail;
            return { ...item, text: redacted };
        });
        if (normalized_input_path) {
            if (private_key_continuation || private_key_marker_tail) {
                partial_private_key_paths.set(normalized_input_path, {
                    open_count: private_key_open_count,
                    marker_tail: private_key_marker_tail,
                });
            }
            else {
                partial_private_key_paths.delete(normalized_input_path);
            }
        }
        if (modified)
            return { content: new_content };
    });
    pi.registerCommand('redact-stats', {
        description: 'Show how many secrets have been redacted',
        handler: async (_args, ctx) => {
            ctx.ui.notify(`Secrets redacted this session: ${total_redacted}`);
        },
    });
}
//# sourceMappingURL=index.js.map