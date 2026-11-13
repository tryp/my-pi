export function initialize_pattern_registry(patterns, overlap_chars) {
    for (const { name, max_match_chars } of patterns) {
        if (max_match_chars > overlap_chars) {
            throw new Error(`Redaction pattern ${name} maximum length ${max_match_chars} exceeds configured overlap ${overlap_chars}`);
        }
    }
    return patterns;
}
export const MAX_REDACTION_CHUNK_CHARS = 256 * 1024;
export const MAX_JWT_COMPONENT_CHARS = 8_192;
export const MAX_REDACTION_MATCH_CHARS = 3 * MAX_JWT_COMPONENT_CHARS + 5;
export const REDACTION_OVERLAP_CHARS = MAX_REDACTION_MATCH_CHARS;
const ANCHOR_CONTEXT_CHARS = 1;
/**
 * Apply a global pattern in overlapping windows. A core owns matches by their
 * absolute start offset; edits are applied once, against the original text.
 * Every start owned by a core has up to `overlap_chars` characters of lookahead
 * inside its window slice. Thus every match at or below the configured maximum
 * that starts in that core fits fully in the slice: no seam can split a match,
 * so a credential cannot leak merely because it crosses a window boundary.
 */
export function replace_owned_matches(text, pattern, replacement_for_match, core_chars, overlap_chars) {
    const edits = [];
    for (let core_start = 0; core_start < text.length; core_start += core_chars) {
        const core_end = Math.min(text.length, core_start + core_chars);
        const window_start = Math.max(0, core_start - overlap_chars);
        const window_end = Math.min(text.length, core_end + overlap_chars + ANCHOR_CONTEXT_CHARS);
        const window = text.slice(window_start, window_end);
        pattern.lastIndex = 0;
        let match;
        while ((match = pattern.exec(window)) !== null) {
            if (match[0].length > overlap_chars) {
                throw new Error(`Redaction match length ${match[0].length} exceeded configured overlap ${overlap_chars}`);
            }
            const absolute_start = window_start + match.index;
            if (absolute_start >= core_start && absolute_start < core_end) {
                const absolute_end = absolute_start + match[0].length;
                if (absolute_end > window_end) {
                    throw new Error(`Redaction match exceeded its ${overlap_chars}-character overlap`);
                }
                // `$` may see the artificial end of an overlap window. Do not
                // accept that as EOF or a multiline line ending in the source.
                const artificial_end = absolute_end === window_end && window_end < text.length;
                if (!artificial_end) {
                    const replacement = replacement_for_match(match);
                    if (replacement !== undefined) {
                        edits.push({
                            start: absolute_start,
                            end: absolute_end,
                            replacement,
                        });
                    }
                }
            }
            if (match[0].length === 0)
                pattern.lastIndex++;
        }
    }
    let redacted = '';
    let cursor = 0;
    for (const edit of edits.sort((a, b) => a.start - b.start)) {
        if (edit.start < cursor) {
            throw new Error('Redaction pattern produced overlapping owned matches');
        }
        redacted += text.slice(cursor, edit.start) + edit.replacement;
        cursor = edit.end;
    }
    redacted += text.slice(cursor);
    return { redacted, count: edits.length };
}
//# sourceMappingURL=windowed-replace.js.map