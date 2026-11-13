export interface WindowedReplacementResult {
	redacted: string;
	count: number;
}

interface OwnedEdit {
	start: number;
	end: number;
	replacement: string;
}

export const MAX_REDACTION_CHUNK_CHARS = 256 * 1024;
export const MAX_JWT_COMPONENT_CHARS = 8_192;
export const MAX_REDACTION_MATCH_CHARS =
	3 * MAX_JWT_COMPONENT_CHARS + 5;
export const REDACTION_OVERLAP_CHARS = MAX_REDACTION_MATCH_CHARS;

const ANCHOR_CONTEXT_CHARS = 1;

/**
 * Apply a global pattern in overlapping windows. A core owns matches by their
 * absolute start offset; edits are applied once, against the original text.
 */
export function replace_owned_matches(
	text: string,
	pattern: RegExp,
	replacement_for_match: (match: RegExpExecArray) => string | undefined,
	core_chars: number,
	overlap_chars: number,
): WindowedReplacementResult {
	const edits: OwnedEdit[] = [];

	for (let core_start = 0; core_start < text.length; core_start += core_chars) {
		const core_end = Math.min(text.length, core_start + core_chars);
		const window_start = Math.max(0, core_start - overlap_chars);
		const window_end = Math.min(
			text.length,
			core_end + overlap_chars + ANCHOR_CONTEXT_CHARS,
		);
		const window = text.slice(window_start, window_end);
		pattern.lastIndex = 0;

		let match: RegExpExecArray | null;
		while ((match = pattern.exec(window)) !== null) {
			if (match[0].length > overlap_chars) {
				throw new Error(
					`Redaction match length ${match[0].length} exceeded configured overlap ${overlap_chars}`,
				);
			}
			const absolute_start = window_start + match.index;
			if (absolute_start >= core_start && absolute_start < core_end) {
				const absolute_end = absolute_start + match[0].length;
				if (absolute_end > window_end) {
					throw new Error(
					`Redaction match exceeded its ${overlap_chars}-character overlap`,
					);
				}
				// `$` may see the artificial end of an overlap window. Do not
				// accept that as EOF or a multiline line ending in the source.
				const artificial_end =
					absolute_end === window_end && window_end < text.length;
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
			if (match[0].length === 0) pattern.lastIndex++;
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
