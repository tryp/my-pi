export interface WindowedReplacementResult {
	redacted: string;
	count: number;
}

interface OwnedEdit {
	start: number;
	end: number;
	replacement: string;
}

export interface BoundedPattern {
	name: string;
	pattern: RegExp;
	/** Legacy descriptive metadata only; never used as a safety bound. */
	max_match_chars: number;
}

export function initialize_pattern_registry(
	patterns: readonly BoundedPattern[],
	_overlap_chars: number,
): readonly BoundedPattern[] {
	// A caller-provided length cannot prove a regex has a bounded match.
	return patterns;
}

export const MAX_REDACTION_CHUNK_CHARS = 256 * 1024;
export const MAX_JWT_COMPONENT_CHARS = 8_192;
export const MAX_REDACTION_MATCH_CHARS =
	3 * MAX_JWT_COMPONENT_CHARS + 5;
export const REDACTION_OVERLAP_CHARS = MAX_REDACTION_MATCH_CHARS;

/**
 * Match against the complete original input, then apply absolute-offset edits
 * in one pass. The legacy function name and sizing arguments are retained for
 * compatibility; correctness never depends on them.
 */
export function replace_owned_matches(
	text: string,
	pattern: RegExp,
	replacement_for_match: (match: RegExpExecArray) => string | undefined,
	_core_chars: number,
	_overlap_chars: number,
): WindowedReplacementResult {
	const edits: OwnedEdit[] = [];
	pattern.lastIndex = 0;
	let match: RegExpExecArray | null;
	while ((match = pattern.exec(text)) !== null) {
		const replacement = replacement_for_match(match);
		if (replacement !== undefined) {
			edits.push({
				start: match.index,
				end: match.index + match[0].length,
				replacement,
			});
		}
		if (match[0].length === 0) pattern.lastIndex++;
	}

	let redacted = '';
	let cursor = 0;
	for (const edit of edits.sort((a, b) => a.start - b.start)) {
		if (edit.start < cursor) continue;
		redacted += text.slice(cursor, edit.start) + edit.replacement;
		cursor = edit.end;
	}
	redacted += text.slice(cursor);
	return { redacted, count: edits.length };
}
