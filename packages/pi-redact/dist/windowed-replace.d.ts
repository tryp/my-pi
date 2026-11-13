export interface WindowedReplacementResult {
    redacted: string;
    count: number;
}
export interface BoundedPattern {
    name: string;
    pattern: RegExp;
    max_match_chars: number;
}
export declare function initialize_pattern_registry(patterns: readonly BoundedPattern[], overlap_chars: number): readonly BoundedPattern[];
export declare const MAX_REDACTION_CHUNK_CHARS: number;
export declare const MAX_JWT_COMPONENT_CHARS = 8192;
export declare const MAX_REDACTION_MATCH_CHARS: number;
export declare const REDACTION_OVERLAP_CHARS: number;
/**
 * Apply a global pattern in overlapping windows. A core owns matches by their
 * absolute start offset; edits are applied once, against the original text.
 * Every start owned by a core has up to `overlap_chars` characters of lookahead
 * inside its window slice. Thus every match at or below the configured maximum
 * that starts in that core fits fully in the slice: no seam can split a match,
 * so a credential cannot leak merely because it crosses a window boundary.
 */
export declare function replace_owned_matches(text: string, pattern: RegExp, replacement_for_match: (match: RegExpExecArray) => string | undefined, core_chars: number, overlap_chars: number): WindowedReplacementResult;
