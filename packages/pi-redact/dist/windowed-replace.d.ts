export interface WindowedReplacementResult {
    redacted: string;
    count: number;
}
export interface BoundedPattern {
    name: string;
    pattern: RegExp;
    /** Legacy descriptive metadata only; never used as a safety bound. */
    max_match_chars: number;
}
export declare function initialize_pattern_registry(patterns: readonly BoundedPattern[], _overlap_chars: number): readonly BoundedPattern[];
export declare const MAX_REDACTION_CHUNK_CHARS: number;
export declare const MAX_JWT_COMPONENT_CHARS = 8192;
export declare const MAX_REDACTION_MATCH_CHARS: number;
export declare const REDACTION_OVERLAP_CHARS: number;
/**
 * Match against the complete original input, then apply absolute-offset edits
 * in one pass. The legacy function name and sizing arguments are retained for
 * compatibility; correctness never depends on them.
 */
export declare function replace_owned_matches(text: string, pattern: RegExp, replacement_for_match: (match: RegExpExecArray) => string | undefined, _core_chars: number, _overlap_chars: number): WindowedReplacementResult;
