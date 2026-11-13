import type { ExtensionAPI } from '@earendil-works/pi-coding-agent';
interface RedactionResult {
    redacted: string;
    count: number;
}
interface RedactionOptions {
    force_ssh_config?: boolean;
}
export declare function looks_like_ssh_config(text: string): boolean;
export declare function redact_ssh_config_metadata(text: string): RedactionResult;
export declare function redact_text(text: string, options?: RedactionOptions): RedactionResult;
export declare function process_read_text(path: string, text: string): string;
export default function filter_output(pi: ExtensionAPI): Promise<void>;
export {};
