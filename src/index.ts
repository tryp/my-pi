import type {
	ExtensionAPI,
	ExtensionCommandContext,
} from '@earendil-works/pi-coding-agent';
import {
	show_confirm_modal,
	show_picker_modal,
	show_text_modal,
} from '@spences10/pi-tui-modal';
import { Type } from 'typebox';
import {
	CONTEXT_SETTINGS_PRESETS,
	context_settings_from_preset,
	get_context_capture_limits,
	get_context_mcp_output_limits,
	get_context_settings_config_path,
	is_context_settings_preset,
	load_context_settings_config,
	save_context_settings_config,
	type ContextSettingsConfig,
	type ContextSettingsPreset,
} from './config.js';
import {
	get_context_store,
	is_context_sidecar_enabled,
	maybe_store_context_output,
	set_context_sidecar_enabled,
	should_index_text,
	type ContextListResult,
	type ContextPurgeDetails,
	type ContextScopeOptions,
	type ContextSearchResult,
	type ContextStats,
} from './store.js';

function is_text_content(
	item: unknown,
): item is { type: 'text'; text: string } {
	return (
		!!item &&
		typeof item === 'object' &&
		(item as { type?: unknown }).type === 'text' &&
		typeof (item as { text?: unknown }).text === 'string'
	);
}

function summarize_tool_input(input: unknown): string | null {
	if (!input || typeof input !== 'object') return null;
	try {
		const json = JSON.stringify(input);
		return json.length > 500 ? `${json.slice(0, 497)}...` : json;
	} catch {
		return null;
	}
}

function should_skip_tool(tool_name: string): boolean {
	// Coverage policy:
	// - context_* tools are retrieval/maintenance output; indexing them would
	//   recurse and make the sidecar harder to reason about.
	// - team output is coordination state, not bulky artifact content; keep it in
	//   team/pirecall surfaces rather than duplicating mailbox/task state here.
	// - MCP receipts are produced before generic tool_result hooks; the hook also
	//   ignores existing [context-sidecar] receipts so direct MCP storage is not
	//   indexed a second time.
	return (
		tool_name === 'context_search' ||
		tool_name === 'context_get' ||
		tool_name === 'context_list' ||
		tool_name === 'context_stats' ||
		tool_name === 'context_purge' ||
		tool_name === 'team'
	);
}

function session_id_from_context(
	ctx?: Pick<ExtensionCommandContext, 'sessionManager'>,
): string | null {
	const manager = ctx?.sessionManager;
	return (
		manager?.getSessionFile?.() ?? manager?.getSessionId?.() ?? null
	);
}

function scope_from_context(
	ctx?: Pick<ExtensionCommandContext, 'cwd' | 'sessionManager'>,
): ContextScopeOptions {
	return {
		project_path: ctx?.cwd ?? process.cwd(),
		session_id: session_id_from_context(ctx),
	};
}

function format_search_results(
	results: ContextSearchResult[],
): string {
	if (results.length === 0) return 'No indexed context matched.';
	return results
		.map((result, index) =>
			[
				`## ${index + 1}. ${result.title ?? result.chunk_id}`,
				`Source: ${result.source_id} • Chunk: ${result.chunk_id} • Tool: ${result.tool_name}`,
				'',
				result.content,
			].join('\n'),
		)
		.join('\n\n---\n\n');
}

function format_list_results(results: ContextListResult[]): string {
	if (results.length === 0)
		return 'No indexed context sources found.';
	return results
		.map((result) =>
			[
				`## ${result.source_id}`,
				`Created: ${new Date(result.created_at).toISOString()} • Tool: ${result.tool_name}`,
				`Size: ${result.bytes} bytes, ${result.lines} lines, ${result.chunk_count} chunks`,
				`Project: ${result.project_path ?? '(none)'}`,
				`Session: ${result.session_id ?? '(none)'}`,
				result.input_summary
					? `Input: ${result.input_summary}`
					: undefined,
				result.first_chunk_title
					? `First chunk: ${result.first_chunk_title}`
					: undefined,
				result.preview ? `Preview: ${result.preview}` : undefined,
			]
				.filter(Boolean)
				.join('\n'),
		)
		.join('\n\n');
}

function format_purge_details(details: ContextPurgeDetails): string {
	const filters = [
		details.source_id ? `source_id=${details.source_id}` : undefined,
		details.project_path !== undefined
			? `project_path=${details.project_path ?? '(none)'}`
			: undefined,
		details.session_id !== undefined
			? `session_id=${details.session_id ?? '(none)'}`
			: undefined,
		details.older_than_days !== undefined
			? `older_than_days=${details.older_than_days}`
			: undefined,
	]
		.filter(Boolean)
		.join(', ');
	return `Deleted ${details.deleted} context source(s).${filters ? ` Filters: ${filters}.` : ''}`;
}

function format_stats(stats: ContextStats): string {
	const scoped = stats.scope_project_path || stats.scope_session_id;
	return [
		'## context-sidecar stats',
		'',
		`- Enabled: ${is_context_sidecar_enabled()}`,
		scoped
			? `- Scope: project=${stats.scope_project_path ?? '(none)'}, session=${stats.scope_session_id ?? '(none)'}`
			: '- Scope: global',
		`- Scoped sources: ${stats.sources}`,
		`- Scoped chunks: ${stats.chunks}`,
		`- Scoped raw bytes stored: ${stats.bytes_stored}`,
		`- Global sources: ${stats.global_sources}`,
		`- Global chunks: ${stats.global_chunks}`,
		`- Global raw bytes stored: ${stats.global_bytes_stored}`,
		`- Bytes returned: ${stats.bytes_returned}`,
		`- Bytes saved: ${stats.bytes_saved}`,
		`- Reduction: ${stats.reduction_pct}%`,
		`- DB bytes: ${stats.total_bytes}`,
		`- Scoped oldest source: ${format_timestamp(stats.oldest_created_at)}`,
		`- Scoped newest source: ${format_timestamp(stats.newest_created_at)}`,
		`- Global oldest source: ${format_timestamp(stats.global_oldest_created_at)}`,
		`- Global newest source: ${format_timestamp(stats.global_newest_created_at)}`,
		`- Retention days: ${stats.retention_days ?? 'disabled'}`,
		`- Purge on shutdown: ${stats.purge_on_shutdown}`,
		`- Max DB size: ${stats.max_mb === null ? 'disabled' : `${stats.max_mb} MiB`}`,
	].join('\n');
}

function format_timestamp(timestamp: number | null): string {
	return timestamp === null
		? '(none)'
		: new Date(timestamp).toISOString();
}

function format_days(days: number | null): string {
	return days === null ? 'disabled' : `${days} day(s)`;
}

function format_max_mb(max_mb: number | null): string {
	return max_mb === null ? 'disabled' : `${max_mb} MiB`;
}

function format_kib(bytes: number): string {
	return `${Math.round(bytes / 1024)} KiB`;
}

function format_output_limit(bytes: number, lines: number): string {
	return `${format_kib(bytes)} / ${lines} lines`;
}

function format_context_settings_status(stats: ContextStats): string {
	const saved = load_context_settings_config();
	const capture_limits = get_context_capture_limits();
	const mcp_limits = get_context_mcp_output_limits();
	return [
		'## context-sidecar settings',
		'',
		`- Config path: ${get_context_settings_config_path()}`,
		`- Saved preset: ${saved?.preset ?? '(none; using built-in defaults)'}`,
		`- Effective retention: ${format_days(stats.retention_days)}`,
		`- Effective max size: ${format_max_mb(stats.max_mb)}`,
		`- Effective purge on shutdown: ${stats.purge_on_shutdown}`,
		`- Effective tool capture threshold: ${format_output_limit(capture_limits.max_bytes, capture_limits.max_lines)}`,
		`- Effective MCP capture threshold: ${format_output_limit(mcp_limits.max_bytes, mcp_limits.max_lines)}`,
		'',
		'Presets:',
		...Object.entries(CONTEXT_SETTINGS_PRESETS).map(
			([key, preset]) => `- ${key}: ${preset.description}`,
		),
		'',
		'Usage:',
		'- /context settings <preset>',
		'- /context settings custom <days|off> <max-mb|off> [capture-kb] [capture-lines] [purge-on-shutdown]',
	].join('\n');
}

function parse_optional_setting_number(value: string): number | null {
	const normalized = value.trim().toLowerCase();
	if (
		['0', 'off', 'false', 'none', 'disabled'].includes(normalized)
	) {
		return null;
	}
	const parsed = Number(normalized);
	if (!Number.isFinite(parsed) || parsed <= 0) {
		throw new Error('Expected a positive number or off.');
	}
	return parsed;
}

function parse_optional_setting_boolean(
	value: string | undefined,
	fallback = false,
): boolean {
	if (!value) return fallback;
	const normalized = value.trim().toLowerCase();
	if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
	if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
	throw new Error('Expected purge-on-shutdown to be true or false.');
}

function parse_positive_setting_number(value: string): number {
	const parsed = Number(value.trim());
	if (!Number.isFinite(parsed) || parsed <= 0) {
		throw new Error('Expected a positive number.');
	}
	return parsed;
}

type ContextSettingsPatch = Partial<
	Omit<ContextSettingsConfig, 'version' | 'preset'>
>;

const RETENTION_SETTING_OPTIONS = [
	{
		value: '1',
		label: '1 day',
		description: 'Minimal local cache',
		days: 1,
	},
	{
		value: '7',
		label: '7 days',
		description: 'Default retention',
		days: 7,
	},
	{
		value: '30',
		label: '30 days',
		description: 'Research window',
		days: 30,
	},
	{
		value: '90',
		label: '90 days',
		description: 'Long-lived local archive',
		days: 90,
	},
	{
		value: 'off',
		label: 'Off',
		description: 'Disable age cleanup',
		days: null,
	},
] as const;

const STORAGE_CAP_SETTING_OPTIONS = [
	{
		value: '50',
		label: '50 MiB',
		description: 'Small local cache',
		max_mb: 50,
	},
	{
		value: '250',
		label: '250 MiB',
		description: 'Balanced cap',
		max_mb: 250,
	},
	{
		value: '1024',
		label: '1 GiB',
		description: 'Research cap',
		max_mb: 1024,
	},
	{
		value: '5120',
		label: '5 GiB',
		description: 'Archive cap',
		max_mb: 5120,
	},
	{
		value: 'off',
		label: 'No cap',
		description: 'Only retention controls cleanup',
		max_mb: null,
	},
] as const;

const CAPTURE_SIZE_SETTING_OPTIONS = [
	{
		value: 'small',
		label: 'Small',
		description: 'Capture after 16 KiB / 200 lines',
		capture_max_bytes: 16 * 1024,
		capture_max_lines: 200,
		mcp_max_bytes: 32 * 1024,
		mcp_max_lines: 1_000,
	},
	{
		value: 'default',
		label: 'Default',
		description: 'Capture after 24 KiB / 300 lines',
		capture_max_bytes: 24 * 1024,
		capture_max_lines: 300,
		mcp_max_bytes: 50 * 1024,
		mcp_max_lines: 2_000,
	},
	{
		value: 'large',
		label: 'Large',
		description: 'Capture after 48 KiB / 600 lines',
		capture_max_bytes: 48 * 1024,
		capture_max_lines: 600,
		mcp_max_bytes: 96 * 1024,
		mcp_max_lines: 3_000,
	},
	{
		value: 'huge',
		label: 'Huge',
		description: 'Capture after 64 KiB / 1,000 lines',
		capture_max_bytes: 64 * 1024,
		capture_max_lines: 1_000,
		mcp_max_bytes: 128 * 1024,
		mcp_max_lines: 4_000,
	},
] as const;

async function show_context_text_modal(
	ctx: ExtensionCommandContext,
	title: string,
	text: string,
): Promise<void> {
	await show_text_modal(ctx, {
		title,
		text,
		max_visible_lines: 18,
		overlay_options: { width: '80%', minWidth: 64 },
	});
}

async function show_context_stats(
	ctx: ExtensionCommandContext,
): Promise<void> {
	const scope = scope_from_context(ctx);
	const text = format_stats(get_context_store(scope).stats(scope));
	if (ctx.hasUI) {
		await show_context_text_modal(ctx, 'Context sidecar stats', text);
	} else {
		ctx.ui.notify(text, 'info');
	}
}

function save_context_settings(
	ctx: ExtensionCommandContext,
	config: ContextSettingsConfig,
): void {
	save_context_settings_config(config);
	const scope = scope_from_context(ctx);
	const cleanup = get_context_store(scope).cleanup();
	ctx.ui.notify(
		`Context settings saved: ${config.preset} (${format_days(config.retention_days)}, ${format_max_mb(config.max_mb)} cap, capture ${format_output_limit(config.capture_max_bytes, config.capture_max_lines)}). Cleanup deleted ${cleanup.deleted} source(s).`,
		'info',
	);
}

function save_context_settings_patch(
	ctx: ExtensionCommandContext,
	patch: ContextSettingsPatch,
): void {
	const base =
		load_context_settings_config() ??
		context_settings_from_preset('default');
	save_context_settings(ctx, {
		...base,
		...patch,
		version: 1,
		preset: 'custom',
	});
}

async function show_context_preset_settings(
	ctx: ExtensionCommandContext,
): Promise<void> {
	const saved = load_context_settings_config();
	const selected = await show_picker_modal(ctx, {
		title: 'Context preset',
		subtitle:
			'Apply retention, storage, and capture thresholds together',
		items: Object.entries(CONTEXT_SETTINGS_PRESETS).map(
			([key, preset]) => ({
				value: key,
				label: `${preset.label}${saved?.preset === key ? ' ✓' : ''}`,
				description: preset.description,
			}),
		),
		footer: 'enter applies preset • esc back',
	});
	if (!selected) return;
	save_context_settings(
		ctx,
		context_settings_from_preset(selected as ContextSettingsPreset),
	);
}

async function show_context_retention_settings(
	ctx: ExtensionCommandContext,
): Promise<void> {
	const current = load_context_settings_config();
	const selected = await show_picker_modal(ctx, {
		title: 'Context retention days',
		subtitle: `Current: ${format_days(current?.retention_days ?? 7)}`,
		items: RETENTION_SETTING_OPTIONS.map((option) => ({
			value: option.value,
			label: `${option.label}${current?.retention_days === option.days ? ' ✓' : ''}`,
			description: option.description,
		})),
		footer: 'enter saves • esc back',
	});
	const option = RETENTION_SETTING_OPTIONS.find(
		(item) => item.value === selected,
	);
	if (!option) return;
	save_context_settings_patch(ctx, { retention_days: option.days });
}

async function show_context_storage_cap_settings(
	ctx: ExtensionCommandContext,
): Promise<void> {
	const current = load_context_settings_config();
	const selected = await show_picker_modal(ctx, {
		title: 'Context storage cap',
		subtitle: `Current: ${format_max_mb(current?.max_mb ?? null)}`,
		items: STORAGE_CAP_SETTING_OPTIONS.map((option) => ({
			value: option.value,
			label: `${option.label}${current?.max_mb === option.max_mb ? ' ✓' : ''}`,
			description: option.description,
		})),
		footer: 'enter saves • esc back',
	});
	const option = STORAGE_CAP_SETTING_OPTIONS.find(
		(item) => item.value === selected,
	);
	if (!option) return;
	save_context_settings_patch(ctx, { max_mb: option.max_mb });
}

async function show_context_capture_size_settings(
	ctx: ExtensionCommandContext,
): Promise<void> {
	const current = load_context_settings_config();
	const capture_limits = get_context_capture_limits();
	const selected = await show_picker_modal(ctx, {
		title: 'Context capture size',
		subtitle: `Current: ${format_output_limit(capture_limits.max_bytes, capture_limits.max_lines)}`,
		items: CAPTURE_SIZE_SETTING_OPTIONS.map((option) => ({
			value: option.value,
			label: `${option.label}${current?.capture_max_bytes === option.capture_max_bytes && current?.capture_max_lines === option.capture_max_lines ? ' ✓' : ''}`,
			description: option.description,
		})),
		footer: 'enter saves • esc back',
	});
	const option = CAPTURE_SIZE_SETTING_OPTIONS.find(
		(item) => item.value === selected,
	);
	if (!option) return;
	save_context_settings_patch(ctx, {
		capture_max_bytes: option.capture_max_bytes,
		capture_max_lines: option.capture_max_lines,
		mcp_max_bytes: option.mcp_max_bytes,
		mcp_max_lines: option.mcp_max_lines,
	});
}

async function show_context_settings(
	ctx: ExtensionCommandContext,
	options: { nested?: boolean } = {},
): Promise<void> {
	if (!ctx.hasUI) {
		const scope = scope_from_context(ctx);
		ctx.ui.notify(
			format_context_settings_status(
				get_context_store(scope).stats(scope),
			),
			'info',
		);
		return;
	}

	while (true) {
		const scope = scope_from_context(ctx);
		const stats = get_context_store(scope).stats(scope);
		const capture_limits = get_context_capture_limits();
		const selected = await show_picker_modal(ctx, {
			title: 'Context sidecar settings',
			subtitle: `Current: ${format_days(stats.retention_days)}, ${format_max_mb(stats.max_mb)} cap, capture ${format_output_limit(capture_limits.max_bytes, capture_limits.max_lines)}`,
			items: [
				{
					value: 'capture-size',
					label: 'Capture size',
					description: 'Choose when output is moved into sidecar',
				},
				{
					value: 'retention-days',
					label: 'Retention days',
					description: 'Choose how long indexed output is kept',
				},
				{
					value: 'storage-cap',
					label: 'Storage cap',
					description: 'Choose max raw bytes stored locally',
				},
				{
					value: 'presets',
					label: 'Presets',
					description: 'Apply bundled settings all at once',
				},
				{
					value: 'show',
					label: 'Show current settings',
					description: 'Inspect effective saved/env-backed policy',
				},
			],
			footer: `enter opens • esc ${options.nested ? 'back' : 'close'}`,
		});

		if (!selected) return;
		if (selected === 'capture-size') {
			await show_context_capture_size_settings(ctx);
		} else if (selected === 'retention-days') {
			await show_context_retention_settings(ctx);
		} else if (selected === 'storage-cap') {
			await show_context_storage_cap_settings(ctx);
		} else if (selected === 'presets') {
			await show_context_preset_settings(ctx);
		} else if (selected === 'show') {
			await show_context_text_modal(
				ctx,
				'Context sidecar settings',
				format_context_settings_status(stats),
			);
		}
	}
}

async function handle_context_settings(
	ctx: ExtensionCommandContext,
	args: string[],
): Promise<void> {
	const [
		kind,
		days_text,
		max_mb_text,
		capture_kb_text,
		capture_lines_text,
		purge_text,
	] = args;
	if (!kind) {
		await show_context_settings(ctx);
		return;
	}
	if (kind === 'show' || kind === 'current') {
		const scope = scope_from_context(ctx);
		const text = format_context_settings_status(
			get_context_store(scope).stats(scope),
		);
		if (ctx.hasUI) {
			await show_context_text_modal(
				ctx,
				'Context sidecar settings',
				text,
			);
		} else {
			ctx.ui.notify(text, 'info');
		}
		return;
	}
	if (is_context_settings_preset(kind)) {
		save_context_settings(ctx, context_settings_from_preset(kind));
		return;
	}
	if (kind === 'custom') {
		if (!days_text || !max_mb_text) {
			ctx.ui.notify(
				'Usage: /context settings custom <days|off> <max-mb|off> [capture-kb] [capture-lines] [purge-on-shutdown]',
				'warning',
			);
			return;
		}
		try {
			const base =
				load_context_settings_config() ??
				context_settings_from_preset('default');
			save_context_settings(ctx, {
				version: 1,
				preset: 'custom',
				retention_days: parse_optional_setting_number(days_text),
				max_mb: parse_optional_setting_number(max_mb_text),
				capture_max_bytes: capture_kb_text
					? parse_positive_setting_number(capture_kb_text) * 1024
					: base.capture_max_bytes,
				capture_max_lines: capture_lines_text
					? parse_positive_setting_number(capture_lines_text)
					: base.capture_max_lines,
				mcp_max_bytes: capture_kb_text
					? parse_positive_setting_number(capture_kb_text) * 1024
					: base.mcp_max_bytes,
				mcp_max_lines: capture_lines_text
					? parse_positive_setting_number(capture_lines_text)
					: base.mcp_max_lines,
				purge_on_shutdown: parse_optional_setting_boolean(
					purge_text,
					base.purge_on_shutdown,
				),
			});
		} catch (error) {
			ctx.ui.notify(
				error instanceof Error ? error.message : String(error),
				'warning',
			);
		}
		return;
	}

	ctx.ui.notify(
		`Unknown context settings preset: ${kind}. Use ${Object.keys(CONTEXT_SETTINGS_PRESETS).join(', ')}, show, or custom.`,
		'warning',
	);
}

async function show_context_list(
	ctx: ExtensionCommandContext,
	limit?: number,
): Promise<void> {
	const scope = scope_from_context(ctx);
	const text = format_list_results(
		get_context_store(scope).list({ ...scope, limit }),
	);
	if (ctx.hasUI) {
		await show_context_text_modal(
			ctx,
			'Context sidecar sources',
			text,
		);
	} else {
		ctx.ui.notify(text, 'info');
	}
}

async function purge_context(
	ctx: ExtensionCommandContext,
	options: {
		older_than_days?: number;
		source_id?: string;
		expired?: boolean;
	} = {},
): Promise<void> {
	const policy = get_context_store().stats();
	const days = options.older_than_days ?? policy.retention_days ?? 14;
	const description = options.expired
		? 'Delete expired context sources now?'
		: options.source_id
			? `Delete context source ${options.source_id}?`
			: `Delete context sources older than ${days} day(s)?`;
	const confirmed = ctx.hasUI
		? await show_confirm_modal(ctx, {
				title: 'Purge context sidecar?',
				message: description,
				confirm_label: 'Purge',
			})
		: await ctx.ui.confirm('Purge context sidecar?', description);
	if (!confirmed) return;
	const scope = scope_from_context(ctx);
	const details = options.expired
		? { deleted: get_context_store(scope).cleanup().deleted }
		: get_context_store(scope).purge_with_details({
				...scope,
				older_than_days: options.source_id ? undefined : days,
				source_id: options.source_id,
			});
	ctx.ui.notify(format_purge_details(details), 'info');
}

async function show_context_menu(
	ctx: ExtensionCommandContext,
): Promise<void> {
	while (true) {
		const selected = await show_picker_modal(ctx, {
			title: 'Context sidecar',
			subtitle: 'Local SQLite storage for oversized tool output',
			items: [
				{
					value: 'list',
					label: 'List recent sources',
					description: 'Browse indexed output in this scope',
				},
				{
					value: 'stats',
					label: 'Show stats',
					description: 'Byte accounting and storage reduction',
				},
				{
					value: 'settings',
					label: 'Configure settings',
					description:
						'Configure capture size, retention, and storage cap',
				},
				{
					value: 'purge',
					label: 'Purge old context',
					description: 'Delete sources older than 14 days',
				},
			],
			footer: 'enter opens • esc close',
		});
		if (!selected) return;
		if (selected === 'list') await show_context_list(ctx);
		else if (selected === 'stats') await show_context_stats(ctx);
		else if (selected === 'settings')
			await show_context_settings(ctx, { nested: true });
		else await purge_context(ctx);
	}
}

export default function context_sidecar(pi: ExtensionAPI): void {
	set_context_sidecar_enabled(true, { project_path: process.cwd() });

	pi.on('session_start', async (_event, ctx) => {
		const scope = scope_from_context(ctx);
		set_context_sidecar_enabled(true, scope);
		get_context_store(scope).cleanup();
	});

	pi.on('session_shutdown', async () => {
		const store = get_context_store();
		const stats = store.stats();
		if (stats.purge_on_shutdown) store.cleanup();
		set_context_sidecar_enabled(false);
	});

	pi.on('tool_result', async (event, ctx) => {
		const tool_name = String(event.toolName ?? 'tool');
		if (should_skip_tool(tool_name)) return;
		if (!Array.isArray(event.content)) return;

		const text_items = event.content.filter(is_text_content);
		if (text_items.length === 0) return;
		const text = text_items.map((item) => item.text).join('\n');
		if (text.includes('[context-sidecar]')) return;
		if (!should_index_text(text)) return;

		try {
			const stored = maybe_store_context_output({
				text,
				tool_name,
				input_summary: summarize_tool_input(event.input),
				...scope_from_context(ctx),
			});
			if (!stored) return;
			return {
				content: [{ type: 'text' as const, text: stored.receipt }],
			};
		} catch {
			return;
		}
	});

	pi.registerTool({
		name: 'context_search',
		label: 'Context Search',
		description:
			'Search large tool output stored in the local SQLite context sidecar.',
		promptSnippet:
			'Search oversized tool output that was indexed into the local context sidecar',
		parameters: Type.Object({
			query: Type.String({ description: 'FTS search query' }),
			source_id: Type.Optional(
				Type.String({
					description: 'Limit to one indexed source id',
				}),
			),
			tool_name: Type.Optional(
				Type.String({ description: 'Limit to one tool name' }),
			),
			limit: Type.Optional(
				Type.Number({
					description: 'Maximum chunks to return, default 5',
				}),
			),
			global: Type.Optional(
				Type.Boolean({
					description:
						'Search all indexed sources instead of current project/session scope',
				}),
			),
		}),
		async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
			const scope = scope_from_context(ctx);
			const results = get_context_store(scope).search(params.query, {
				...(params.global ? {} : scope),
				global: params.global,
				source_id: params.source_id,
				tool_name: params.tool_name,
				limit: params.limit,
			});
			return {
				content: [
					{
						type: 'text' as const,
						text: format_search_results(results),
					},
				],
				details: { count: results.length },
			};
		},
	});

	pi.registerTool({
		name: 'context_get',
		label: 'Context Get',
		description:
			'Retrieve exact chunks from the local SQLite context sidecar.',
		promptSnippet: 'Retrieve exact stored output chunks by source id',
		parameters: Type.Object({
			source_id: Type.String({ description: 'Indexed source id' }),
			chunk_id: Type.Optional(
				Type.String({ description: 'Optional exact chunk id' }),
			),
			global: Type.Optional(
				Type.Boolean({
					description:
						'Retrieve across all scopes instead of current project/session scope',
				}),
			),
		}),
		async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
			const scope = scope_from_context(ctx);
			const store = get_context_store(scope);
			const scope_options = {
				...(params.global ? {} : scope),
				global: params.global,
			};
			const chunks = store.get(
				params.source_id,
				params.chunk_id,
				scope_options,
			);
			let text = chunks.length
				? chunks
						.map((chunk) =>
							[
								`## ${chunk.id}`,
								`Source: ${chunk.source_id} • Chunk ${chunk.ordinal}`,
								'',
								chunk.content,
							].join('\n'),
						)
						.join('\n\n---\n\n')
				: 'No chunks found.';
			const summary =
				chunks.length === 0 && params.chunk_id
					? store.chunk_summary(params.source_id, scope_options)
					: null;
			if (summary && summary.chunk_count > 0) {
				const range =
					summary.first_chunk_id === summary.last_chunk_id
						? summary.first_chunk_id
						: `${summary.first_chunk_id} … ${summary.last_chunk_id}`;
				text = [
					`No chunk found for chunk_id "${params.chunk_id}".`,
					`Source ${params.source_id} has ${summary.chunk_count} chunk(s): ${range}.`,
					`Valid ordinals: ${summary.first_ordinal} … ${summary.last_ordinal}.`,
					summary.first_chunk_id
						? `Try chunk_id:"${summary.first_chunk_id}" or chunk_id:"1".`
						: undefined,
				]
					.filter((line): line is string => line !== undefined)
					.join('\n');
			}
			return {
				content: [{ type: 'text' as const, text }],
				details: { count: chunks.length },
			};
		},
	});

	pi.registerTool({
		name: 'context_list',
		label: 'Context List',
		description:
			'List indexed sources in the local SQLite context sidecar.',
		promptSnippet:
			'List recent indexed context-sidecar sources without knowing a source id',
		parameters: Type.Object({
			source_id: Type.Optional(
				Type.String({ description: 'Limit to one source id' }),
			),
			tool_name: Type.Optional(
				Type.String({ description: 'Limit to one tool name' }),
			),
			project_path: Type.Optional(
				Type.String({ description: 'Limit to one project path' }),
			),
			session_id: Type.Optional(
				Type.String({ description: 'Limit to one session id' }),
			),
			newer_than_days: Type.Optional(
				Type.Number({
					description: 'Only sources newer than N days',
				}),
			),
			older_than_days: Type.Optional(
				Type.Number({
					description: 'Only sources older than N days',
				}),
			),
			limit: Type.Optional(
				Type.Number({ description: 'Maximum sources, default 10' }),
			),
			offset: Type.Optional(
				Type.Number({ description: 'Pagination offset, default 0' }),
			),
			global: Type.Optional(
				Type.Boolean({
					description:
						'List all scopes instead of current project/session scope',
				}),
			),
		}),
		async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
			const scope = scope_from_context(ctx);
			const has_explicit_scope =
				params.project_path !== undefined ||
				params.session_id !== undefined;
			const project_path = has_explicit_scope
				? params.project_path
				: scope.project_path;
			const session_id = has_explicit_scope
				? params.session_id
				: scope.session_id;
			const results = get_context_store(scope).list({
				project_path,
				session_id,
				global: params.global || has_explicit_scope,
				source_id: params.source_id,
				tool_name: params.tool_name,
				newer_than_days: params.newer_than_days,
				older_than_days: params.older_than_days,
				limit: params.limit,
				offset: params.offset,
			});
			return {
				content: [
					{
						type: 'text' as const,
						text: format_list_results(results),
					},
				],
				details: { count: results.length },
			};
		},
	});

	pi.registerTool({
		name: 'context_stats',
		label: 'Context Stats',
		description:
			'Show byte accounting for the local SQLite context sidecar.',
		parameters: Type.Object({}),
		async execute(_toolCallId, _params, _signal, _onUpdate, ctx) {
			const scope = scope_from_context(ctx);
			const stats = get_context_store(scope).stats(scope);
			return {
				content: [
					{ type: 'text' as const, text: format_stats(stats) },
				],
				details: stats,
			};
		},
	});

	pi.registerTool({
		name: 'context_purge',
		label: 'Context Purge',
		description:
			'Delete indexed context-sidecar output by age, source, project, session, or active retention policy.',
		parameters: Type.Object({
			expired: Type.Optional(
				Type.Boolean({
					description:
						'Run active retention cleanup now instead of manual age purge',
				}),
			),
			older_than_days: Type.Optional(
				Type.Number({
					description:
						'Delete sources older than this many days; defaults to active retention days or 14',
				}),
			),
			source_id: Type.Optional(
				Type.String({ description: 'Delete one source id' }),
			),
			project_path: Type.Optional(
				Type.String({
					description: 'Limit purge to one project path',
				}),
			),
			session_id: Type.Optional(
				Type.String({ description: 'Limit purge to one session id' }),
			),
			global: Type.Optional(
				Type.Boolean({
					description:
						'Purge all scopes instead of current project/session scope',
				}),
			),
		}),
		async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
			const scope = scope_from_context(ctx);
			const store = get_context_store(scope);
			const stats = store.stats();
			const has_explicit_scope =
				params.project_path !== undefined ||
				params.session_id !== undefined;
			const project_path = params.global
				? params.project_path
				: has_explicit_scope
					? params.project_path
					: scope.project_path;
			const session_id = params.global
				? params.session_id
				: has_explicit_scope
					? params.session_id
					: scope.session_id;
			const details = params.expired
				? { deleted: store.cleanup().deleted }
				: store.purge_with_details({
						project_path,
						session_id,
						older_than_days: params.source_id
							? undefined
							: (params.older_than_days ??
								stats.retention_days ??
								14),
						source_id: params.source_id,
					});
			return {
				content: [
					{
						type: 'text' as const,
						text: format_purge_details(details),
					},
				],
				details,
			};
		},
	});

	pi.registerCommand('context', {
		description: 'Inspect and manage the context sidecar',
		getArgumentCompletions: (prefix) =>
			['list', 'stats', 'settings', 'purge']
				.filter((item) => item.startsWith(prefix.trim()))
				.map((item) => ({ value: item, label: item })),
		handler: async (args, ctx) => {
			const [sub = '', ...rest] = args
				.trim()
				.split(/\s+/)
				.filter(Boolean);
			if (!sub && ctx.hasUI) {
				await show_context_menu(ctx);
				return;
			}

			switch (sub || 'list') {
				case 'list': {
					const [limit_text] = rest;
					const limit = limit_text ? Number(limit_text) : undefined;
					if (limit !== undefined && !Number.isFinite(limit)) {
						ctx.ui.notify('Usage: /context list [limit]', 'warning');
						return;
					}
					await show_context_list(ctx, limit);
					return;
				}
				case 'stats':
					await show_context_stats(ctx);
					return;
				case 'settings':
					await handle_context_settings(ctx, rest);
					return;
				case 'purge': {
					const [kind, value] = rest;
					if (kind === 'expired') {
						await purge_context(ctx, { expired: true });
						return;
					}
					if (kind === 'source' && value) {
						await purge_context(ctx, { source_id: value });
						return;
					}
					const days = kind ? Number(kind) : undefined;
					if (days !== undefined && !Number.isFinite(days)) {
						ctx.ui.notify(
							'Usage: /context purge [older-than-days] | expired | source <source-id>',
							'warning',
						);
						return;
					}
					await purge_context(ctx, { older_than_days: days });
					return;
				}
				default:
					ctx.ui.notify(
						`Unknown context command: ${sub}. Use list, stats, settings, or purge.`,
						'warning',
					);
			}
		},
	});

	pi.registerCommand('context-stats', {
		description: 'Show context sidecar byte accounting',
		handler: async (_args, ctx) => {
			await show_context_stats(ctx);
		},
	});
}

export {
	CONTEXT_SETTINGS_PRESETS,
	context_settings_from_preset,
	get_context_capture_limits,
	get_context_mcp_output_limits,
	get_context_settings_config_path,
	load_context_settings_config,
	save_context_settings_config,
} from './config.js';
export type {
	ContextOutputLimits,
	ContextSettingsConfig,
	ContextSettingsPreset,
	ContextSettingsValues,
} from './config.js';
export {
	get_context_store,
	is_context_sidecar_enabled,
	maybe_store_context_output,
	parse_context_retention_policy,
	set_context_sidecar_enabled,
	should_index_text,
} from './store.js';
export type {
	ContextCleanupResult,
	ContextListResult,
	ContextPurgeDetails,
	ContextRetentionPolicy,
	ContextScopeOptions,
	ContextSearchResult,
	ContextStats,
	StoreContextInput,
	StoredContextOutput,
} from './store.js';
