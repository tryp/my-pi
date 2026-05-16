import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ContextStore } from './store.js';

interface SeededSource {
	name: string;
	source_id: string;
	first_chunk_id: string | null;
}

interface SearchScenario {
	name: string;
	query: string;
	source: string;
	expect: string;
	limit?: number;
	description: string;
}

interface GetScenario {
	name: string;
	source: string;
	chunk_id: string;
	expect: string;
	description: string;
}

interface EvalCaseResult {
	name: string;
	type: 'search' | 'get';
	passed: boolean;
	description: string;
	detail: string;
	returned_bytes: number;
	result_count: number;
}

interface EvalReport {
	version: 1;
	summary: {
		passed: number;
		failed: number;
		total: number;
		score_pct: number;
		returned_bytes: number;
	};
	results: EvalCaseResult[];
}

const PROJECT = '/tmp/pi-context-eval-project';
const SESSION = '/tmp/pi-context-eval-session.jsonl';

const search_scenarios: SearchScenario[] = [
	{
		name: 'exact-token-baseline',
		source: 'needle-log',
		query: 'TARGET_VALUE',
		expect: 'TARGET_VALUE appears on line 855',
		limit: 5,
		description:
			'Basic exact-token lookup should work before and after.',
	},
	{
		name: 'over-specific-human-query',
		source: 'staging-help',
		query:
			'stage specific chunk line commit checks amend author sign-off',
		expect: 'Press space to stage this hunk',
		limit: 5,
		description:
			'Human/agent query contains useful words plus absent words; strict AND search currently misses.',
	},
	{
		name: 'literal-or-query',
		source: 'skill-script',
		query:
			'run_gh_skill_update OR run_gh_skill_install OR case update',
		expect: 'run_gh_skill_update',
		limit: 5,
		description:
			'Queries copied from agent reasoning often include OR; search should treat this as alternatives, not require literal OR.',
	},
	{
		name: 'punctuation-symbol-query',
		source: 'code-symbols',
		query: 'registerCommand context-stats',
		expect: "registerCommand('context-stats'",
		limit: 5,
		description:
			'Code and command names include punctuation that should not make retrieval brittle.',
	},
	{
		name: 'chunk-boundary-query',
		source: 'chunk-boundary',
		query: 'alpha-token omega-token',
		expect: 'alpha-token',
		limit: 5,
		description:
			'Useful terms may be split across chunks; strict per-chunk AND search misses them.',
	},
];

const get_scenarios: GetScenario[] = [
	{
		name: 'get-first-ordinal-alias',
		source: 'needle-log',
		chunk_id: '1',
		expect: 'before noise line 0',
		description:
			'Receipt-led chunk retrieval via ordinal alias should stay reliable.',
	},
];

function make_noise_lines(count: number, prefix: string): string {
	return Array.from(
		{ length: count },
		(_, index) => `${prefix} noise line ${index} ${'x'.repeat(48)}`,
	).join('\n');
}

function source_texts(): Record<
	string,
	{ tool_name: string; text: string }
> {
	return {
		'needle-log': {
			tool_name: 'bash',
			text: [
				make_noise_lines(80, 'before'),
				'TARGET_VALUE appears on line 855 with surrounding diagnostic text',
				make_noise_lines(80, 'after'),
			].join('\n'),
		},
		'staging-help': {
			tool_name: 'bash',
			text: [
				'Interactive git UI help',
				'Press space to stage this hunk.',
				'Press enter to open the selected file.',
				'Use a to amend after review.',
				make_noise_lines(40, 'staging'),
			].join('\n'),
		},
		'skill-script': {
			tool_name: 'read',
			text: [
				'case "$command" in',
				'  update) run_gh_skill_update "$repo" ;;',
				'  install) run_gh_skill_install "$repo" ;;',
				'esac',
				make_noise_lines(40, 'script'),
			].join('\n'),
		},
		'code-symbols': {
			tool_name: 'read',
			text: [
				"pi.registerCommand('context-stats', {",
				"  description: 'Show context sidecar byte accounting',",
				'});',
				make_noise_lines(40, 'code'),
			].join('\n'),
		},
		'chunk-boundary': {
			tool_name: 'mcp__mcp-omnisearch__web_extract',
			text: [
				`alpha-token ${'a'.repeat(5000)}`,
				'',
				`omega-token ${'b'.repeat(5000)}`,
			].join('\n'),
		},
	};
}

function seed(store: ContextStore): Map<string, SeededSource> {
	const seeded = new Map<string, SeededSource>();
	for (const [name, source] of Object.entries(source_texts())) {
		const stored = store.store({
			text: source.text,
			tool_name: source.tool_name,
			input_summary: name,
			project_path: PROJECT,
			session_id: SESSION,
			force: true,
		});
		if (!stored) throw new Error(`Failed to seed ${name}`);
		seeded.set(name, {
			name,
			source_id: stored.source_id,
			first_chunk_id: stored.first_chunk_id,
		});
	}
	return seeded;
}

function result_bytes(values: Array<{ content: string }>): number {
	return values.reduce(
		(total, value) =>
			total + Buffer.byteLength(value.content, 'utf8'),
		0,
	);
}

export function run_context_eval(): EvalReport {
	const dir = mkdtempSync(join(tmpdir(), 'pi-context-eval-'));
	const db_path = join(dir, 'context.db');
	const store = new ContextStore({
		db_path,
		project_path: PROJECT,
		session_id: SESSION,
	});

	try {
		const seeded = seed(store);
		const results: EvalCaseResult[] = [];

		for (const scenario of search_scenarios) {
			const source = seeded.get(scenario.source);
			if (!source)
				throw new Error(`Missing source ${scenario.source}`);
			const search = store.search(scenario.query, {
				source_id: source.source_id,
				limit: scenario.limit,
			});
			const passed = search.some((result) =>
				result.content.includes(scenario.expect),
			);
			results.push({
				name: scenario.name,
				type: 'search',
				passed,
				description: scenario.description,
				detail: passed
					? `matched ${search[0]?.chunk_id ?? 'unknown chunk'}`
					: `no expected match for query ${JSON.stringify(scenario.query)} (${search.length} result(s))`,
				returned_bytes: result_bytes(search),
				result_count: search.length,
			});
		}

		for (const scenario of get_scenarios) {
			const source = seeded.get(scenario.source);
			if (!source)
				throw new Error(`Missing source ${scenario.source}`);
			const chunks = store.get(source.source_id, scenario.chunk_id);
			const passed = chunks.some((chunk) =>
				chunk.content.includes(scenario.expect),
			);
			results.push({
				name: scenario.name,
				type: 'get',
				passed,
				description: scenario.description,
				detail: passed
					? `retrieved ${chunks[0]?.id ?? scenario.chunk_id}`
					: `missing expected content via chunk_id ${scenario.chunk_id}`,
				returned_bytes: result_bytes(chunks),
				result_count: chunks.length,
			});
		}

		const passed = results.filter((result) => result.passed).length;
		const total = results.length;
		const returned_bytes = results.reduce(
			(sum, result) => sum + result.returned_bytes,
			0,
		);
		return {
			version: 1,
			summary: {
				passed,
				failed: total - passed,
				total,
				score_pct: Math.round((passed / total) * 1000) / 10,
				returned_bytes,
			},
			results,
		};
	} finally {
		store.close();
		rmSync(dir, { recursive: true, force: true });
	}
}

function format_report(report: EvalReport): string {
	return [
		'# pi-context eval',
		'',
		`Score: ${report.summary.passed}/${report.summary.total} (${report.summary.score_pct}%)`,
		`Returned bytes: ${report.summary.returned_bytes}`,
		'',
		...report.results.map((result) =>
			[
				`${result.passed ? '✅' : '❌'} ${result.name} (${result.type})`,
				`   ${result.description}`,
				`   ${result.detail}; results=${result.result_count}; bytes=${result.returned_bytes}`,
			].join('\n'),
		),
	].join('\n');
}

export async function run_context_eval_cli(
	args = process.argv.slice(2),
): Promise<void> {
	const json = args.includes('--json');
	const report = run_context_eval();
	process.stdout.write(
		json
			? `${JSON.stringify(report, null, 2)}\n`
			: `${format_report(report)}\n`,
	);
	if (report.summary.failed > 0) process.exitCode = 1;
}
