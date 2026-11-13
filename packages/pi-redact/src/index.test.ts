import { performance } from 'node:perf_hooks';
import { describe, expect, it } from 'vitest';
import {
	initialize_pattern_registry,
	MAX_REDACTION_CHUNK_CHARS,
	REDACTION_OVERLAP_CHARS,
	replace_owned_matches,
} from './windowed-replace.js';
import * as built_dist from '../dist/index.js';
import filter_output, {
	looks_like_ssh_config,
	redact_ssh_config_metadata,
	redact_text,
} from './index.js';

describe('redact_text', () => {
	it('built distribution redacts a candidate beyond the old regex ceiling', () => {
		const candidate = `Bearer ${'z'.repeat(50_000)}`;
		const result = built_dist.redact_text(candidate);
		expect(result.count).toBe(1);
		expect(result.redacted).not.toContain(candidate);
	});
	it('redacts AWS access keys', () => {
		const input = 'key: AKIA1234567890ABCDEF';
		const { redacted, count } = redact_text(input);
		expect(count).toBe(1);
		expect(redacted).toContain('[REDACTED:AWS Access Key]');
		expect(redacted).not.toContain('AKIA1234567890ABCDEF');
	});

	it('handles multi-megabyte single-line output under two seconds', () => {
		const input = `prefix Bearer ${'a'.repeat(32)} ${'x'.repeat(10 * 1024 * 1024)}`;
		const started = performance.now();
		const { redacted, count } = redact_text(input);
		const duration_ms = performance.now() - started;
		expect(count).toBe(1);
		expect(redacted).toContain('[REDACTED:Bearer Token]');
		expect(redacted).not.toBe(input);
		expect(duration_ms).toBeLessThan(2_000);
		if (process.env.PI_REDACT_PERF_REPORT === '1') {
			console.info(`pi-redact 10 MiB duration: ${duration_ms.toFixed(1)} ms`);
		}
	});

	it('redacts a Kagi credential straddling the 256 KiB seam', () => {
		const chunk = 256 * 1024;
		const credential = `${'A'.repeat(40)}.${'B'.repeat(40)}`;
		const input = `${'.'.repeat(chunk - 40)}${credential}`;
		const { redacted, count } = redact_text(input);
		expect(count).toBeGreaterThanOrEqual(1);
		expect(redacted).toContain('[REDACTED:Kagi API Key]');
		expect(redacted).not.toContain(credential);
	});

	it('redacts credentials at every start offset around the core seam', () => {
		const chunk = MAX_REDACTION_CHUNK_CHARS;
		const credential = `${'A'.repeat(40)}.${'B'.repeat(40)}`;
		const pieces: string[] = [];
		let cursor = 0;
		let expected_count = 0;
		for (let delta = -120; delta <= 120; delta++) {
			const seam = (expected_count + 1) * chunk;
			const start = seam + delta;
			pieces.push('.'.repeat(start - cursor), credential);
			cursor = start + credential.length;
			expected_count++;
		}
		const input = pieces.join('');
		const kagi_pattern =
			/(?<![a-zA-Z0-9_-])[a-zA-Z0-9_-]{40,200}\.[a-zA-Z0-9_-]{40,200}(?![a-zA-Z0-9_-])/g;
		const { redacted, count } = replace_owned_matches(
			input,
			kagi_pattern,
			() => '[REDACTED:Kagi API Key]',
			chunk,
			REDACTION_OVERLAP_CHARS,
		);
		expect(count).toBe(expected_count);
		expect(redacted).not.toContain(credential);
	});

	it('contains a maximum-length JWT match in the seam overlap', () => {
		const chunk = 256 * 1024;
		const jwt = `eyJ${'A'.repeat(8192)}.${'B'.repeat(8192)}.${'C'.repeat(8192)}`;
		const input = `${'.'.repeat(chunk - 1)}${jwt}`;
		const { redacted, count } = redact_text(input);
		expect(jwt.length).toBe(24_581);
		expect(count).toBe(1);
		expect(redacted).toContain('[REDACTED:JWT]');
		expect(redacted).not.toContain(jwt);
	});

	it('does not treat descriptive match length metadata as a regex safety proof', () => {
		const test_only_pattern = {
			name: 'unbounded test pattern',
			pattern: /A+/g,
			max_match_chars: REDACTION_OVERLAP_CHARS + 1,
		};
		expect(initialize_pattern_registry([test_only_pattern], REDACTION_OVERLAP_CHARS)).toEqual(
			[test_only_pattern],
		);
	});

	it('counts a seam-spanning credential once and a window-2 credential once', () => {
		const chunk = 256 * 1024;
		const first = `${'A'.repeat(40)}.${'B'.repeat(40)}`;
		const second = `${'C'.repeat(40)}.${'D'.repeat(40)}`;
		const input =
			'.'.repeat(chunk - 20) +
			first +
			'.'.repeat(2 * chunk + 200 - (chunk - 20 + first.length)) +
			second;
		const { redacted, count } = redact_text(input);
		expect(count).toBe(2);
		expect(redacted).not.toContain(first);
		expect(redacted).not.toContain(second);
	});

	it('applies absolute-offset edits safely across three windows', () => {
		const chunk = 256 * 1024;
		const credentials = [
			`${'A'.repeat(40)}.${'B'.repeat(40)}`,
			`${'C'.repeat(40)}.${'D'.repeat(40)}`,
			`${'E'.repeat(40)}.${'F'.repeat(40)}`,
		];
		const input =
			credentials[0] +
			'.'.repeat(chunk + 100 - credentials[0].length) +
			credentials[1] +
			'.'.repeat(chunk + 100 - credentials[1].length) +
			credentials[2];
		const { redacted, count } = redact_text(input);
		expect(count).toBe(3);
		for (const credential of credentials) {
			expect(redacted).not.toContain(credential);
		}
		expect(redacted).not.toContain('A'.repeat(40));
		expect(redacted).not.toContain('C'.repeat(40));
		expect(redacted).not.toContain('E'.repeat(40));
	});

	it('keeps single-window output byte-identical to direct pattern replacement', () => {
		const input = 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456';
		const expected = input.replace(
			/Bearer[ \t]{1,64}[a-zA-Z0-9._-]{20,256}(?![a-zA-Z0-9._-])/g,
			(match) =>
				`${match.slice(0, 4)}${'*'.repeat(Math.min(match.length - 4, 20))}[REDACTED:Bearer Token]`,
		);
		expect(redact_text(input)).toEqual({ redacted: expected, count: 1 });
	});

	it('fully redacts provider and Kagi candidates beyond former ceilings', () => {
		const provider_token = `sk-${'a'.repeat(20_000)}`;
		const kagi_token = `${'A'.repeat(2_000)}.${'B'.repeat(2_000)}`;
		for (const candidate of [provider_token, kagi_token]) {
			const { redacted, count } = redact_text(candidate);
			expect(count).toBe(1);
			expect(redacted).not.toContain(candidate);
		}
	});

	it('redacts oversized quoted fields, long PEMs, and credentials across old chunk seams', () => {
		const password = 'P'.repeat(20_000);
		const pem_body = 'X'.repeat(300_000);
		const kagi = `${'K'.repeat(800)}.${'g'.repeat(900)}`;
		const input = `password="${password}"\\n${kagi}\\n-----BEGIN PRIVATE KEY-----${pem_body}-----END PRIVATE KEY-----`;
		const { redacted, count } = redact_text(input);
		expect(count).toBeGreaterThanOrEqual(3);
		for (const candidate of [password, kagi, pem_body]) {
			expect(redacted).not.toContain(candidate);
		}
	});

	it('redacts escaped-quote fields and long connection-string passwords', () => {
		const field_value = `${'a'.repeat(9_000)}\\"${'b'.repeat(9_000)}`;
		const connection_password = 'p'.repeat(20_000);
		const input = `password="${field_value}" postgres://user:${connection_password}@localhost/db`;
		const { redacted } = redact_text(input);
		for (const candidate of [field_value, connection_password]) {
			expect(redacted).not.toContain(candidate);
		}
	});

	it('fully redacts JWT components beyond the former 8 KiB cap', () => {
		const jwt = `eyJ${'A'.repeat(12_000)}.${'B'.repeat(12_000)}.${'C'.repeat(12_000)}`;
		const { redacted, count } = redact_text(jwt);
		expect(count).toBe(1);
		expect(redacted).not.toContain(jwt);
	});

	it('consumes an unterminated quoted secret field through end of input', () => {
		const tail = 'secret-' + 's'.repeat(20_000);
		const { redacted } = redact_text(`password="${tail}`);
		expect(redacted).not.toContain(tail);
	});

	it('redacts AWS temp access keys', () => {
		const input = 'key: ASIA1234567890ABCDEF';
		const { redacted, count } = redact_text(input);
		expect(count).toBe(1);
		expect(redacted).toContain('[REDACTED:AWS Temp Access Key]');
		expect(redacted).not.toContain('ASIA1234567890ABCDEF');
	});

	it('redacts uppercase AWS secret env vars', () => {
		const input =
			'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY01';
		const { redacted, count } = redact_text(input);
		expect(count).toBe(1);
		expect(redacted).toContain('[REDACTED:AWS Secret Key]');
		expect(redacted).not.toContain(
			'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY01',
		);
	});

	it('redacts bearer tokens', () => {
		const input =
			'Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456';
		const { redacted, count } = redact_text(input);
		expect(count).toBe(1);
		expect(redacted).toContain('[REDACTED:Bearer Token]');
		expect(redacted).not.toContain(
			'Bearer abcdefghijklmnopqrstuvwxyz123456',
		);
	});

	it('redacts full private key blocks', () => {
		const input = `-----BEGIN PRIVATE KEY-----\nQ0FOQVJZX1BSSVZBVEVfS0VZX0JMT0NLX0xJTkVfMDAx\nQ0FOQVJZX1BSSVZBVEVfS0VZX0JMT0NLX0xJTkVfMDAy\n-----END PRIVATE KEY-----`;
		const { redacted, count } = redact_text(input);
		expect(count).toBe(1);
		expect(redacted).toContain('[REDACTED:Private Key]');
		expect(redacted).not.toContain(
			'Q0FOQVJZX1BSSVZBVEVfS0VZX0JMT0NLX0xJTkVfMDAx',
		);
	});

	it('redacts connection strings with passwords', () => {
		const input =
			'postgres://user:super-secret-password@localhost:5432/app';
		const { redacted, count } = redact_text(input);
		expect(count).toBe(1);
		expect(redacted).toContain(
			'[REDACTED:Connection String with Password]',
		);
		expect(redacted).not.toContain(':super-secret-password@');
	});

	it('redacts generic secret fields', () => {
		const input = 'SERVICE_PASSWORD=CanaryPassword-Redaction-001!';
		const { redacted, count } = redact_text(input);
		expect(count).toBe(1);
		expect(redacted).toContain('[REDACTED:Generic Password Field]');
		expect(redacted).not.toContain('CanaryPassword-Redaction-001!');
	});

	it('redacts quoted JSON secret fields without leaking their values', () => {
		const values = {
			password: ['super', 'secret', '12345'].join(''),
			access_token: ['opaque', '-token-', 'value!'].join(''),
			client_secret: ['client', '$#%&*?', 'secret'].join(''),
			refresh_token: ['refresh', '-opaque-', 'credential'].join(''),
			aws_secret_access_key: ['A1b2', '/+=', 'C3d4']
				.join('')
				.repeat(5),
		};
		const input = JSON.stringify(values);
		const { redacted, count } = redact_text(input);

		expect(count).toBe(5);
		for (const value of Object.values(values)) {
			expect(redacted).not.toContain(value);
		}
		expect(redacted).toContain('[REDACTED:Generic Password Field]');
	});

	it('redacts the complete value when an env secret contains shell punctuation', () => {
		const value = ['p@', '$$', 'w0rd!', 'xyz#%&*?~^'].join('');
		const input = `PASSWORD=${value}`;
		const { redacted, count } = redact_text(input);

		expect(count).toBe(1);
		expect(redacted).not.toContain(value);
		expect(redacted).not.toContain('xyz#%&*?~^');
	});

	it.each([
		[
			'JWT',
			[
				'eyJ',
				'hbGciOiJIUzI1NiJ9',
				'.',
				'eyJzdWIiOiIxMjM0NTY3ODkwIn0',
				'.',
				'signaturevalue123456',
			].join(''),
		],
		['Slack Token', `xoxb-${'A'.repeat(32)}`],
		['GitLab Token', `glpat-${'B'.repeat(24)}`],
		['Google API Key', `AIza${'C'.repeat(35)}`],
		['npm Token', `npm_${'D'.repeat(36)}`],
		['SendGrid API Key', `SG.${'E'.repeat(24)}.${'F'.repeat(43)}`],
	])('redacts %s credentials', (_name, credential) => {
		const { redacted, count } = redact_text(credential);
		expect(count).toBe(1);
		expect(redacted).not.toContain(credential);
	});

	it('redacts a private-key chunk even when its END marker is absent', () => {
		const private_key_chunk = [
			'-----BEGIN PRIVATE KEY-----',
			'Q0FOQVJZX1BSSVZBVEVfS0VZX0ZJUlNUX0NIVU5L',
		].join('\n');
		const { redacted, count } = redact_text(private_key_chunk);

		expect(count).toBe(1);
		expect(redacted).not.toContain(
			'Q0FOQVJZX1BSSVZBVEVfS0VZX0ZJUlNUX0NIVU5L',
		);
		expect(redacted).toContain('[REDACTED:Private Key]');
	});

	it('does not blanket-redact unlabelled encoded output', () => {
		const input = Buffer.from(
			'ordinary build artifact content without credentials',
		).toString('base64');
		const { redacted, count } = redact_text(input);
		expect(count).toBe(0);
		expect(redacted).toBe(input);
	});

	it('tracks and redacts private-key continuations across read chunks', async () => {
		let tool_result_handler:
			| ((event: Record<string, unknown>) => unknown)
			| undefined;
		const pi = {
			on(
				name: string,
				handler: (event: Record<string, unknown>) => unknown,
			) {
				if (name === 'tool_result') tool_result_handler = handler;
			},
			registerCommand() {},
		};
		await filter_output(pi as never);
		const path = '/tmp/chunked-private-key.pem';
		const first_chunk = [
			'-----BEGIN PRIVATE KEY-----',
			'Q0FOQVJZX0ZJUlNUX0NIVU5LX1BSSVZBVEVfS0VZ',
		].join('\n');
		const second_chunk = [
			'Q0FOQVJZX1NFQ09ORF9DSFVOS19QUklWQVRFX0tFWQ==',
			'-----END PRIVATE KEY-----',
		].join('\n');

		await tool_result_handler?.({
			toolName: 'read',
			input: { path },
			content: [{ type: 'text', text: first_chunk }],
		});
		const result = (await tool_result_handler?.({
			toolName: 'read',
			input: { path, offset: 2 },
			content: [{ type: 'text', text: second_chunk }],
		})) as { content?: Array<{ text?: string }> };

		expect(result.content?.[0]?.text).toContain(
			'[REDACTED:Private Key continuation]',
		);
		expect(result.content?.[0]?.text).not.toContain(
			'Q0FOQVJZX1NFQ09ORF9DSFVOS19QUklWQVRFX0tFWQ==',
		);
	});

	it('tracks ordered and split private-key markers across sequential reads in source and built output', async () => {
		for (const extension of [filter_output, built_dist.default]) {
			let handler:
				| ((event: Record<string, unknown>) => unknown)
				| undefined;
			const pi = {
				on(name: string, callback: (event: Record<string, unknown>) => unknown) {
					if (name === 'tool_result') handler = callback;
				},
				registerCommand() {},
			};
			await extension(pi as never);

			const ordered_path = `/tmp/ordered-private-key-${Math.random()}.pem`;
			await handler?.({
				toolName: 'read',
				input: { path: ordered_path },
				content: [{
					type: 'text',
					text: `-----END PRIVATE KEY-----\nclosed block\n-----BEGIN PRIVATE KEY-----`,
				}],
			});
			const ordered_result = (await handler?.({
				toolName: 'read',
				input: { path: ordered_path, offset: 2 },
				content: [{ type: 'text', text: 'ORDERED_KEY_MATERIAL_MUST_NOT_LEAK' }],
			})) as { content?: Array<{ text?: string }> };
			expect(ordered_result.content?.[0]?.text).not.toContain(
				'ORDERED_KEY_MATERIAL_MUST_NOT_LEAK',
			);

			const split_path = `/tmp/split-marker-private-key-${Math.random()}.pem`;
			await handler?.({
				toolName: 'read',
				input: { path: split_path },
				content: [{ type: 'text', text: '-----BEG' }],
			});
			const split_begin = (await handler?.({
				toolName: 'read',
				input: { path: split_path, offset: 1 },
				content: [{ type: 'text', text: `IN PRIVATE KEY-----\nSPLIT_BEGIN_KEY_MATERIAL` }],
			})) as { content?: Array<{ text?: string }> };
			expect(split_begin.content?.[0]?.text).not.toContain(
				'SPLIT_BEGIN_KEY_MATERIAL',
			);

			await handler?.({
				toolName: 'read',
				input: { path: split_path, offset: 2 },
				content: [{ type: 'text', text: 'SPLIT_END_KEY_MATERIAL-----END PRI' }],
			});
			await handler?.({
				toolName: 'read',
				input: { path: split_path, offset: 3 },
				content: [{ type: 'text', text: 'VATE KEY-----' }],
			});
			const after_end = await handler?.({
				toolName: 'read',
				input: { path: split_path, offset: 4 },
				content: [{ type: 'text', text: 'ordinary public text' }],
			});
			expect(after_end).toBeUndefined();
		}
	});

	it('redacts private-key continuations split across text content blocks', async () => {
		let tool_result_handler:
			| ((event: Record<string, unknown>) => unknown)
			| undefined;
		const pi = {
			on(
				name: string,
				handler: (event: Record<string, unknown>) => unknown,
			) {
				if (name === 'tool_result') tool_result_handler = handler;
			},
			registerCommand() {},
		};
		await filter_output(pi as never);
		const continuation = 'Q0FOQVJZX1BSSVZBVEVfQk9EWV9DT05URU5U';
		const result = (await tool_result_handler?.({
			toolName: 'read',
			input: { path: '/tmp/split-content-key.pem' },
			content: [
				{ type: 'text', text: `-----${'BEGIN PRIVATE KEY-----'}\n` },
				{ type: 'text', text: continuation },
			],
		})) as { content?: Array<{ text?: string }> };

		expect(result.content?.[1]?.text).toContain(
			'[REDACTED:Private Key continuation]',
		);
		expect(result.content?.[1]?.text).not.toContain(continuation);
	});

	it('normalizes read paths before tracking private-key continuations', async () => {
		let tool_result_handler:
			| ((event: Record<string, unknown>) => unknown)
			| undefined;
		const pi = {
			on(
				name: string,
				handler: (event: Record<string, unknown>) => unknown,
			) {
				if (name === 'tool_result') tool_result_handler = handler;
			},
			registerCommand() {},
		};
		await filter_output(pi as never);
		const continuation =
			'Q0FOQVJZX1NFQ09ORF9DSFVOS19QUklWQVRFX0tFWQ==';
		await tool_result_handler?.({
			toolName: 'read',
			input: { path: '/tmp/equivalent-key.pem' },
			content: [
				{ type: 'text', text: `-----${'BEGIN PRIVATE KEY-----'}\n` },
			],
		});
		const result = (await tool_result_handler?.({
			toolName: 'read',
			input: { path: '/tmp/./equivalent-key.pem', offset: 2 },
			content: [{ type: 'text', text: continuation }],
		})) as { content?: Array<{ text?: string }> };

		expect(result.content?.[0]?.text).toContain(
			'[REDACTED:Private Key continuation]',
		);
		expect(result.content?.[0]?.text).not.toContain(continuation);
	});

	it('redacts GitHub fine-grained PATs', () => {
		const input = 'github_pat_' + 'A'.repeat(30);
		const { redacted, count } = redact_text(input);
		expect(count).toBe(1);
		expect(redacted).toContain('[REDACTED:GitHub Fine-grained PAT]');
		expect(redacted).not.toContain('github_pat_' + 'A'.repeat(30));
	});

	it('redacts SSH config metadata from a config block', () => {
		const input = `Host prod-app\n  HostName 10.0.0.12\n  User deploy\n  IdentityFile ~/.ssh/work-prod\n  ProxyJump bastion.internal\n  LocalForward 5432 db.internal:5432\n  RemoteForward 8443 localhost:443\n  DynamicForward 1080\n  ProxyCommand ssh -W %h:%p bastion.internal\n  CertificateFile ~/.ssh/work-prod-cert.pub\n  HostKeyAlias prod-app.internal\n  Match host *.internal user deploy\n`;
		const { redacted, count } = redact_text(input);
		expect(count).toBe(12);
		expect(redacted).toContain('Host [REDACTED:SSH Host]');
		expect(redacted).toContain('HostName [REDACTED:SSH HostName]');
		expect(redacted).toContain('User [REDACTED:SSH User]');
		expect(redacted).toContain(
			'IdentityFile [REDACTED:SSH IdentityFile]',
		);
		expect(redacted).toContain('ProxyJump [REDACTED:SSH ProxyJump]');
		expect(redacted).toContain(
			'LocalForward [REDACTED:SSH LocalForward]',
		);
		expect(redacted).toContain(
			'RemoteForward [REDACTED:SSH RemoteForward]',
		);
		expect(redacted).toContain(
			'DynamicForward [REDACTED:SSH DynamicForward]',
		);
		expect(redacted).toContain(
			'ProxyCommand [REDACTED:SSH ProxyCommand]',
		);
		expect(redacted).toContain(
			'CertificateFile [REDACTED:SSH CertificateFile]',
		);
		expect(redacted).toContain(
			'HostKeyAlias [REDACTED:SSH HostKeyAlias]',
		);
		expect(redacted).toContain('Match [REDACTED:SSH Match]');
		expect(redacted).not.toContain('10.0.0.12');
		expect(redacted).not.toContain('deploy');
		expect(redacted).not.toContain('~/.ssh/work-prod');
		expect(redacted).not.toContain('bastion.internal');
	});

	it('keeps Host * and Match all unchanged', () => {
		const input = `Host *\n  ServerAliveInterval 30\nMatch all\n  ForwardAgent no\n`;
		const { redacted, count } = redact_text(input, {
			force_ssh_config: true,
		});
		expect(count).toBe(0);
		expect(redacted).toBe(input);
	});

	it('does not treat ordinary prose as SSH config', () => {
		const input =
			'User deploy should run HostName setup in docs first.';
		const { redacted, count } = redact_text(input);
		expect(count).toBe(0);
		expect(redacted).toBe(input);
	});

	it('can force SSH redaction for config fragments', () => {
		const input = 'HostName 10.42.0.7';
		const { redacted, count } = redact_text(input, {
			force_ssh_config: true,
		});
		expect(count).toBe(1);
		expect(redacted).toBe('HostName [REDACTED:SSH HostName]');
	});

	it('leaves clean text unchanged', () => {
		const input = 'This is normal output with no secrets.';
		const { redacted, count } = redact_text(input);
		expect(count).toBe(0);
		expect(redacted).toBe(input);
	});

	it('does not redact ordinary package metadata and documentation links', () => {
		const input = JSON.stringify(
			{
				name: 'my-pi',
				homepage: 'https://github.com/spences10/my-pi',
				repository: {
					type: 'git',
					url: 'git+https://github.com/spences10/my-pi.git',
				},
				author: 'Scott Spence <scott@example.com>',
				keywords: ['cli', 'sqlite', 'telemetry'],
				badge: 'https://img.shields.io/npm/v/@spences10/pi-redact',
			},
			null,
			2,
		);
		const markdown = `${input}\n[repo](https://github.com/spences10/my-pi)\n[npm](https://www.npmjs.com/package/@spences10/pi-redact)`;
		const { redacted, count } = redact_text(markdown);
		expect(count).toBe(0);
		expect(redacted).toBe(markdown);
	});

	it('does not redact ordinary source variables that contain token', () => {
		const input =
			"const first_token = command.trim().split(/\\s+/)[0] ?? 'hook';";
		const { redacted, count } = redact_text(input);
		expect(count).toBe(0);
		expect(redacted).toBe(input);
	});

	it('still redacts uppercase token-like env fields', () => {
		const input = 'SERVICE_TOKEN = "CanaryPassword-Redaction-001!"';
		const { redacted, count } = redact_text(input);
		expect(count).toBe(1);
		expect(redacted).toContain('[REDACTED:Generic Password Field]');
		expect(redacted).not.toContain('CanaryPassword-Redaction-001!');
	});

	it('does not let generic secret phrases span prose or markdown boundaries', () => {
		const input = `The redactor detects secrets defensively.

- tokens, passwords, and API keys are examples.
- Prefer nopeek for secret-safe loading.

See https://github.com/spences10/nopeek for details.`;
		const { redacted, count } = redact_text(input);
		expect(count).toBe(0);
		expect(redacted).toBe(input);
	});

	it('still redacts generic secret phrases with explicit values', () => {
		const input = 'password is CanaryPassword-Redaction-001!';
		const { redacted, count } = redact_text(input);
		expect(count).toBe(1);
		expect(redacted).toContain('[REDACTED:Generic Secret Phrase]');
		expect(redacted).not.toContain('CanaryPassword-Redaction-001!');
	});
});

describe('SSH helpers', () => {
	it('detects SSH config content', () => {
		const input = `Host prod\n  HostName 10.0.0.12\n  User deploy\n`;
		expect(looks_like_ssh_config(input)).toBe(true);
	});

	it('does not detect unrelated content as SSH config', () => {
		expect(
			looks_like_ssh_config('HostName examples are documented here.'),
		).toBe(false);
	});

	it('redacts SSH config metadata directly', () => {
		const input = `Host prod\n  HostName 192.168.1.20\n  User ubuntu\n`;
		const { redacted, count } = redact_ssh_config_metadata(input);
		expect(count).toBe(3);
		expect(redacted).toContain('Host [REDACTED:SSH Host]');
		expect(redacted).toContain('HostName [REDACTED:SSH HostName]');
		expect(redacted).toContain('User [REDACTED:SSH User]');
	});
});
