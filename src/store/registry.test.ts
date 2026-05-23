import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { ContextStore } from '../store.js';
import {
	get_context_store,
	maybe_store_context_output,
	set_context_sidecar_enabled,
} from './registry.js';

const dirs: string[] = [];

function temp_db(): string {
	const dir = mkdtempSync(join(tmpdir(), 'pi-context-registry-'));
	dirs.push(dir);
	return join(dir, 'context.db');
}

afterEach(() => {
	set_context_sidecar_enabled(false);
	for (const dir of dirs.splice(0)) {
		rmSync(dir, { recursive: true, force: true });
	}
});

describe('context store registry', () => {
	it('gates writes on enablement and reconfigures a reused store', () => {
		const db_path = temp_db();
		expect(
			maybe_store_context_output(ContextStore, {
				text: 'disabled '.repeat(20),
				tool_name: 'bash',
			}),
		).toBeNull();

		set_context_sidecar_enabled(true, {
			db_path,
			max_bytes: 10,
			project_path: '/project-a',
		});
		maybe_store_context_output(ContextStore, {
			text: `alpha-registry\n${'x '.repeat(100)}`,
			tool_name: 'bash',
		});
		const first = get_context_store(ContextStore);

		set_context_sidecar_enabled(true, {
			db_path,
			max_bytes: 10,
			project_path: '/project-b',
		});
		maybe_store_context_output(ContextStore, {
			text: `beta-registry\n${'x '.repeat(100)}`,
			tool_name: 'bash',
		});
		const second = get_context_store(ContextStore);

		expect(second).toBe(first);
		expect(second.search('alpha-registry')).toHaveLength(0);
		expect(second.search('beta-registry')).toHaveLength(1);
		expect(
			second.search('alpha-registry', { project_path: '/project-a' }),
		).toHaveLength(1);
		second.close();
	});
});
