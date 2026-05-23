import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { ContextStore } from '../store.js';
import {
	context_store_purge_with_details,
	context_store_stats,
} from './maintenance.js';

const stores: ContextStore[] = [];
const dirs: string[] = [];

function create_store(): ContextStore {
	const dir = mkdtempSync(join(tmpdir(), 'pi-context-maintenance-'));
	dirs.push(dir);
	const store = new ContextStore({
		db_path: join(dir, 'context.db'),
		max_bytes: 10,
		project_path: '/project-a',
	});
	stores.push(store);
	return store;
}

afterEach(() => {
	for (const store of stores.splice(0)) {
		try {
			store.close();
		} catch {
			// already closed
		}
	}
	for (const dir of dirs.splice(0)) {
		rmSync(dir, { recursive: true, force: true });
	}
});

describe('context store maintenance helpers', () => {
	it('reports scoped stats and purges matching sources with details', () => {
		const store = create_store();
		const stored = store.store({
			text: `maintenance-token\n${'x '.repeat(100)}`,
			tool_name: 'bash',
		});

		expect(
			context_store_stats(store, { project_path: '/project-a' })
				.sources,
		).toBe(1);
		expect(
			context_store_stats(store, { project_path: '/project-b' })
				.sources,
		).toBe(0);

		const details = context_store_purge_with_details(store, {
			source_id: stored!.source_id,
		});
		expect(details).toMatchObject({
			deleted: 1,
			source_id: stored!.source_id,
		});
		expect(context_store_stats(store).sources).toBe(0);
	});
});
