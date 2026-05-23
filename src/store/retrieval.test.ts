import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { ContextStore } from '../store.js';
import {
	context_store_chunk_summary,
	context_store_get,
} from './retrieval.js';

const stores: ContextStore[] = [];
const dirs: string[] = [];

function create_store(): ContextStore {
	const dir = mkdtempSync(join(tmpdir(), 'pi-context-retrieval-'));
	dirs.push(dir);
	const store = new ContextStore({
		db_path: join(dir, 'context.db'),
		max_bytes: 10,
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

describe('context store retrieval helpers', () => {
	it('summarizes chunks and resolves numeric chunk references', () => {
		const store = create_store();
		const stored = store.store({
			text: `needle-retrieval\n${'x '.repeat(5000)}`,
			tool_name: 'bash',
		});

		const summary = context_store_chunk_summary(
			store,
			stored!.source_id,
		);
		expect(summary?.chunk_count).toBe(stored!.chunk_count);
		expect(summary?.first_chunk_id).toBe(stored!.first_chunk_id);

		const first = context_store_get(store, stored!.source_id, '1');
		expect(first).toHaveLength(1);
		expect(first[0]!.id).toBe(stored!.first_chunk_id);
	});
});
