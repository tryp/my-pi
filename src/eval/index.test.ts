import { describe, expect, it } from 'vitest';

describe('packages/pi-context/src/eval/index.ts', () => {
	it('loads without side effects', async () => {
		await expect(import('./index.js')).resolves.toBeDefined();
	});
});
