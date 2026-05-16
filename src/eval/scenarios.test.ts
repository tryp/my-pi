import { describe, expect, it } from 'vitest';

describe('packages/pi-context/src/eval/scenarios.ts', () => {
	it('loads without side effects', async () => {
		await expect(import('./scenarios.js')).resolves.toBeDefined();
	});
});
