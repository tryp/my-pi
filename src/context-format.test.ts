import { describe, expect, it } from 'vitest';

describe('packages/pi-context/src/context-format.ts', () => {
	it('loads without side effects', async () => {
		await expect(
			import('./context-format.js'),
		).resolves.toBeDefined();
	});
});
