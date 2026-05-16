import { describe, expect, it } from 'vitest';

describe('packages/pi-context/src/context-scope.ts', () => {
	it('loads without side effects', async () => {
		await expect(import('./context-scope.js')).resolves.toBeDefined();
	});
});
