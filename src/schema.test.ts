import { describe, expect, it } from 'vitest';

describe('packages/pi-context/src/schema.ts', () => {
	it('loads without side effects', async () => {
		await expect(import('./schema.js')).resolves.toBeDefined();
	});
});
