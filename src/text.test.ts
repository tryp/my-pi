import { describe, expect, it } from 'vitest';

describe('packages/pi-context/src/text.ts', () => {
	it('loads without side effects', async () => {
		await expect(import('./text.js')).resolves.toBeDefined();
	});
});
