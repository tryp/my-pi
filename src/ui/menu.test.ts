import { describe, expect, it } from 'vitest';

describe('packages/pi-context/src/ui/menu.ts', () => {
	it('loads without side effects', async () => {
		await expect(import('./menu.js')).resolves.toBeDefined();
	});
});
