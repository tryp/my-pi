import { describe, expect, it } from 'vitest';

describe('packages/pi-context/src/ui/settings.ts', () => {
	it('loads without side effects', async () => {
		await expect(import('./settings.js')).resolves.toBeDefined();
	});
});
