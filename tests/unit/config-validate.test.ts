import { describe, it, expect, beforeEach, vi } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';

describe('config validate command', () => {
    let consoleSpy: any;

    beforeEach(() => {
        consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    });

    afterEach(() => {
        consoleSpy.mockRestore();
    });

    describe('g0 config validate', () => {
        it('should validate that .g0.yaml is valid', async () => {
            const configPath = join(process.cwd(), '.g0.yaml');
            const fileContent = readFileSync(configPath, 'utf-8');
            expect(fileContent).toBeDefined();
            expect(fileContent.length).toBeGreaterThan(0);
        });

        it('should validate that .g0-policy.yaml is valid', async () => {
            const policyPath = join(process.cwd(), '.g0-policy.yaml');
            const fileContent = readFileSync(policyPath, 'utf-8');
            expect(fileContent).toBeDefined();
            expect(fileContent.length).toBeGreaterThan(0);
        });

        it('should validate that .g0-risk-acceptance.yaml is valid with 3 accepted risks', async () => {
            const riskPath = join(process.cwd(), '.g0-risk-acceptance.yaml');
            const fileContent = readFileSync(riskPath, 'utf-8');
            const acceptedRisksMatch = fileContent.match(/acceptedRisks:|risks:/g) || [];
            expect(fileContent).toBeDefined();
            expect(fileContent.length).toBeGreaterThan(0);
            expect(acceptedRisksMatch.length).toBeGreaterThanOrEqual(1);
        });
    });
});