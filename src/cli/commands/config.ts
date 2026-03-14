import { Command } from 'commander';
import fs from 'fs';
import path from 'path';
import yaml from 'js-yaml';

interface ValidationResult {
    valid: boolean;
    file: string;
    errors: string[];
    info?: string;
}

const VALID_PRESETS = ['strict', 'standard', 'relaxed'];
const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low'];

function validateConfigFile(filePath: string): ValidationResult {
    const result: ValidationResult = {
        valid: true,
        file: path.basename(filePath),
        errors: [],
    };

    if (!fs.existsSync(filePath)) {
        return result;
    }

    try {
        const content = fs.readFileSync(filePath, 'utf-8');
        const config = yaml.load(content) as Record<string, unknown>;

        if (path.basename(filePath) === '.g0.yaml') {
            const preset = (config.preset as string)?.toLowerCase();
            if (preset && !VALID_PRESETS.includes(preset)) {
                result.errors.push(
                    `unknown preset "${preset}" (did you mean "${findClosestMatch(preset, VALID_PRESETS)}"?)`
                );
            }
        }

        if (path.basename(filePath) === '.g0-policy.yaml') {
            const policies = (config.policies as unknown[]) || [];
            policies.forEach((policy: unknown, idx: number) => {
                const p = policy as Record<string, unknown>;
                if (p.severity && !VALID_SEVERITIES.includes(p.severity as string)) {
                    result.errors.push(
                        `severity must be one of: ${VALID_SEVERITIES.join(', ')}`
                    );
                }
            });
        }

        if (path.basename(filePath) === '.g0-risk-acceptance.yaml') {
            const accepted = (config.accepted as unknown[]) || [];
            result.info = `(${accepted.length} accepted risks)`;
        }

        result.valid = result.errors.length === 0;
    } catch (error) {
        result.errors.push(
            `failed to parse: ${error instanceof Error ? error.message : 'unknown error'}`
        );
        result.valid = false;
    }

    return result;
}

function findClosestMatch(input: string, options: string[]): string {
    return options.reduce((closest, option) => {
        const distance = Math.abs(input.length - option.length);
        return distance < Math.abs(input.length - closest.length) ? option : closest;
    });
}

export const configValidateCommand = new Command('validate')
    .description('Validate g0 configuration files')
    .action(() => {
        const cwd = process.cwd();
        const files = ['.g0.yaml', '.g0-policy.yaml', '.g0-risk-acceptance.yaml'];
        const results = files.map((file) =>
            validateConfigFile(path.join(cwd, file))
        );

        const hasErrors = results.some((r) => !r.valid && r.errors.length > 0);

        results.forEach((result) => {
            if (result.errors.length === 0 && fs.existsSync(path.join(cwd, result.file))) {
                console.log(`✓ ${result.file} is valid ${result.info || ''}`);
            } else if (result.errors.length > 0) {
                result.errors.forEach((error) => {
                    console.log(`✗ ${result.file}:0 — ${error}`);
                });
            }
        });

        process.exit(hasErrors ? 1 : 0);
    });