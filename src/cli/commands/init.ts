import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Command } from 'commander';
import chalk from 'chalk';

const DEFAULT_CONFIG = `# g0 Configuration
# See: https://github.com/guard0-ai/g0

# Minimum score to pass CI/CD gate (0-100)
min_score: 70

# Minimum grade to pass (A, B, C, D, F)
# min_grade: C

# Severity threshold - fail if any finding at or above this level
# fail_on: critical

# Exclude specific rules
# exclude_rules:
#   - AA-DL-001  # verbose=True (acceptable in dev)

# Exclude paths from scanning
# exclude_paths:
#   - tests/
#   - docs/
#   - examples/

# Custom rules directory
# rules_dir: ./rules
`;

export const initCommand = new Command('init')
  .description('Initialize g0 configuration file')
  .option('-f, --force', 'Overwrite existing config')
  .option('--hooks', 'Install git pre-commit hook')
  .action((options: { force?: boolean; hooks?: boolean }) => {
    if (options.hooks) {
      installPreCommitHook();
      return;
    }

    const configPath = path.join(process.cwd(), '.g0.yaml');

    if (fs.existsSync(configPath) && !options.force) {
      console.log(chalk.yellow('Config file already exists: .g0.yaml'));
      console.log(chalk.dim('Use --force to overwrite'));
      return;
    }

    fs.writeFileSync(configPath, DEFAULT_CONFIG, 'utf-8');
    console.log(chalk.green('Created .g0.yaml'));
    console.log(chalk.dim('Run `g0 scan` to scan your project'));
  });

function installPreCommitHook(): void {
  const gitDir = path.join(process.cwd(), '.git');
  if (!fs.existsSync(gitDir)) {
    console.error(chalk.red('Not a git repository. Run `git init` first.'));
    process.exit(1);
  }

  const hooksDir = path.join(gitDir, 'hooks');
  if (!fs.existsSync(hooksDir)) {
    fs.mkdirSync(hooksDir, { recursive: true });
  }

  const hookPath = path.join(hooksDir, 'pre-commit');
  if (fs.existsSync(hookPath)) {
    console.log(chalk.yellow('Pre-commit hook already exists.'));
    console.log(chalk.dim(`  ${hookPath}`));
    console.log(chalk.dim('Remove it manually and re-run to replace.'));
    return;
  }

  // Read the template from the package
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const templatePath = path.join(__dirname, '..', '..', 'templates', 'pre-commit-hook.sh');
  let hookContent: string;
  if (fs.existsSync(templatePath)) {
    hookContent = fs.readFileSync(templatePath, 'utf-8');
  } else {
    // Fallback inline template
    hookContent = `#!/bin/sh
set -e
echo "[g0] Running security scan..."
g0 gate . --min-score 70 --no-critical
echo "[g0] Security scan passed."
`;
  }

  fs.writeFileSync(hookPath, hookContent, { mode: 0o755 });
  console.log(chalk.green('Installed pre-commit hook'));
  console.log(chalk.dim(`  ${hookPath}`));
}
