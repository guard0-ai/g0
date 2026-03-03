import * as fs from 'node:fs';
import * as path from 'node:path';
import _ignore from 'ignore';

// Handle ESM/CJS interop — the `ignore` package may export .default at runtime
const ignore = (_ignore as any).default || _ignore;
import type { FileInfo, FileInventory } from '../types/common.js';

const DEFAULT_IGNORE = [
  'node_modules', '.git', '__pycache__', '.venv', 'venv', 'env',
  '.tox', '.mypy_cache', '.pytest_cache', 'dist', 'build', '.next',
  '.nuxt', 'coverage', '.nyc_output', '.turbo', '.vercel',
  'target', 'vendor',
  '*.pyc', '*.pyo', '*.so', '*.dylib', '*.dll',
  '*.min.js', '*.bundle.js', '*.map',
  '*.jpg', '*.jpeg', '*.png', '*.gif', '*.ico', '*.svg',
  '*.woff', '*.woff2', '*.ttf', '*.eot',
  '*.zip', '*.tar.gz', '*.tgz',
];

const CODE_EXTENSIONS: Record<string, FileInfo['language']> = {
  '.py': 'python',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.js': 'javascript',
  '.jsx': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.java': 'java',
  '.go': 'go',
  '.yaml': 'yaml',
  '.yml': 'yaml',
  '.json': 'json',
  '.toml': 'toml',
};

const CONFIG_NAMES = new Set([
  'package.json', 'pyproject.toml', 'setup.py', 'setup.cfg',
  'requirements.txt', 'Pipfile', 'poetry.lock',
  '.env', '.env.local', '.env.example',
  'agents.yaml', 'tasks.yaml', 'crew.yaml',
  'mcp.json', 'claude_desktop_config.json',
  'SOUL.md', 'MEMORY.md', 'openclaw.json',
  'tsconfig.json', 'vite.config.ts',
  'pom.xml', 'build.gradle', 'build.gradle.kts',
  'go.mod', 'go.sum',
]);

export async function walkDirectory(rootPath: string, excludePaths?: string[]): Promise<FileInventory> {
  const ig = ignore();
  ig.add(DEFAULT_IGNORE);

  if (excludePaths && excludePaths.length > 0) {
    ig.add(excludePaths);
  }

  const gitignorePath = path.join(rootPath, '.gitignore');
  if (fs.existsSync(gitignorePath)) {
    const gitignoreContent = fs.readFileSync(gitignorePath, 'utf-8');
    ig.add(gitignoreContent);
  }

  const files: FileInfo[] = [];
  walkRecursive(rootPath, rootPath, ig, files);

  return categorizeFiles(files);
}

function walkRecursive(
  dir: string,
  rootPath: string,
  ig: ReturnType<typeof ignore>,
  files: FileInfo[],
): void {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    const relativePath = path.relative(rootPath, fullPath);

    if (ig.ignores(relativePath)) continue;

    if (entry.isDirectory()) {
      if (ig.ignores(relativePath + '/')) continue;
      walkRecursive(fullPath, rootPath, ig, files);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      const language = CODE_EXTENSIONS[ext] ?? 'other';
      const isConfig = CONFIG_NAMES.has(entry.name);
      if (language === 'other' && !isConfig) continue;

      let size: number;
      try {
        size = fs.statSync(fullPath).size;
      } catch {
        continue;
      }

      files.push({ path: fullPath, relativePath, language, size });
    }
  }
}

function categorizeFiles(files: FileInfo[]): FileInventory {
  return {
    all: files,
    python: files.filter(f => f.language === 'python'),
    typescript: files.filter(f => f.language === 'typescript'),
    javascript: files.filter(f => f.language === 'javascript'),
    java: files.filter(f => f.language === 'java'),
    go: files.filter(f => f.language === 'go'),
    yaml: files.filter(f => f.language === 'yaml'),
    json: files.filter(f => f.language === 'json'),
    configs: files.filter(f => CONFIG_NAMES.has(path.basename(f.path))),
  };
}
