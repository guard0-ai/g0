import * as path from 'node:path';
import type { FileInventory, FileInfo } from '../types/common.js';
import type { AnalyzabilityScore } from '../types/score.js';
import type { Finding } from '../types/finding.js';

const ANALYZABLE_EXTENSIONS = new Set([
  '.py', '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '.java', '.go', '.rs', '.rb', '.php', '.cs', '.swift', '.kt',
  '.yaml', '.yml', '.json', '.toml', '.ini', '.cfg', '.conf',
  '.xml', '.html', '.css', '.scss', '.less',
  '.md', '.txt', '.rst', '.env', '.sh', '.bash', '.zsh',
  '.sql', '.graphql', '.proto',
  '.dockerfile', '.tf', '.hcl',
]);

const INERT_EXTENSIONS = new Set([
  '.md', '.txt', '.rst', '.csv', '.tsv',
  '.license', '.gitignore', '.gitattributes', '.editorconfig',
]);

const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp', '.bmp', '.tiff', '.svg',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.mp3', '.mp4', '.wav', '.ogg', '.webm', '.avi',
  '.pdf', '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
  '.wasm', '.dylib', '.so', '.dll', '.exe', '.bin',
  '.pyc', '.pyo', '.class', '.o', '.a',
]);

const MINIFIED_PATTERNS = [
  /\.min\.(js|css)$/,
  /\.bundle\.(js|css)$/,
  /\.chunk\.js$/,
  /[\\/]dist[\\/]/,
  /[\\/]build[\\/]/,
  /[\\/]vendor[\\/]/,
  /[\\/]node_modules[\\/]/,
];

function classifyFile(file: FileInfo): 'analyzable' | 'inert' | 'opaque' {
  const ext = path.extname(file.path).toLowerCase();

  if (BINARY_EXTENSIONS.has(ext)) return 'opaque';
  if (MINIFIED_PATTERNS.some(p => p.test(file.path))) return 'opaque';
  if (ANALYZABLE_EXTENSIONS.has(ext)) return 'analyzable';
  if (INERT_EXTENSIONS.has(ext)) return 'inert';

  // Unknown extension -> opaque
  if (ext === '' || ext === '.lock' || ext === '.map') return 'opaque';

  return 'opaque';
}

function opaqueReason(file: FileInfo): string {
  const ext = path.extname(file.path).toLowerCase();
  if (BINARY_EXTENSIONS.has(ext)) return `binary (${ext})`;
  if (MINIFIED_PATTERNS.some(p => p.test(file.path))) return 'minified/bundled';
  if (ext === '.lock') return 'lock file';
  if (ext === '.map') return 'source map';
  return `unknown extension (${ext || 'none'})`;
}

export function computeAnalyzability(files: FileInventory): AnalyzabilityScore {
  const opaqueFiles: Array<{ path: string; reason: string; size: number }> = [];
  let totalWeight = 0;
  let analyzableWeight = 0;

  for (const file of files.all) {
    const weight = Math.max(1, Math.log2(Math.max(1, file.size)));
    totalWeight += weight;

    const classification = classifyFile(file);
    if (classification === 'analyzable' || classification === 'inert') {
      analyzableWeight += weight;
    } else {
      opaqueFiles.push({
        path: file.relativePath,
        reason: opaqueReason(file),
        size: file.size,
      });
    }
  }

  const score = totalWeight > 0
    ? Math.round((analyzableWeight / totalWeight) * 100)
    : 100;

  return {
    totalFiles: files.all.length,
    analyzableFiles: files.all.length - opaqueFiles.length,
    score,
    opaqueFiles,
  };
}

export function generateAnalyzabilityFindings(analyzability: AnalyzabilityScore): Finding[] {
  const findings: Finding[] = [];

  if (analyzability.score < 60) {
    findings.push({
      id: `analyzability-low-${analyzability.score}`,
      ruleId: 'AA-ANALYZE-001',
      title: 'Low analyzability score',
      description: `Only ${analyzability.score}% of the codebase is inspectable. ${analyzability.opaqueFiles.length} files could not be analyzed.`,
      severity: 'medium',
      confidence: 'high',
      domain: 'supply-chain',
      location: { file: '.', line: 0 },
      remediation: 'Review opaque files for potential security risks. Consider removing unnecessary binaries from the repository.',
      standards: { owaspAgentic: ['ASI04'] },
    });
  }

  // Cap opaque binary findings at 5
  const largeBinaries = analyzability.opaqueFiles
    .filter(f => f.size > 10240)
    .slice(0, 5);

  for (const file of largeBinaries) {
    findings.push({
      id: `opaque-binary-${file.path}`,
      ruleId: 'AA-ANALYZE-002',
      title: `Opaque binary: ${file.path}`,
      description: `${file.reason} (${(file.size / 1024).toFixed(0)}KB) — cannot be inspected for security issues`,
      severity: 'low',
      confidence: 'high',
      domain: 'supply-chain',
      location: { file: file.path, line: 0 },
      remediation: 'Verify this file is trusted and necessary. Consider using a package manager instead of vendoring binaries.',
      standards: { owaspAgentic: ['ASI04'] },
    });
  }

  return findings;
}
