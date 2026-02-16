export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Confidence = 'high' | 'medium' | 'low';

export type FrameworkId =
  | 'langchain'
  | 'crewai'
  | 'mcp'
  | 'openai'
  | 'autogen'
  | 'vercel-ai'
  | 'bedrock'
  | 'langchain4j'
  | 'spring-ai'
  | 'golang-ai'
  | 'generic';

export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';

export type SecurityDomain =
  | 'goal-integrity'
  | 'tool-safety'
  | 'identity-access'
  | 'supply-chain'
  | 'code-execution'
  | 'memory-context'
  | 'data-leakage'
  | 'cascading-failures'
  | 'human-oversight'
  | 'inter-agent'
  | 'reliability-bounds'
  | 'rogue-agent';

export type ReportFormat = 'terminal' | 'json' | 'html' | 'sarif';

export interface FileInfo {
  path: string;
  relativePath: string;
  language: 'python' | 'typescript' | 'javascript' | 'java' | 'go' | 'yaml' | 'json' | 'toml' | 'other';
  size: number;
}

export interface FileInventory {
  all: FileInfo[];
  python: FileInfo[];
  typescript: FileInfo[];
  javascript: FileInfo[];
  java: FileInfo[];
  go: FileInfo[];
  yaml: FileInfo[];
  json: FileInfo[];
  configs: FileInfo[];
}

export interface Location {
  file: string;
  line: number;
  column?: number;
  snippet?: string;
}
