import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { FrameworkInfo } from '../../types/agent-graph.js';

const AI_FRAMEWORKS = new Set([
  'langchain', 'langchain-core', 'langchain-openai', 'langchain-anthropic',
  'langchain-community', 'langgraph',
  'crewai', 'crewai-tools',
  'openai',
  'anthropic',
  'mcp', 'fastmcp',
  'autogen', 'pyautogen',
  'transformers', 'torch', 'tensorflow',
  'chromadb', 'pinecone-client', 'faiss-cpu', 'faiss-gpu',
  'weaviate-client', 'qdrant-client', 'pymilvus',
  'pydantic', 'pydantic-ai',
  'llama-index', 'llamaindex',
  'huggingface-hub',
  'boto3', 'botocore',
  'google-generativeai', 'google-cloud-aiplatform',
  'cohere', 'replicate', 'together',
]);

const JAVA_AI_GROUPS = new Map<string, string>([
  ['dev.langchain4j', 'langchain4j'],
  ['dev.langgraph4j', 'langgraph4j'],
  ['org.springframework.ai', 'spring-ai'],
  ['com.google.cloud', 'google-cloud-ai'],
  ['io.quarkiverse.langchain4j', 'quarkus-langchain4j'],
]);

const GO_AI_MODULES = new Set([
  'github.com/tmc/langchaingo',
  'github.com/cloudwego/eino',
  'github.com/firebase/genkit',
  'cloud.google.com/go/ai',
  'github.com/google/generative-ai-go',
  'github.com/sashabaranov/go-openai',
  'github.com/anthropics/anthropic-sdk-go',
]);

const JS_AI_PACKAGES = new Set([
  'openai', '@openai/agents',
  'anthropic', '@anthropic-ai/sdk',
  'langchain', '@langchain/core', '@langchain/openai', '@langchain/anthropic',
  '@langchain/community', '@langchain/langgraph',
  '@modelcontextprotocol/sdk',
  'ai', '@ai-sdk/openai', '@ai-sdk/anthropic',
  'chromadb', '@pinecone-database/pinecone',
  '@qdrant/js-client-rest',
  'ollama',
  '@google/generative-ai',
  'cohere-ai',
]);

export function extractFrameworkVersions(files: FileInventory): FrameworkInfo[] {
  const versions: FrameworkInfo[] = [];

  for (const file of files.all) {
    const basename = file.relativePath.split('/').pop() ?? '';

    if (basename === 'requirements.txt' || basename === 'requirements-dev.txt') {
      versions.push(...parseRequirementsTxt(file.path, file.relativePath));
    } else if (basename === 'pyproject.toml') {
      versions.push(...parsePyprojectToml(file.path, file.relativePath));
    } else if (basename === 'package.json') {
      versions.push(...parsePackageJson(file.path, file.relativePath));
    } else if (basename === 'pom.xml') {
      versions.push(...parsePomXml(file.path, file.relativePath));
    } else if (basename === 'build.gradle' || basename === 'build.gradle.kts') {
      versions.push(...parseBuildGradle(file.path, file.relativePath));
    } else if (basename === 'go.mod') {
      versions.push(...parseGoMod(file.path, file.relativePath));
    }
  }

  return versions;
}

function parseRequirementsTxt(filePath: string, relativePath: string): FrameworkInfo[] {
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return [];
  }

  const results: FrameworkInfo[] = [];
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    // Match: package==1.0.0, package>=1.0.0, package~=1.0.0, package
    const match = trimmed.match(/^([a-zA-Z0-9_-]+)\s*(?:([=~<>!]+)\s*([^\s;,#]+))?/);
    if (!match) continue;

    const pkgName = match[1].toLowerCase();
    if (!AI_FRAMEWORKS.has(pkgName)) continue;

    results.push({
      name: pkgName,
      version: match[3] || undefined,
      file: relativePath,
    });
  }

  return results;
}

function parsePyprojectToml(filePath: string, relativePath: string): FrameworkInfo[] {
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return [];
  }

  const results: FrameworkInfo[] = [];
  // Simple TOML dependency parsing - look for dependencies array entries
  const depPattern = /["']([a-zA-Z0-9_-]+)\s*(?:([=~<>!]+)\s*([^"'\s,\]]+))?["']/g;
  let match: RegExpExecArray | null;

  while ((match = depPattern.exec(content)) !== null) {
    const pkgName = match[1].toLowerCase();
    if (!AI_FRAMEWORKS.has(pkgName)) continue;

    results.push({
      name: pkgName,
      version: match[3] || undefined,
      file: relativePath,
    });
  }

  return results;
}

function parsePackageJson(filePath: string, relativePath: string): FrameworkInfo[] {
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return [];
  }

  let parsed: Record<string, any>;
  try {
    parsed = JSON.parse(content);
  } catch {
    return [];
  }

  const results: FrameworkInfo[] = [];
  const allDeps = {
    ...parsed.dependencies,
    ...parsed.devDependencies,
  };

  for (const [name, version] of Object.entries(allDeps)) {
    if (!JS_AI_PACKAGES.has(name)) continue;
    results.push({
      name,
      version: typeof version === 'string' ? version.replace(/^[\^~>=<]/, '') : undefined,
      file: relativePath,
    });
  }

  return results;
}

function parsePomXml(filePath: string, relativePath: string): FrameworkInfo[] {
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return [];
  }

  const results: FrameworkInfo[] = [];
  // Match <dependency> blocks: <groupId>...</groupId> <artifactId>...</artifactId> <version>...</version>
  const depPattern = /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>(?:\s*<version>([^<]+)<\/version>)?/g;
  let match: RegExpExecArray | null;

  while ((match = depPattern.exec(content)) !== null) {
    const groupId = match[1].trim();
    const artifactId = match[2].trim();
    const version = match[3]?.trim();

    // Check if this group matches a known AI framework
    for (const [prefix, frameworkName] of JAVA_AI_GROUPS) {
      if (groupId.startsWith(prefix)) {
        results.push({
          name: `${frameworkName}:${artifactId}`,
          version: version || undefined,
          file: relativePath,
        });
        break;
      }
    }
  }

  return results;
}

function parseBuildGradle(filePath: string, relativePath: string): FrameworkInfo[] {
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return [];
  }

  const results: FrameworkInfo[] = [];
  // Match: implementation 'group:artifact:version' or implementation("group:artifact:version")
  const depPattern = /(?:implementation|api|compileOnly)\s*[\("']([^:]+):([^:]+):([^"'\)]+)/g;
  let match: RegExpExecArray | null;

  while ((match = depPattern.exec(content)) !== null) {
    const groupId = match[1].trim();
    const artifactId = match[2].trim();
    const version = match[3].trim();

    for (const [prefix, frameworkName] of JAVA_AI_GROUPS) {
      if (groupId.startsWith(prefix)) {
        results.push({
          name: `${frameworkName}:${artifactId}`,
          version,
          file: relativePath,
        });
        break;
      }
    }
  }

  return results;
}

function parseGoMod(filePath: string, relativePath: string): FrameworkInfo[] {
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return [];
  }

  const results: FrameworkInfo[] = [];
  // Match: require github.com/foo/bar v1.2.3  or  github.com/foo/bar v1.2.3 (inside require block)
  const requirePattern = /(?:^|\n)\s*(?:require\s+)?(\S+)\s+(v[\d.]+\S*)/g;
  let match: RegExpExecArray | null;

  while ((match = requirePattern.exec(content)) !== null) {
    const modPath = match[1].trim();
    const version = match[2].trim();

    if (GO_AI_MODULES.has(modPath)) {
      // Use short name: last path segment
      const shortName = modPath.split('/').pop() || modPath;
      results.push({
        name: shortName,
        version: version.replace(/^v/, ''),
        file: relativePath,
      });
    }
  }

  return results;
}
