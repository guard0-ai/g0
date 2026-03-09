import * as fs from 'node:fs';
import type { Rule } from '../../types/control.js';
import type { Finding } from '../../types/finding.js';
import type { AgentGraph } from '../../types/agent-graph.js';
import {
  isTreeSitterAvailable,
  getFileTreeForLang,
  findFunctionCalls,
  getKeywordArgument,
} from '../ast/index.js';

export const memoryContextRules: Rule[] = [
  {
    id: 'AA-MP-001',
    name: 'Unbounded conversation memory',
    domain: 'memory-context',
    severity: 'medium',
    confidence: 'medium',
    description: 'Conversation memory has no size limits, risking context window overflow and memory poisoning.',
    frameworks: ['langchain', 'crewai'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const astLang = file.language === 'python' ? 'python' as const
          : file.language === 'typescript' ? 'typescript' as const
          : file.language === 'javascript' ? 'javascript' as const : null;
        const tree = astLang && isTreeSitterAvailable() ? getFileTreeForLang(file.path, content, astLang) : null;

        if (tree) {
          // AST: find ConversationBufferMemory calls, verify no k kwarg
          const bufferCalls = findFunctionCalls(tree, 'ConversationBufferMemory');
          const windowCalls = findFunctionCalls(tree, 'ConversationBufferWindowMemory');

          // If using WindowMemory, skip (it has built-in bounds)
          if (windowCalls.length > 0) continue;

          for (const call of bufferCalls) {
            const kArg = getKeywordArgument(call, 'k');
            if (kArg) continue; // Has a limit

            const line = call.startPosition.row + 1;
            findings.push({
              id: `AA-MP-001-${findings.length}`,
              ruleId: 'AA-MP-001',
              title: 'Unbounded conversation memory',
              description: `ConversationBufferMemory in ${file.relativePath} stores all messages without limits.`,
              severity: 'medium',
              confidence: 'medium',
              domain: 'memory-context',
              location: { file: file.relativePath, line, snippet: 'ConversationBufferMemory()' },
              remediation: 'Use ConversationBufferWindowMemory with k parameter or ConversationSummaryMemory.',
              standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
            });
          }
        } else {
          // Regex fallback
          if (/ConversationBufferMemory\s*\(/.test(content) && !/ConversationBufferWindowMemory/.test(content)) {
            const match = content.match(/ConversationBufferMemory\s*\(/);
            if (match) {
              const line = content.substring(0, match.index!).split('\n').length;
              findings.push({
                id: `AA-MP-001-${findings.length}`,
                ruleId: 'AA-MP-001',
                title: 'Unbounded conversation memory',
                description: `ConversationBufferMemory in ${file.relativePath} stores all messages without limits.`,
                severity: 'medium',
                confidence: 'medium',
                domain: 'memory-context',
                location: { file: file.relativePath, line, snippet: 'ConversationBufferMemory()' },
                remediation: 'Use ConversationBufferWindowMemory with k parameter or ConversationSummaryMemory.',
                standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
              });
            }
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-002',
    name: 'No session isolation in memory',
    domain: 'memory-context',
    severity: 'high',
    confidence: 'medium',
    description: 'Memory store has no session isolation, allowing cross-user data leakage.',
    frameworks: ['langchain', 'crewai'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001', 'F002'], iso42001: ['A.6.3'], nistAiRmf: ['MEASURE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const astLang = file.language === 'python' ? 'python' as const
          : file.language === 'typescript' ? 'typescript' as const
          : file.language === 'javascript' ? 'javascript' as const : null;
        const tree = astLang && isTreeSitterAvailable() ? getFileTreeForLang(file.path, content, astLang) : null;

        if (tree) {
          // AST: find memory store constructors, check for session_id kwarg
          const memoryCallPatterns = /(?:Redis|Postgres|Mongo|SQLite)ChatMessageHistory$/;
          const memoryCalls = findFunctionCalls(tree, memoryCallPatterns);

          for (const call of memoryCalls) {
            const hasSession =
              getKeywordArgument(call, 'session_id') !== null ||
              getKeywordArgument(call, 'user_id') !== null ||
              getKeywordArgument(call, 'namespace') !== null ||
              getKeywordArgument(call, 'prefix') !== null;

            if (!hasSession) {
              const line = call.startPosition.row + 1;
              const callee = call.childForFieldName('function');
              findings.push({
                id: `AA-MP-002-${findings.length}`,
                ruleId: 'AA-MP-002',
                title: 'No session isolation in memory',
                description: `Memory store in ${file.relativePath} has no apparent session isolation.`,
                severity: 'high',
                confidence: 'medium',
                domain: 'memory-context',
                location: { file: file.relativePath, line, snippet: callee?.text ?? call.text.substring(0, 40) },
                remediation: 'Add session_id or user_id to memory stores to isolate user data.',
                standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001', 'F002'], iso42001: ['A.6.3'], nistAiRmf: ['MEASURE-2.1'] },
              });
            }
          }
        } else {
          // Regex fallback
          const memoryPatterns = [
            /(?:Redis|Postgres|Mongo|SQLite)ChatMessageHistory\s*\(/g,
            /RedisChatMessageHistory\s*\(/g,
            /PostgresChatMessageHistory\s*\(/g,
          ];

          for (const pattern of memoryPatterns) {
            pattern.lastIndex = 0;
            let match: RegExpExecArray | null;
            while ((match = pattern.exec(content)) !== null) {
              const region = content.substring(match.index, match.index + 500);
              const hasSessionId = /session_id|user_id|namespace|prefix/i.test(region);

              if (!hasSessionId) {
                const line = content.substring(0, match.index).split('\n').length;
                findings.push({
                  id: `AA-MP-002-${findings.length}`,
                  ruleId: 'AA-MP-002',
                  title: 'No session isolation in memory',
                  description: `Memory store in ${file.relativePath} has no apparent session isolation.`,
                  severity: 'high',
                  confidence: 'medium',
                  domain: 'memory-context',
                  location: { file: file.relativePath, line, snippet: match[0] },
                  remediation: 'Add session_id or user_id to memory stores to isolate user data.',
                  standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001', 'F002'], iso42001: ['A.6.3'], nistAiRmf: ['MEASURE-2.1'] },
                });
              }
            }
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-003',
    name: 'No TTL on persistent memory',
    domain: 'memory-context',
    severity: 'medium',
    confidence: 'medium',
    description: 'Persistent memory has no TTL, allowing stale or poisoned data to persist indefinitely.',
    frameworks: ['all'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const storePatterns = [
          /(?:Redis|Postgres|Mongo|SQLite)(?:Chat)?(?:MessageHistory|Memory|Store)\s*\(/g,
        ];

        for (const pattern of storePatterns) {
          pattern.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = pattern.exec(content)) !== null) {
            const region = content.substring(match.index, match.index + 500);
            const hasTTL = /ttl|expire|max_age|retention/i.test(region);

            if (!hasTTL) {
              const line = content.substring(0, match.index).split('\n').length;
              findings.push({
                id: `AA-MP-003-${findings.length}`,
                ruleId: 'AA-MP-003',
                title: 'No TTL on persistent memory',
                description: `Persistent memory in ${file.relativePath} has no TTL configured.`,
                severity: 'medium',
                confidence: 'medium',
                domain: 'memory-context',
                location: { file: file.relativePath, line, snippet: match[0] },
                remediation: 'Configure TTL on persistent memory stores to limit data retention.',
                standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-3.1'] },
              });
            }
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-004',
    name: 'No memory namespace isolation',
    domain: 'memory-context',
    severity: 'medium',
    confidence: 'medium',
    description: 'Vector store or memory lacks namespace isolation between agents or users.',
    frameworks: ['all'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001', 'F002'], iso42001: ['A.6.3'], nistAiRmf: ['MEASURE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const vectorPatterns = [
          /(?:Chroma|Pinecone|Weaviate|Qdrant|FAISS)(?:\.from_|Client)\s*\(/g,
        ];

        for (const pattern of vectorPatterns) {
          pattern.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = pattern.exec(content)) !== null) {
            const region = content.substring(match.index, match.index + 500);
            const hasNamespace = /namespace|collection|index_name|tenant/i.test(region);

            if (!hasNamespace) {
              const line = content.substring(0, match.index).split('\n').length;
              findings.push({
                id: `AA-MP-004-${findings.length}`,
                ruleId: 'AA-MP-004',
                title: 'No namespace isolation in vector store',
                description: `Vector store in ${file.relativePath} lacks namespace isolation.`,
                severity: 'medium',
                confidence: 'medium',
                domain: 'memory-context',
                location: { file: file.relativePath, line, snippet: match[0] },
                remediation: 'Use collection names or namespaces to isolate data per agent or user.',
                standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001', 'F002'], iso42001: ['A.6.3'], nistAiRmf: ['MEASURE-2.1'] },
              });
            }
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-005',
    name: 'Shared memory across users',
    domain: 'memory-context',
    severity: 'high',
    confidence: 'medium',
    description: 'Memory instance is declared at module level without user/session scoping, potentially sharing state across users.',
    frameworks: ['langchain', 'crewai'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001', 'F002'], iso42001: ['A.6.3'], nistAiRmf: ['MEASURE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const memoryPattern = /memory\s*=\s*(?:ConversationBufferMemory|ChatMessageHistory|InMemoryChatMessageHistory)\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = memoryPattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          // Check if it's module-level (line < 20 or not indented)
          const matchLine = content.split('\n')[line - 1] ?? '';
          const isModuleLevel = line < 20 || /^\S/.test(matchLine);
          if (isModuleLevel) {
            // Check surrounding context for user_id scoping
            const region = content.substring(Math.max(0, match.index - 200), match.index + 200);
            if (!/user_id|session_id|self\./.test(region)) {
              findings.push({
                id: `AA-MP-005-${findings.length}`,
                ruleId: 'AA-MP-005',
                title: 'Shared memory across users',
                description: `Module-level memory instance in ${file.relativePath} may share state across users.`,
                severity: 'high',
                confidence: 'medium',
                domain: 'memory-context',
                location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
                remediation: 'Create memory instances per user/session, not at module level. Pass user_id or session_id.',
                standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001', 'F002'], iso42001: ['A.6.3'], nistAiRmf: ['MEASURE-2.1'] },
              });
            }
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-006',
    name: 'Memory persisted without encryption',
    domain: 'memory-context',
    severity: 'medium',
    confidence: 'medium',
    description: 'Memory data is persisted to disk or storage without encryption.',
    frameworks: ['all'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001', 'E001'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const persistPattern = /(?:save_to_file|persist|dump|to_json|to_disk)\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = persistPattern.exec(content)) !== null) {
          // Check nearby context for encryption patterns
          const regionStart = Math.max(0, match.index - 500);
          const regionEnd = Math.min(content.length, match.index + 500);
          const region = content.substring(regionStart, regionEnd);
          const hasEncryption = /encrypt|cipher|crypto|fernet|aes|kms/i.test(region);

          // Also check if this is in a memory-related context
          const hasMemoryContext = /memory|chat|message|conversation|history/i.test(region);

          if (!hasEncryption && hasMemoryContext) {
            const line = content.substring(0, match.index).split('\n').length;
            // Use the full source line for the snippet (not just the regex match text)
            const sourceLine = content.split('\n')[line - 1]?.trim() ?? match[0];
            findings.push({
              id: `AA-MP-006-${findings.length}`,
              ruleId: 'AA-MP-006',
              title: 'Memory persisted without encryption',
              description: `Memory persistence in ${file.relativePath} does not appear to use encryption.`,
              severity: 'medium',
              confidence: 'medium',
              domain: 'memory-context',
              location: { file: file.relativePath, line, snippet: sourceLine.substring(0, 80) },
              remediation: 'Encrypt memory data before persisting to disk or storage. Use Fernet, AES, or a KMS.',
              standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001', 'E001'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-007',
    name: 'No context length validation',
    domain: 'memory-context',
    severity: 'medium',
    confidence: 'medium',
    description: 'LLM client is instantiated without max_tokens parameter, risking context window overflow.',
    frameworks: ['all'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        // Skip if the file uses AgentExecutor with max_iterations (framework-level context control)
        if (/AgentExecutor\s*\([\s\S]*?max_iterations/.test(content)) continue;

        const llmPattern = /(?:ChatOpenAI|OpenAI|Anthropic|ChatAnthropic)\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = llmPattern.exec(content)) !== null) {
          // Check the call region for max_tokens
          const callEnd = content.indexOf(')', match.index + match[0].length);
          const callRegion = content.substring(match.index, callEnd !== -1 ? callEnd + 1 : match.index + 500);
          if (!/max_tokens|max_output_tokens|maxTokens/.test(callRegion)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-MP-007-${findings.length}`,
              ruleId: 'AA-MP-007',
              title: 'No context length validation',
              description: `LLM client in ${file.relativePath} does not specify max_tokens, risking unbounded responses.`,
              severity: 'medium',
              confidence: 'medium',
              domain: 'memory-context',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Set max_tokens parameter on LLM clients to control response length and prevent context overflow.',
              standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-008',
    name: 'RAG retriever without access control',
    domain: 'memory-context',
    severity: 'high',
    confidence: 'medium',
    description: 'RAG retriever is used without access control, potentially exposing data across users.',
    frameworks: ['all'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], aiuc1: ['F002', 'B001'], iso42001: ['A.6.2'], nistAiRmf: ['MEASURE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const retrieverPattern = /(?:as_retriever|VectorStoreRetriever|SelfQueryRetriever)\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = retrieverPattern.exec(content)) !== null) {
          // Check surrounding context for access control patterns
          const regionStart = Math.max(0, match.index - 300);
          const regionEnd = Math.min(content.length, match.index + 500);
          const region = content.substring(regionStart, regionEnd);
          const hasAccessControl = /user_id|filter|access_control|permission|namespace|tenant/i.test(region);

          if (!hasAccessControl) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-MP-008-${findings.length}`,
              ruleId: 'AA-MP-008',
              title: 'RAG retriever without access control',
              description: `Retriever in ${file.relativePath} has no apparent access control or filtering.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'memory-context',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Add user_id filtering, namespace isolation, or access control to RAG retrievers.',
              standards: { owaspAgentic: ['ASI06'], aiuc1: ['F002', 'B001'], iso42001: ['A.6.2'], nistAiRmf: ['MEASURE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-009',
    name: 'Unbounded conversation buffer',
    domain: 'memory-context',
    severity: 'high',
    confidence: 'medium',
    description: 'ConversationBufferMemory is used without k or max_token_limit, allowing unbounded memory growth and potential context window overflow.',
    frameworks: ['langchain'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        // Match ConversationBufferMemory( but NOT ConversationBufferWindowMemory(
        const bufferPattern = /ConversationBufferMemory\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = bufferPattern.exec(content)) !== null) {
          // Skip if it's actually ConversationBufferWindowMemory
          const preceding = content.substring(Math.max(0, match.index - 10), match.index);
          if (/Window$/.test(preceding)) continue;

          // Check the call region for k or max_token_limit
          const callEnd = content.indexOf(')', match.index + match[0].length);
          const callRegion = content.substring(match.index, callEnd !== -1 ? callEnd + 1 : match.index + 500);
          if (!/\bk\s*=|max_token_limit\s*=/.test(callRegion)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-MP-009-${findings.length}`,
              ruleId: 'AA-MP-009',
              title: 'Unbounded conversation buffer',
              description: `ConversationBufferMemory in ${file.relativePath} has no k or max_token_limit, allowing unbounded growth.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'memory-context',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Use ConversationBufferWindowMemory with k parameter, or set max_token_limit on the memory instance.',
              standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-010',
    name: 'Memory persistence without encryption',
    domain: 'memory-context',
    severity: 'high',
    confidence: 'medium',
    description: 'Memory is saved to file or database without encryption, risking exposure of sensitive conversation data.',
    frameworks: ['all'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        // Detect save_context, save_memory, persist writing to file/sqlite
        const persistPattern = /(?:save_context|save_memory|persist)\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = persistPattern.exec(content)) !== null) {
          const regionStart = Math.max(0, match.index - 500);
          const regionEnd = Math.min(content.length, match.index + 500);
          const region = content.substring(regionStart, regionEnd);

          // Check if persisting to file or sqlite
          const hasFileOrDb = /\.json|\.txt|\.db|\.sqlite|sqlite3|open\s*\(|write|file_path|db_path/i.test(region);
          // Check for encryption patterns
          const hasEncryption = /encrypt|cipher|crypto|fernet|aes|kms|gpg|sealed/i.test(region);

          if (hasFileOrDb && !hasEncryption) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-MP-010-${findings.length}`,
              ruleId: 'AA-MP-010',
              title: 'Memory persistence without encryption',
              description: `Memory in ${file.relativePath} is persisted to file or database without encryption.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'memory-context',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Encrypt memory data before persisting. Use Fernet, AES-256, or a KMS-backed encryption scheme.',
              standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-011',
    name: 'Vector store without namespace isolation',
    domain: 'memory-context',
    severity: 'high',
    confidence: 'medium',
    description: 'Vector store is initialized without namespace or per-user collection isolation, risking cross-tenant data leakage.',
    frameworks: ['all'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        // Match vector store constructors: Chroma(, Pinecone(, FAISS(
        const vectorPattern = /(?:Chroma|Pinecone|FAISS)\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = vectorPattern.exec(content)) !== null) {
          // Grab the call region
          const callEnd = content.indexOf(')', match.index + match[0].length);
          const regionEnd = Math.min(content.length, callEnd !== -1 ? callEnd + 1 : match.index + 500);
          const callRegion = content.substring(match.index, regionEnd);

          // Check for namespace isolation patterns
          const hasNamespace = /namespace\s*=|tenant\s*=/.test(callRegion);
          const hasUserCollection = /collection_name\s*=.*user|collection_name\s*=.*tenant|collection_name\s*=.*session/i.test(callRegion);

          if (!hasNamespace && !hasUserCollection) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-MP-011-${findings.length}`,
              ruleId: 'AA-MP-011',
              title: 'Vector store without namespace isolation',
              description: `Vector store in ${file.relativePath} lacks namespace or per-user collection isolation.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'memory-context',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Add namespace= or tenant= parameter, or use per-user collection names to isolate vector data.',
              standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-012',
    name: 'Memory shared between agents',
    domain: 'memory-context',
    severity: 'high',
    confidence: 'medium',
    description: 'A single memory instance is used across multiple agent constructors, risking cross-agent context leakage.',
    frameworks: ['langchain', 'crewai'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        // Find memory variable assignments
        const memAssignPattern = /(\w+)\s*=\s*(?:ConversationBufferMemory|ConversationBufferWindowMemory|ConversationSummaryMemory|ChatMessageHistory|InMemoryChatMessageHistory)\s*\(/g;
        let assignMatch: RegExpExecArray | null;
        while ((assignMatch = memAssignPattern.exec(content)) !== null) {
          const memVarName = assignMatch[1];
          // Count how many agent constructors reference this memory variable via memory= param
          const agentMemPattern = new RegExp(
            `(?:Agent|AgentExecutor|initialize_agent|CrewAgent|Crew)\\s*\\([^)]*memory\\s*=\\s*${memVarName}\\b`,
            'g',
          );
          const agentUses: number[] = [];
          let agentMatch: RegExpExecArray | null;
          while ((agentMatch = agentMemPattern.exec(content)) !== null) {
            const agentLine = content.substring(0, agentMatch.index).split('\n').length;
            agentUses.push(agentLine);
          }

          if (agentUses.length > 1) {
            const line = content.substring(0, assignMatch.index).split('\n').length;
            findings.push({
              id: `AA-MP-012-${findings.length}`,
              ruleId: 'AA-MP-012',
              title: 'Memory shared between agents',
              description: `Memory variable '${memVarName}' in ${file.relativePath} is used by ${agentUses.length} agent constructors.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'memory-context',
              location: { file: file.relativePath, line, snippet: assignMatch[0].substring(0, 60) },
              remediation: 'Create separate memory instances for each agent to prevent cross-agent context leakage.',
              standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-013',
    name: 'No memory cleanup on session end',
    domain: 'memory-context',
    severity: 'medium',
    confidence: 'medium',
    description: 'Memory or session is used without clear/cleanup handlers, risking stale data persistence between sessions.',
    frameworks: ['all'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        // Check for memory usage
        const memoryUsagePattern = /(?:ConversationBufferMemory|ConversationBufferWindowMemory|ConversationSummaryMemory|ChatMessageHistory|InMemoryChatMessageHistory)\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = memoryUsagePattern.exec(content)) !== null) {
          // Check entire file for cleanup patterns
          const hasCleanup = /\.clear\s*\(|\.reset\s*\(|memory_cleanup|session_cleanup|on_session_end|atexit|signal\.signal|finally\s*:|__del__|on_disconnect|on_close/i.test(content);

          if (!hasCleanup) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-MP-013-${findings.length}`,
              ruleId: 'AA-MP-013',
              title: 'No memory cleanup on session end',
              description: `Memory in ${file.relativePath} has no cleanup or clear handler for session termination.`,
              severity: 'medium',
              confidence: 'medium',
              domain: 'memory-context',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Add memory.clear() or cleanup handlers on session end, disconnect, or application shutdown.',
              standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
            });
            // Only report once per file
            break;
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-014',
    name: 'Memory includes raw tool outputs',
    domain: 'memory-context',
    severity: 'medium',
    confidence: 'medium',
    description: 'Tool outputs are stored directly in memory without filtering, risking injection of untrusted data into conversation context.',
    frameworks: ['langchain', 'crewai'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        // Detect return_direct=True (tool output goes straight to user/memory without agent filtering)
        const returnDirectPattern = /return_direct\s*=\s*True/g;
        let match: RegExpExecArray | null;
        while ((match = returnDirectPattern.exec(content)) !== null) {
          // Check surrounding context for memory usage
          const hasMemoryContext = /memory|ConversationBuffer|ChatMessageHistory|save_context/i.test(content);
          if (hasMemoryContext) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-MP-014-${findings.length}`,
              ruleId: 'AA-MP-014',
              title: 'Memory includes raw tool outputs',
              description: `Tool with return_direct=True in ${file.relativePath} sends unfiltered output to memory.`,
              severity: 'medium',
              confidence: 'medium',
              domain: 'memory-context',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: 'Filter or sanitize tool outputs before storing in memory. Avoid return_direct=True with persistent memory.',
              standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
            });
          }
        }

        // Also detect memory.save_context with tool results directly
        const saveToolPattern = /save_context\s*\([^)]*tool_output|save_context\s*\([^)]*result/g;
        while ((match = saveToolPattern.exec(content)) !== null) {
          const regionStart = Math.max(0, match.index - 300);
          const region = content.substring(regionStart, match.index + match[0].length + 300);
          const hasFiltering = /sanitize|filter|clean|strip|truncate|validate/i.test(region);

          if (!hasFiltering) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-MP-014-${findings.length}`,
              ruleId: 'AA-MP-014',
              title: 'Memory includes raw tool outputs',
              description: `Tool output saved to memory without filtering in ${file.relativePath}.`,
              severity: 'medium',
              confidence: 'medium',
              domain: 'memory-context',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Filter or sanitize tool outputs before storing in memory. Remove sensitive data and limit output size.',
              standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-015',
    name: 'Memory search without relevance filtering',
    domain: 'memory-context',
    severity: 'medium',
    confidence: 'medium',
    description: 'Vector similarity search is used without score_threshold or k limit, risking retrieval of irrelevant or poisoned context.',
    frameworks: ['all'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        // Match similarity_search( calls
        const searchPattern = /similarity_search\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = searchPattern.exec(content)) !== null) {
          // Grab the call region to check for parameters
          const callEnd = content.indexOf(')', match.index + match[0].length);
          const regionEnd = Math.min(content.length, callEnd !== -1 ? callEnd + 1 : match.index + 500);
          const callRegion = content.substring(match.index, regionEnd);

          const hasScoreThreshold = /score_threshold\s*=/.test(callRegion);
          const hasKLimit = /\bk\s*=/.test(callRegion);

          if (!hasScoreThreshold && !hasKLimit) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-MP-015-${findings.length}`,
              ruleId: 'AA-MP-015',
              title: 'Memory search without relevance filtering',
              description: `similarity_search in ${file.relativePath} has no score_threshold or k limit.`,
              severity: 'medium',
              confidence: 'medium',
              domain: 'memory-context',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Add score_threshold and/or k parameters to similarity_search to filter irrelevant results.',
              standards: { owaspAgentic: ['ASI06'], aiuc1: ['F001'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-016',
    name: 'Context window near limit without truncation strategy',
    domain: 'memory-context',
    severity: 'high',
    confidence: 'medium',
    description: 'LLM context is built without a truncation or summarization strategy, risking overflow and lost instructions.',
    frameworks: ['all'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], iso23894: ['R.2', 'R.5'], owaspAivss: ['AIVSS-DP'], a2asBasic: ['ISOL', 'AUDIT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:messages\.append|add_message|chat_history\.add|messages\.push|messages\s*\+\s*=)/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const hasStrategy = /truncat|summariz|trim_messages|max_history|window_size|ConversationSummaryMemory|token_count|count_tokens/i.test(content);
          if (!hasStrategy) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-MP-016-${findings.length}`, ruleId: 'AA-MP-016',
              title: 'Context window near limit without truncation strategy',
              description: `Messages are appended in ${file.relativePath} without a truncation or summarization strategy.`,
              severity: 'high', confidence: 'medium', domain: 'memory-context',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: 'Implement a truncation strategy (sliding window, summarization, or token counting) to prevent context overflow.',
              standards: { owaspAgentic: ['ASI06'], iso23894: ['R.2', 'R.5'], owaspAivss: ['AIVSS-DP'], a2asBasic: ['ISOL', 'AUDIT'] },
            });
            break; // One finding per file
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-017',
    name: 'Memory poisoning via tool output',
    domain: 'memory-context',
    severity: 'high',
    confidence: 'medium',
    description: 'Tool results are stored in memory without sanitization, enabling memory poisoning attacks.',
    frameworks: ['all'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], iso23894: ['R.2', 'R.5'], owaspAivss: ['AIVSS-DP'], a2asBasic: ['ISOL', 'AUDIT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:memory\.(?:save|add|store|put)|add_to_memory|save_context)\s*\([^)]*(?:tool_output|tool_result|\.output|\.result)/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const region = content.substring(Math.max(0, match.index - 300), Math.min(content.length, match.index + 300));
          if (!/sanitiz|filter|clean|strip_tags|escape|validate_output/i.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-MP-017-${findings.length}`, ruleId: 'AA-MP-017',
              title: 'Memory poisoning via tool output',
              description: `Tool output stored in memory without sanitization in ${file.relativePath}.`,
              severity: 'high', confidence: 'medium', domain: 'memory-context',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Sanitize and validate tool outputs before storing them in memory. Strip HTML, limit length, and filter control characters.',
              standards: { owaspAgentic: ['ASI06'], iso23894: ['R.2', 'R.5'], owaspAivss: ['AIVSS-DP'], a2asBasic: ['ISOL', 'AUDIT'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-018',
    name: 'No memory access audit log',
    domain: 'memory-context',
    severity: 'medium',
    confidence: 'medium',
    description: 'Memory read/write operations are not logged for audit purposes.',
    frameworks: ['all'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], iso23894: ['R.2', 'R.5'], owaspAivss: ['AIVSS-DP'], a2asBasic: ['ISOL', 'AUDIT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const memoryPattern = /(?:ConversationBufferMemory|ChatMessageHistory|InMemoryChatMessageHistory|VectorStore|ChromaDB|Pinecone|FAISS)\s*\(/;
        if (!memoryPattern.test(content)) continue;
        const hasAuditLog = /audit|log_access|access_log|memory_log|logging\.info.*memory|logger\.info.*memory|log\.info.*memory/i.test(content);
        if (!hasAuditLog) {
          const match = content.match(memoryPattern);
          const line = match ? content.substring(0, match.index!).split('\n').length : 1;
          findings.push({
            id: `AA-MP-018-${findings.length}`, ruleId: 'AA-MP-018',
            title: 'No memory access audit log',
            description: `Memory operations in ${file.relativePath} are not logged for audit purposes.`,
            severity: 'medium', confidence: 'medium', domain: 'memory-context',
            location: { file: file.relativePath, line, snippet: match ? match[0].substring(0, 60) : 'memory usage' },
            remediation: 'Add audit logging for all memory read/write operations to enable forensic analysis.',
            standards: { owaspAgentic: ['ASI06'], iso23894: ['R.2', 'R.5'], owaspAivss: ['AIVSS-DP'], a2asBasic: ['ISOL', 'AUDIT'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-019',
    name: 'Stale memory not invalidated',
    domain: 'memory-context',
    severity: 'medium',
    confidence: 'medium',
    description: 'Memory entries have no TTL or expiration mechanism, allowing stale data to persist.',
    frameworks: ['all'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], iso23894: ['R.2', 'R.5'], owaspAivss: ['AIVSS-DP'], a2asBasic: ['ISOL', 'AUDIT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const memoryStorePattern = /(?:memory_store|cache|dict|Map)\s*(?:=|\()/;
        const memoryContextPattern = /(?:memory|conversation|chat_history|message_store)/i;
        if (!memoryContextPattern.test(content) || !memoryStorePattern.test(content)) continue;
        const hasTtl = /ttl|expire|max_age|retention|invalidat|evict|cleanup_interval|staleness/i.test(content);
        if (!hasTtl) {
          const match = content.match(memoryContextPattern);
          const line = match ? content.substring(0, match.index!).split('\n').length : 1;
          findings.push({
            id: `AA-MP-019-${findings.length}`, ruleId: 'AA-MP-019',
            title: 'Stale memory not invalidated',
            description: `Memory store in ${file.relativePath} has no TTL or expiration to invalidate stale entries.`,
            severity: 'medium', confidence: 'medium', domain: 'memory-context',
            location: { file: file.relativePath, line },
            remediation: 'Add TTL, expiration, or periodic cleanup to memory stores to prevent stale data accumulation.',
            standards: { owaspAgentic: ['ASI06'], iso23894: ['R.2', 'R.5'], owaspAivss: ['AIVSS-DP'], a2asBasic: ['ISOL', 'AUDIT'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-020',
    name: 'Memory replay attacks',
    domain: 'memory-context',
    severity: 'high',
    confidence: 'medium',
    description: 'Memory entries lack nonce or timestamp, making them vulnerable to replay attacks.',
    frameworks: ['all'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], iso23894: ['R.2', 'R.5'], owaspAivss: ['AIVSS-DP'], a2asBasic: ['ISOL', 'AUDIT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:add_message|save_context|memory\.save|memory\.add|store_message)\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const region = content.substring(Math.max(0, match.index - 500), Math.min(content.length, match.index + 500));
          if (!/nonce|timestamp|created_at|msg_id|message_id|uuid|sequence_number/i.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-MP-020-${findings.length}`, ruleId: 'AA-MP-020',
              title: 'Memory replay attacks',
              description: `Memory entry in ${file.relativePath} has no nonce or timestamp to prevent replay attacks.`,
              severity: 'high', confidence: 'medium', domain: 'memory-context',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Add timestamps, nonces, or unique message IDs to memory entries to prevent replay attacks.',
              standards: { owaspAgentic: ['ASI06'], iso23894: ['R.2', 'R.5'], owaspAivss: ['AIVSS-DP'], a2asBasic: ['ISOL', 'AUDIT'] },
            });
            break; // One finding per file
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-021',
    name: 'RAG retrieval without relevance threshold',
    domain: 'memory-context',
    severity: 'high',
    confidence: 'medium',
    description: 'Vector search returns results without a minimum relevance score, risking injection of irrelevant or poisoned content.',
    frameworks: ['all'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], iso23894: ['R.2', 'R.5'], owaspAivss: ['AIVSS-DP'], a2asBasic: ['ISOL', 'AUDIT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:similarity_search|vector_search|\.query|\.search|as_retriever)\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const region = content.substring(match.index, Math.min(content.length, match.index + 500));
          if (!/score_threshold|min_score|relevance_threshold|min_relevance|distance_threshold/i.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-MP-021-${findings.length}`, ruleId: 'AA-MP-021',
              title: 'RAG retrieval without relevance threshold',
              description: `Vector search in ${file.relativePath} has no relevance score threshold.`,
              severity: 'high', confidence: 'medium', domain: 'memory-context',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Set score_threshold or min_relevance on vector searches to filter out irrelevant results.',
              standards: { owaspAgentic: ['ASI06'], iso23894: ['R.2', 'R.5'], owaspAivss: ['AIVSS-DP'], a2asBasic: ['ISOL', 'AUDIT'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-022',
    name: 'Embedding injection in vector store',
    domain: 'memory-context',
    severity: 'high',
    confidence: 'medium',
    description: 'User input is directly embedded into vector store without filtering, enabling embedding injection attacks.',
    frameworks: ['all'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], iso23894: ['R.2', 'R.5'], owaspAivss: ['AIVSS-DP'], a2asBasic: ['ISOL', 'AUDIT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:add_texts|add_documents|from_texts|upsert|embed_documents)\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const region = content.substring(Math.max(0, match.index - 500), Math.min(content.length, match.index + 500));
          const hasUserInput = /user_input|request\.|user_text|query|user_message|input_text/i.test(region);
          const hasFiltering = /sanitiz|filter|clean|validate|strip|escape|moderate/i.test(region);
          if (hasUserInput && !hasFiltering) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-MP-022-${findings.length}`, ruleId: 'AA-MP-022',
              title: 'Embedding injection in vector store',
              description: `User input embedded into vector store without filtering in ${file.relativePath}.`,
              severity: 'high', confidence: 'medium', domain: 'memory-context',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Sanitize and validate user input before embedding into vector stores. Apply content moderation.',
              standards: { owaspAgentic: ['ASI06'], iso23894: ['R.2', 'R.5'], owaspAivss: ['AIVSS-DP'], a2asBasic: ['ISOL', 'AUDIT'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-023',
    name: 'Memory serialization without integrity check',
    domain: 'memory-context',
    severity: 'high',
    confidence: 'medium',
    description: 'Memory is serialized via pickle or JSON without HMAC or integrity verification.',
    frameworks: ['all'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], iso23894: ['R.2', 'R.5'], owaspAivss: ['AIVSS-DP'], a2asBasic: ['ISOL', 'AUDIT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const memoryContext = /memory|conversation|chat_history|message_store/i;
        if (!memoryContext.test(content)) continue;
        const pattern = /(?:pickle\.(?:dump|dumps|load|loads)|json\.(?:dump|dumps|load|loads)|serialize|deserialize)\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const region = content.substring(Math.max(0, match.index - 500), Math.min(content.length, match.index + 500));
          if (!/hmac|integrity|signature|sign|verify|hash_check|checksum|mac\b/i.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-MP-023-${findings.length}`, ruleId: 'AA-MP-023',
              title: 'Memory serialization without integrity check',
              description: `Memory serialization in ${file.relativePath} via ${match[0].replace(/\s*\($/, '')} lacks HMAC or integrity verification.`,
              severity: 'high', confidence: 'medium', domain: 'memory-context',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Add HMAC or digital signature verification to serialized memory data to prevent tampering.',
              standards: { owaspAgentic: ['ASI06'], iso23894: ['R.2', 'R.5'], owaspAivss: ['AIVSS-DP'], a2asBasic: ['ISOL', 'AUDIT'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-024',
    name: 'Cross-conversation memory bleed',
    domain: 'memory-context',
    severity: 'high',
    confidence: 'medium',
    description: 'Shared memory instance across conversations allows data leakage between different user sessions.',
    frameworks: ['all'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], iso23894: ['R.2', 'R.5'], owaspAivss: ['AIVSS-DP'], a2asBasic: ['ISOL', 'AUDIT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:shared_memory|global_memory|app\.state\.memory|singleton.*memory|_instance.*memory)/gi;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const region = content.substring(Math.max(0, match.index - 300), Math.min(content.length, match.index + 300));
          if (!/session_id|conversation_id|user_id|per_user|per_session|isolat/i.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-MP-024-${findings.length}`, ruleId: 'AA-MP-024',
              title: 'Cross-conversation memory bleed',
              description: `Shared memory in ${file.relativePath} may leak data across conversations.`,
              severity: 'high', confidence: 'medium', domain: 'memory-context',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Isolate memory per conversation or session. Use conversation_id or session_id to scope memory access.',
              standards: { owaspAgentic: ['ASI06'], iso23894: ['R.2', 'R.5'], owaspAivss: ['AIVSS-DP'], a2asBasic: ['ISOL', 'AUDIT'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-MP-025',
    name: 'No memory quota per user',
    domain: 'memory-context',
    severity: 'medium',
    confidence: 'medium',
    description: 'No per-user memory quota or storage limits, allowing unbounded memory consumption.',
    frameworks: ['all'],
    owaspAgentic: ['ASI06'],
    standards: { owaspAgentic: ['ASI06'], iso23894: ['R.2', 'R.5'], owaspAivss: ['AIVSS-DP'], a2asBasic: ['ISOL', 'AUDIT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const memoryPattern = /(?:ConversationBufferMemory|ChatMessageHistory|InMemoryChatMessageHistory|Redis.*Memory|Postgres.*Memory)\s*\(/;
        if (!memoryPattern.test(content)) continue;
        const hasQuota = /quota|max_storage|storage_limit|max_messages|max_entries|per_user_limit|memory_limit|max_size/i.test(content);
        if (!hasQuota) {
          const match = content.match(memoryPattern);
          const line = match ? content.substring(0, match.index!).split('\n').length : 1;
          findings.push({
            id: `AA-MP-025-${findings.length}`, ruleId: 'AA-MP-025',
            title: 'No memory quota per user',
            description: `Memory store in ${file.relativePath} has no per-user quota or storage limit.`,
            severity: 'medium', confidence: 'medium', domain: 'memory-context',
            location: { file: file.relativePath, line, snippet: match ? match[0].substring(0, 60) : 'memory store' },
            remediation: 'Set per-user memory quotas (max_messages, max_storage) to prevent unbounded memory consumption.',
            standards: { owaspAgentic: ['ASI06'], iso23894: ['R.2', 'R.5'], owaspAivss: ['AIVSS-DP'], a2asBasic: ['ISOL', 'AUDIT'] },
          });
        }
      }
      return findings;
    },
  },
];
