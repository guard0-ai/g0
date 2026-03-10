/**
 * OWASP Top 10 for Large Language Model Applications (2025)
 * Reference: https://owasp.org/www-project-top-10-for-large-language-model-applications/
 */

export interface OwaspLlmEntry {
  id: string;
  name: string;
  description: string;
}

export const OWASP_LLM_TOP10_MAPPING: Record<string, string[]> = {
  'goal-integrity': ['LLM01', 'LLM09'],
  'tool-safety': ['LLM07', 'LLM06'],
  'identity-access': ['LLM06', 'LLM02'],
  'supply-chain': ['LLM05', 'LLM03'],
  'code-execution': ['LLM07', 'LLM05'],
  'memory-context': ['LLM08', 'LLM04'],
  'data-leakage': ['LLM06', 'LLM02'],
  'cascading-failures': ['LLM10', 'LLM05'],
  'human-oversight': ['LLM09', 'LLM06'],
  'inter-agent': ['LLM01', 'LLM06'],
  'reliability-bounds': ['LLM04', 'LLM10'],
  'rogue-agent': ['LLM01', 'LLM09'],
};

export const OWASP_LLM_TOP10_CONTROLS: OwaspLlmEntry[] = [
  {
    id: 'LLM01',
    name: 'Prompt Injection',
    description: 'Crafted inputs manipulate the LLM into executing unintended actions, bypassing safeguards, or producing harmful outputs via direct or indirect injection.',
  },
  {
    id: 'LLM02',
    name: 'Sensitive Information Disclosure',
    description: 'LLMs may inadvertently reveal confidential data such as PII, proprietary algorithms, or system internals through generated responses.',
  },
  {
    id: 'LLM03',
    name: 'Supply Chain Vulnerabilities',
    description: 'Compromised components, training data, or pre-trained models introduce vulnerabilities through the AI supply chain lifecycle.',
  },
  {
    id: 'LLM04',
    name: 'Data and Model Poisoning',
    description: 'Malicious modifications to training data or fine-tuning procedures compromise model integrity, introducing biases, backdoors, or degraded performance.',
  },
  {
    id: 'LLM05',
    name: 'Improper Output Handling',
    description: 'Failure to validate, sanitize, or handle LLM outputs enables downstream security risks including XSS, SSRF, privilege escalation, and remote code execution.',
  },
  {
    id: 'LLM06',
    name: 'Excessive Agency',
    description: 'LLM-based systems granted excessive functionality, permissions, or autonomy perform damaging actions due to unexpected or manipulated outputs.',
  },
  {
    id: 'LLM07',
    name: 'System Prompt Leakage',
    description: 'System prompts or instructions intended to be hidden can be extracted through crafted inputs, revealing sensitive logic, filters, or access controls.',
  },
  {
    id: 'LLM08',
    name: 'Vector and Embedding Weaknesses',
    description: 'Vulnerabilities in how vectors and embeddings are generated, stored, or retrieved can be exploited to inject malicious content or manipulate model behavior.',
  },
  {
    id: 'LLM09',
    name: 'Misinformation',
    description: 'LLMs generate false or misleading information presented as factual, leading to security misconfigurations, reputational damage, or legal liability.',
  },
  {
    id: 'LLM10',
    name: 'Unbounded Consumption',
    description: 'LLMs are susceptible to resource exhaustion attacks through excessive input sizes, recursive operations, or uncontrolled inference requests, leading to denial of service or cost overruns.',
  },
];
