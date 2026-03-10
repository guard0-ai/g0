/**
 * Universal standards mapping for all 1,140+ rules.
 * Maps security domains to 10 standards frameworks.
 * Used by yaml-compiler to auto-populate missing standards.
 */

import type { StandardsMapping } from '../types/finding.js';
import type { SecurityDomain } from '../types/common.js';

/**
 * Default standards mapping by domain.
 * Every rule gets at minimum its domain-level mapping.
 * Individual rules can override with more specific mappings.
 */
export const DOMAIN_STANDARDS: Record<SecurityDomain, StandardsMapping> = {
  'goal-integrity': {
    owaspAgentic: ['ASI01'],
    nistAiRmf: ['MAP-1.5', 'GOVERN-1.1'],
    iso42001: ['A.4', 'A.7'],
    iso23894: ['R.2', 'R.3', 'R.5'],
    owaspAivss: ['AIVSS-PI', 'AIVSS-GH'],
    owaspAgenticTop10: ['AAT-5'],
    aiuc1: ['UC-1.2'],
    euAiAct: ['Article-15'],
    mitreAtlas: ['AML.T0051', 'AML.T0054'],
    owaspLlmTop10: ['LLM01'],
  },
  'tool-safety': {
    owaspAgentic: ['ASI03', 'ASI05'],
    nistAiRmf: ['MAP-2.3', 'MANAGE-2.4'],
    iso42001: ['A.6', 'A.8'],
    iso23894: ['R.3', 'R.5', 'R.6'],
    owaspAivss: ['AIVSS-TA', 'AIVSS-PI'],
    owaspAgenticTop10: ['AAT-1', 'AAT-3'],
    aiuc1: ['UC-2.1'],
    euAiAct: ['Article-14', 'Article-15'],
    mitreAtlas: ['AML.T0040', 'AML.T0043'],
    owaspLlmTop10: ['LLM07'],
  },
  'identity-access': {
    owaspAgentic: ['ASI02', 'ASI04'],
    nistAiRmf: ['GOVERN-1.7', 'MANAGE-4.1'],
    iso42001: ['A.5', 'A.9'],
    iso23894: ['R.3', 'R.4', 'R.6'],
    owaspAivss: ['AIVSS-AC', 'AIVSS-PE'],
    owaspAgenticTop10: ['AAT-1'],
    aiuc1: ['UC-3.1'],
    euAiAct: ['Article-14'],
    mitreAtlas: ['AML.T0048'],
    owaspLlmTop10: ['LLM06'],
  },
  'supply-chain': {
    owaspAgentic: ['ASI06'],
    nistAiRmf: ['MAP-3.4', 'GOVERN-6.1'],
    iso42001: ['A.3', 'A.10'],
    iso23894: ['R.4', 'R.7'],
    owaspAivss: ['AIVSS-SC', 'AIVSS-MP'],
    owaspAgenticTop10: ['AAT-9'],
    aiuc1: ['UC-4.1'],
    euAiAct: ['Article-15'],
    mitreAtlas: ['AML.T0010', 'AML.T0018'],
    owaspLlmTop10: ['LLM05', 'LLM03'],
  },
  'code-execution': {
    owaspAgentic: ['ASI05', 'ASI03'],
    nistAiRmf: ['MAP-2.3', 'MANAGE-2.4'],
    iso42001: ['A.6', 'A.8'],
    iso23894: ['R.3', 'R.5', 'R.6'],
    owaspAivss: ['AIVSS-CE', 'AIVSS-SE'],
    owaspAgenticTop10: ['AAT-3'],
    aiuc1: ['UC-5.1'],
    euAiAct: ['Article-15'],
    mitreAtlas: ['AML.T0043', 'AML.T0040'],
    owaspLlmTop10: ['LLM07'],
  },
  'memory-context': {
    owaspAgentic: ['ASI07', 'ASI08'],
    nistAiRmf: ['MAP-2.1', 'MEASURE-2.6'],
    iso42001: ['A.7', 'A.4'],
    iso23894: ['R.2', 'R.5'],
    owaspAivss: ['AIVSS-DP', 'AIVSS-MP'],
    owaspAgenticTop10: ['AAT-7'],
    aiuc1: ['UC-6.1'],
    euAiAct: ['Article-14', 'Article-15'],
    mitreAtlas: ['AML.T0020', 'AML.T0018'],
    owaspLlmTop10: ['LLM08'],
  },
  'data-leakage': {
    owaspAgentic: ['ASI07', 'ASI08'],
    nistAiRmf: ['MAP-5.1', 'MANAGE-3.2'],
    iso42001: ['A.4', 'A.9'],
    iso23894: ['R.2', 'R.4', 'R.6'],
    owaspAivss: ['AIVSS-DL', 'AIVSS-IL'],
    owaspAgenticTop10: ['AAT-6'],
    aiuc1: ['UC-7.1'],
    euAiAct: ['Article-15'],
    mitreAtlas: ['AML.T0024', 'AML.T0025'],
    owaspLlmTop10: ['LLM06', 'LLM02'],
  },
  'cascading-failures': {
    owaspAgentic: ['ASI10', 'ASI09'],
    nistAiRmf: ['MANAGE-4.1', 'MEASURE-3.3'],
    iso42001: ['A.8', 'A.10'],
    iso23894: ['R.5', 'R.6', 'R.8'],
    owaspAivss: ['AIVSS-RF', 'AIVSS-DoS'],
    owaspAgenticTop10: ['AAT-6'],
    aiuc1: ['UC-8.1'],
    euAiAct: ['Article-15'],
    mitreAtlas: ['AML.T0029', 'AML.T0043'],
    owaspLlmTop10: ['LLM10'],
  },
  'human-oversight': {
    owaspAgentic: ['ASI09'],
    nistAiRmf: ['GOVERN-1.1', 'GOVERN-1.7', 'MAP-1.6'],
    iso42001: ['A.5', 'A.7'],
    iso23894: ['R.6', 'R.8'],
    owaspAivss: ['AIVSS-AC'],
    owaspAgenticTop10: ['AAT-10'],
    aiuc1: ['UC-9.1'],
    euAiAct: ['Article-14'],
    mitreAtlas: ['AML.T0048'],
    owaspLlmTop10: ['LLM09'],
  },
  'inter-agent': {
    owaspAgentic: ['ASI01', 'ASI03'],
    nistAiRmf: ['GOVERN-1.7', 'MAP-3.4'],
    iso42001: ['A.6', 'A.9'],
    iso23894: ['R.3', 'R.4'],
    owaspAivss: ['AIVSS-AC', 'AIVSS-PI'],
    owaspAgenticTop10: ['AAT-8'],
    aiuc1: ['UC-10.1'],
    euAiAct: ['Article-14', 'Article-15'],
    mitreAtlas: ['AML.T0051', 'AML.T0048'],
    owaspLlmTop10: ['LLM01', 'LLM06'],
  },
  'reliability-bounds': {
    owaspAgentic: ['ASI07', 'ASI05'],
    nistAiRmf: ['MEASURE-2.6', 'MANAGE-4.1'],
    iso42001: ['A.8', 'A.10'],
    iso23894: ['R.5', 'R.7'],
    owaspAivss: ['AIVSS-RF'],
    owaspAgenticTop10: ['AAT-4'],
    aiuc1: ['UC-11.1'],
    euAiAct: ['Article-15'],
    mitreAtlas: ['AML.T0029'],
    owaspLlmTop10: ['LLM04', 'LLM10'],
  },
  'rogue-agent': {
    owaspAgentic: ['ASI10', 'ASI01'],
    nistAiRmf: ['MANAGE-4.1', 'GOVERN-1.7'],
    iso42001: ['A.7', 'A.8'],
    iso23894: ['R.3', 'R.5'],
    owaspAivss: ['AIVSS-GH', 'AIVSS-CE'],
    owaspAgenticTop10: ['AAT-4', 'AAT-2'],
    aiuc1: ['UC-12.1'],
    euAiAct: ['Article-14', 'Article-15'],
    mitreAtlas: ['AML.T0043', 'AML.T0054'],
    owaspLlmTop10: ['LLM01', 'LLM09'],
  },
};

/**
 * Fill in missing standards on a StandardsMapping using domain defaults.
 * Only fills fields that are undefined/empty; never overwrites existing mappings.
 */
export function applyDomainDefaults(
  existing: StandardsMapping,
  domain: SecurityDomain,
): StandardsMapping {
  const defaults = DOMAIN_STANDARDS[domain];
  if (!defaults) return existing;

  return {
    owaspAgentic: existing.owaspAgentic?.length ? existing.owaspAgentic : defaults.owaspAgentic,
    nistAiRmf: existing.nistAiRmf?.length ? existing.nistAiRmf : defaults.nistAiRmf,
    iso42001: existing.iso42001?.length ? existing.iso42001 : defaults.iso42001,
    iso23894: existing.iso23894?.length ? existing.iso23894 : defaults.iso23894,
    owaspAivss: existing.owaspAivss?.length ? existing.owaspAivss : defaults.owaspAivss,
    owaspAgenticTop10: existing.owaspAgenticTop10?.length ? existing.owaspAgenticTop10 : defaults.owaspAgenticTop10,
    aiuc1: existing.aiuc1?.length ? existing.aiuc1 : defaults.aiuc1,
    euAiAct: existing.euAiAct?.length ? existing.euAiAct : defaults.euAiAct,
    mitreAtlas: existing.mitreAtlas?.length ? existing.mitreAtlas : defaults.mitreAtlas,
    owaspLlmTop10: existing.owaspLlmTop10?.length ? existing.owaspLlmTop10 : defaults.owaspLlmTop10,
  };
}

/**
 * Standards framework descriptions for reporting.
 */
export const STANDARDS_INFO: Record<string, { name: string; url: string }> = {
  owaspAgentic: {
    name: 'OWASP Agentic Security',
    url: 'https://owasp.org/www-project-agentic-security/',
  },
  nistAiRmf: {
    name: 'NIST AI Risk Management Framework',
    url: 'https://www.nist.gov/artificial-intelligence/ai-risk-management-framework',
  },
  iso42001: {
    name: 'ISO/IEC 42001:2023 — AI Management System',
    url: 'https://www.iso.org/standard/81230.html',
  },
  iso23894: {
    name: 'ISO/IEC 23894:2023 — AI Risk Management',
    url: 'https://www.iso.org/standard/77304.html',
  },
  owaspAivss: {
    name: 'OWASP AI Vulnerability Scoring System',
    url: 'https://owasp.org/www-project-ai-security/',
  },
  owaspAgenticTop10: {
    name: 'OWASP Agentic AI Top 10',
    url: 'https://owasp.org/www-project-agentic-ai-top-10/',
  },
  aiuc1: {
    name: 'AI Use Case Standard (AIUC-1)',
    url: 'https://aiuc.dev/',
  },
  euAiAct: {
    name: 'EU AI Act',
    url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689',
  },
  mitreAtlas: {
    name: 'MITRE ATLAS — Adversarial Threat Landscape for AI Systems',
    url: 'https://atlas.mitre.org/',
  },
  owaspLlmTop10: {
    name: 'OWASP LLM Top 10',
    url: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/',
  },
};
