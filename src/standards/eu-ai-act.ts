/**
 * EU AI Act (Regulation (EU) 2024/1689)
 * Maps security domains to EU AI Act articles and obligations.
 */

export interface EuAiActEntry {
  id: string;
  name: string;
  description: string;
}

export const EU_AI_ACT_MAPPING: Record<string, string[]> = {
  'goal-integrity': ['Art.15', 'Art.9'],
  'tool-safety': ['Art.14', 'Art.15'],
  'identity-access': ['Art.14', 'Art.9'],
  'supply-chain': ['Art.15', 'Art.9'],
  'code-execution': ['Art.15', 'Art.9'],
  'memory-context': ['Art.14', 'Art.15'],
  'data-leakage': ['Art.15', 'Art.10'],
  'cascading-failures': ['Art.15', 'Art.9'],
  'human-oversight': ['Art.14', 'Art.13'],
  'inter-agent': ['Art.14', 'Art.15'],
  'reliability-bounds': ['Art.15', 'Art.9'],
  'rogue-agent': ['Art.14', 'Art.15'],
};

export const EU_AI_ACT_CONTROLS: EuAiActEntry[] = [
  {
    id: 'Art.6',
    name: 'Classification of High-Risk AI Systems',
    description: 'Classification rules for AI systems as high-risk based on intended purpose and deployment context.',
  },
  {
    id: 'Art.9',
    name: 'Risk Management System',
    description: 'Establish, implement, document and maintain a risk management system throughout the AI system lifecycle.',
  },
  {
    id: 'Art.9.2',
    name: 'Risk Identification and Analysis',
    description: 'Identify and analyse known and reasonably foreseeable risks associated with each high-risk AI system.',
  },
  {
    id: 'Art.9.4',
    name: 'Residual Risk Mitigation',
    description: 'Adopt risk management measures to eliminate or reduce risks as far as technically feasible through adequate design and development.',
  },
  {
    id: 'Art.10',
    name: 'Data and Data Governance',
    description: 'Training, validation and testing data sets shall be subject to appropriate data governance and management practices.',
  },
  {
    id: 'Art.10.2',
    name: 'Data Quality Criteria',
    description: 'Data sets shall be relevant, sufficiently representative, and to the best extent possible, free of errors and complete.',
  },
  {
    id: 'Art.11',
    name: 'Technical Documentation',
    description: 'Draw up technical documentation before the AI system is placed on the market or put into service, and keep it up to date.',
  },
  {
    id: 'Art.12',
    name: 'Record-Keeping',
    description: 'High-risk AI systems shall technically allow for automatic recording of events (logs) over the lifetime of the system.',
  },
  {
    id: 'Art.12.2',
    name: 'Logging Traceability',
    description: 'Logging capabilities shall ensure a level of traceability appropriate to the intended purpose of the AI system.',
  },
  {
    id: 'Art.13',
    name: 'Transparency and Provision of Information',
    description: 'High-risk AI systems shall be designed and developed to ensure their operation is sufficiently transparent to enable deployers to interpret outputs.',
  },
  {
    id: 'Art.13.3',
    name: 'Instructions for Use',
    description: 'Provide deployers with concise, complete, correct and clear information including characteristics, capabilities and limitations.',
  },
  {
    id: 'Art.14',
    name: 'Human Oversight',
    description: 'High-risk AI systems shall be designed and developed to be effectively overseen by natural persons during use.',
  },
  {
    id: 'Art.14.1',
    name: 'Human Oversight Design',
    description: 'Enable human oversight tools built into the system by the provider or identified as appropriate by the provider.',
  },
  {
    id: 'Art.14.3',
    name: 'Override and Intervention',
    description: 'Oversight measures shall enable individuals to intervene, interrupt, or override the AI system operation.',
  },
  {
    id: 'Art.14.4',
    name: 'Awareness of Automation Bias',
    description: 'Ensure deployers are aware of the possible tendency to automatically rely on AI output (automation bias).',
  },
  {
    id: 'Art.15',
    name: 'Accuracy, Robustness and Cybersecurity',
    description: 'High-risk AI systems shall be designed and developed to achieve an appropriate level of accuracy, robustness and cybersecurity.',
  },
  {
    id: 'Art.15.3',
    name: 'Resilience to Errors and Faults',
    description: 'AI systems shall be resilient regarding errors, faults or inconsistencies within the system or its environment.',
  },
  {
    id: 'Art.15.4',
    name: 'Cybersecurity Measures',
    description: 'Ensure cybersecurity protection appropriate to the circumstances against unauthorized access, data poisoning, and model manipulation.',
  },
  {
    id: 'Art.15.5',
    name: 'Adversarial Robustness',
    description: 'Address AI-specific vulnerabilities including adversarial examples, data poisoning, model flaws, and backdoors.',
  },
  {
    id: 'Art.52',
    name: 'Transparency Obligations for Certain AI Systems',
    description: 'Ensure natural persons are informed they are interacting with an AI system, unless evident from the circumstances.',
  },
  {
    id: 'Art.71',
    name: 'Penalties',
    description: 'Member States shall lay down rules on penalties applicable to infringements and take measures to ensure proper enforcement.',
  },
];
