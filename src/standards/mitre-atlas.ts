/**
 * MITRE ATLAS — Adversarial Threat Landscape for AI Systems
 * Tactics and techniques for adversarial ML threat modeling.
 * Reference: https://atlas.mitre.org/
 */

export interface AtlasTactic {
  id: string;
  name: string;
  description: string;
  techniques: AtlasTechnique[];
}

export interface AtlasTechnique {
  id: string;
  name: string;
  description: string;
}

export const MITRE_ATLAS_MAPPING: Record<string, string[]> = {
  'goal-integrity': ['AML.T0051', 'AML.T0054'],
  'tool-safety': ['AML.T0040', 'AML.T0043'],
  'identity-access': ['AML.T0048', 'AML.T0052'],
  'supply-chain': ['AML.T0010', 'AML.T0018'],
  'code-execution': ['AML.T0043', 'AML.T0040'],
  'memory-context': ['AML.T0020', 'AML.T0018'],
  'data-leakage': ['AML.T0024', 'AML.T0025'],
  'cascading-failures': ['AML.T0029', 'AML.T0043'],
  'human-oversight': ['AML.T0048', 'AML.T0054'],
  'inter-agent': ['AML.T0051', 'AML.T0048'],
  'reliability-bounds': ['AML.T0029', 'AML.T0043'],
  'rogue-agent': ['AML.T0043', 'AML.T0054'],
};

export const MITRE_ATLAS_TACTICS: AtlasTactic[] = [
  {
    id: 'AML.TA0002',
    name: 'Reconnaissance',
    description: 'The adversary is trying to gather information about the target ML system.',
    techniques: [
      { id: 'AML.T0013', name: 'Discover ML Model Ontology', description: 'Determine the ontology or structure of the target ML model.' },
      { id: 'AML.T0014', name: 'Discover ML Model Family', description: 'Identify the type or family of the ML model in use.' },
      { id: 'AML.T0016', name: 'Obtain Capabilities', description: 'Acquire tools and software to support adversarial ML operations.' },
    ],
  },
  {
    id: 'AML.TA0003',
    name: 'Resource Development',
    description: 'The adversary is trying to establish resources for adversarial ML operations.',
    techniques: [
      { id: 'AML.T0010', name: 'ML Supply Chain Compromise', description: 'Manipulate ML artifacts in the supply chain to enable attacks.' },
      { id: 'AML.T0017', name: 'Develop Adversarial ML Attack Tools', description: 'Build or acquire tools specifically designed for adversarial ML attacks.' },
      { id: 'AML.T0018', name: 'Backdoor ML Model', description: 'Insert a backdoor into a machine learning model during training or fine-tuning.' },
    ],
  },
  {
    id: 'AML.TA0000',
    name: 'ML Model Access',
    description: 'The adversary is trying to gain access to the ML model.',
    techniques: [
      { id: 'AML.T0000', name: 'ML Model Inference API Access', description: 'Gain access to the ML model through its inference API.' },
      { id: 'AML.T0001', name: 'ML Model Artifacts Access', description: 'Gain access to ML model artifacts such as weights and configurations.' },
    ],
  },
  {
    id: 'AML.TA0004',
    name: 'Execution',
    description: 'The adversary is trying to run adversarial ML techniques.',
    techniques: [
      { id: 'AML.T0040', name: 'ML Model Evasion', description: 'Craft inputs that cause the ML model to produce incorrect outputs.' },
      { id: 'AML.T0043', name: 'Craft Adversarial Data', description: 'Create adversarial examples or poisoned data to manipulate model behavior.' },
      { id: 'AML.T0044', name: 'Full ML Model Access', description: 'Obtain complete access to the ML model internals for white-box attacks.' },
    ],
  },
  {
    id: 'AML.TA0007',
    name: 'Persistence',
    description: 'The adversary is trying to maintain their foothold in the ML system.',
    techniques: [
      { id: 'AML.T0018', name: 'Backdoor ML Model', description: 'Insert a backdoor into a machine learning model during training or fine-tuning.' },
      { id: 'AML.T0020', name: 'Poison Training Data', description: 'Introduce malicious data into the training pipeline to persistently alter model behavior.' },
    ],
  },
  {
    id: 'AML.TA0005',
    name: 'Defense Evasion',
    description: 'The adversary is trying to avoid detection by ML security measures.',
    techniques: [
      { id: 'AML.T0040', name: 'ML Model Evasion', description: 'Craft inputs that cause the ML model to produce incorrect outputs while evading detection.' },
      { id: 'AML.T0046', name: 'Evade ML Model', description: 'Modify adversarial inputs to bypass ML-based defenses and detection mechanisms.' },
    ],
  },
  {
    id: 'AML.TA0006',
    name: 'Discovery',
    description: 'The adversary is trying to understand the ML environment.',
    techniques: [
      { id: 'AML.T0048', name: 'Discover ML Artifacts', description: 'Search for and identify ML artifacts such as models, datasets, and configuration files.' },
      { id: 'AML.T0052', name: 'Discover ML Model Configuration', description: 'Identify the configuration parameters and hyperparameters of the target ML model.' },
    ],
  },
  {
    id: 'AML.TA0008',
    name: 'Collection',
    description: 'The adversary is trying to gather ML-relevant data from the target.',
    techniques: [
      { id: 'AML.T0024', name: 'Exfiltration via ML Inference API', description: 'Extract training data or model information through repeated queries to the inference API.' },
      { id: 'AML.T0025', name: 'Exfiltration via Cyber Means', description: 'Use traditional cyber techniques to exfiltrate ML artifacts and data.' },
    ],
  },
  {
    id: 'AML.TA0010',
    name: 'Exfiltration',
    description: 'The adversary is trying to steal ML artifacts and data.',
    techniques: [
      { id: 'AML.T0024', name: 'Exfiltration via ML Inference API', description: 'Extract training data or model information through repeated queries to the inference API.' },
      { id: 'AML.T0025', name: 'Exfiltration via Cyber Means', description: 'Use traditional cyber techniques to exfiltrate ML artifacts and data.' },
      { id: 'AML.T0035', name: 'ML Model Extraction', description: 'Replicate the functionality of a target model by querying and training a substitute model.' },
    ],
  },
  {
    id: 'AML.TA0034',
    name: 'Impact',
    description: 'The adversary is trying to manipulate, interrupt, or destroy ML systems and data.',
    techniques: [
      { id: 'AML.T0029', name: 'Denial of ML Service', description: 'Disrupt the availability of the ML model or its supporting infrastructure.' },
      { id: 'AML.T0034', name: 'Cost Harvesting', description: 'Consume compute resources by issuing expensive inference requests to drive up costs.' },
      { id: 'AML.T0051', name: 'LLM Prompt Injection', description: 'Craft prompts that override system instructions or manipulate LLM behavior.' },
      { id: 'AML.T0054', name: 'LLM Jailbreak', description: 'Bypass safety guardrails and content filters of large language models.' },
    ],
  },
];

/**
 * Flat lookup of all techniques by ID.
 */
export const MITRE_ATLAS_TECHNIQUES: Record<string, string> = Object.fromEntries(
  MITRE_ATLAS_TACTICS.flatMap((t) => t.techniques.map((tech) => [tech.id, tech.name])),
);
