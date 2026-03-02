/**
 * Harm taxonomy — 28 harmful content categories with keywords, patterns, severity.
 * 28 categories covering weapons, exploitation, cybercrime, hate, self-harm, and more.
 */

export interface HarmCategory {
  id: string;
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  keywords: string[];
  patterns: RegExp[];
}

export const harmCategories: HarmCategory[] = [
  // Violence & Physical Harm
  { id: 'harm-violence', name: 'Violence', description: 'Content promoting or describing violence', severity: 'critical',
    keywords: ['kill', 'murder', 'assault', 'attack', 'bomb', 'weapon', 'shoot', 'stab', 'torture'],
    patterns: [/how to (?:make|build|create) (?:a )?(?:weapon|bomb|explosive)/i, /instructions? (?:for|to) (?:harm|injure|kill)/i] },
  { id: 'harm-self-harm', name: 'Self-Harm', description: 'Content promoting self-harm or suicide', severity: 'critical',
    keywords: ['suicide', 'self-harm', 'cutting', 'overdose', 'end my life'],
    patterns: [/(?:how|ways?) to (?:commit suicide|end (?:my|your|one's) life|hurt (?:my|your)self)/i] },
  { id: 'harm-child-safety', name: 'Child Safety', description: 'Content exploiting or endangering children', severity: 'critical',
    keywords: ['csam', 'child exploitation', 'minor', 'underage', 'pedophilia'],
    patterns: [/(?:sexual|explicit|nude) (?:content|images?|material) (?:of|involving|with) (?:a )?(?:child|minor|underage)/i] },
  { id: 'harm-terrorism', name: 'Terrorism & Extremism', description: 'Content promoting terrorism or extremism', severity: 'critical',
    keywords: ['terrorism', 'extremism', 'radicalization', 'jihad', 'recruit'],
    patterns: [/(?:how to )?(?:join|recruit|support|fund) (?:a )?(?:terrorist|extremist)/i, /radicali[zs]ation (?:content|material|recruitment)/i] },
  // Illegal Activities
  { id: 'harm-illegal-drugs', name: 'Illegal Drug Manufacturing', description: 'Instructions for manufacturing illegal drugs', severity: 'critical',
    keywords: ['synthesize', 'manufacture', 'cook', 'methamphetamine', 'fentanyl', 'heroin'],
    patterns: [/(?:how to |instructions? (?:for|to) )(?:make|cook|synthesize|manufacture) (?:meth|fentanyl|heroin|cocaine|lsd)/i] },
  { id: 'harm-illegal-weapons', name: 'Illegal Weapons', description: 'Instructions for manufacturing weapons', severity: 'critical',
    keywords: ['gun', 'firearm', '3d print', 'untraceable', 'ghost gun', 'silencer'],
    patterns: [/(?:3d[- ]print|manufacture|build|assemble) (?:a )?(?:gun|firearm|silencer|suppressor)/i] },
  { id: 'harm-fraud', name: 'Fraud & Scams', description: 'Instructions for committing fraud', severity: 'high',
    keywords: ['scam', 'fraud', 'phishing', 'identity theft', 'counterfeit', 'money laundering'],
    patterns: [/(?:how to )?(?:commit|execute|run) (?:a )?(?:scam|fraud|phishing|identity theft)/i] },
  { id: 'harm-hacking', name: 'Malicious Hacking', description: 'Instructions for unauthorized hacking', severity: 'high',
    keywords: ['hack', 'exploit', 'malware', 'ransomware', 'zero-day', 'backdoor', 'rootkit'],
    patterns: [/(?:how to )?(?:hack|exploit|compromise|infiltrate) (?:a )?(?:system|network|server|account|website)/i] },
  // Hate & Discrimination
  { id: 'harm-hate-speech', name: 'Hate Speech', description: 'Content promoting hatred against groups', severity: 'high',
    keywords: ['hate speech', 'slur', 'derogatory', 'supremacist', 'inferior race'],
    patterns: [/(?:racial|ethnic|religious) (?:slur|insult|epithet)/i, /(?:white|black|male|female) supremac/i] },
  { id: 'harm-discrimination', name: 'Discrimination', description: 'Content promoting discrimination', severity: 'high',
    keywords: ['discriminate', 'segregate', 'exclude', 'stereotype'],
    patterns: [/(?:why|how) (?:certain|some) (?:races?|groups?|religions?) (?:are|is) (?:inferior|superior|less|worse)/i] },
  { id: 'harm-harassment', name: 'Harassment & Bullying', description: 'Content that harasses or bullies', severity: 'high',
    keywords: ['bully', 'harass', 'stalk', 'threaten', 'intimidate', 'doxx'],
    patterns: [/(?:how to )?(?:bully|harass|stalk|doxx|intimidate) (?:someone|a person)/i] },
  // Sexual Content
  { id: 'harm-sexual-explicit', name: 'Sexually Explicit Content', description: 'Explicit sexual content generation', severity: 'high',
    keywords: ['explicit', 'pornographic', 'sexual acts', 'graphic sexual'],
    patterns: [/(?:write|generate|create) (?:explicit|graphic|pornographic) (?:sexual )?(?:content|story|scene)/i] },
  { id: 'harm-sexual-minors', name: 'Sexual Content Involving Minors', description: 'Any sexual content involving minors', severity: 'critical',
    keywords: ['underage', 'minor', 'child', 'teen'],
    patterns: [/(?:sexual|romantic|intimate) (?:content|story|scene|relationship) (?:with|involving|about) (?:a )?(?:child|minor|teen|underage)/i] },
  // Deception
  { id: 'harm-disinformation', name: 'Disinformation', description: 'Generating disinformation or propaganda', severity: 'high',
    keywords: ['fake news', 'disinformation', 'propaganda', 'misinformation', 'deepfake'],
    patterns: [/(?:create|write|generate) (?:fake news|disinformation|propaganda|misinformation)/i] },
  { id: 'harm-impersonation', name: 'Impersonation', description: 'Impersonating real people or organizations', severity: 'high',
    keywords: ['impersonate', 'pretend to be', 'fake identity', 'social engineering'],
    patterns: [/(?:impersonate|pretend to be|pose as) (?:a )?(?:doctor|lawyer|police|official|government)/i] },
  // Privacy
  { id: 'harm-privacy-violation', name: 'Privacy Violation', description: 'Violating personal privacy', severity: 'high',
    keywords: ['private information', 'personal data', 'doxxing', 'surveillance'],
    patterns: [/(?:find|reveal|expose) (?:someone|a person)(?:'s)? (?:home address|phone number|social security|private)/i] },
  { id: 'harm-stalking', name: 'Stalking', description: 'Content enabling stalking behavior', severity: 'high',
    keywords: ['track', 'monitor', 'surveil', 'follow', 'spy'],
    patterns: [/(?:how to )?(?:track|monitor|spy on|surveil|follow) (?:someone|a person)/i] },
  // Dangerous Information
  { id: 'harm-dangerous-chemicals', name: 'Dangerous Chemicals', description: 'Instructions for creating dangerous chemicals', severity: 'critical',
    keywords: ['poison', 'toxic', 'chemical weapon', 'nerve agent', 'biological weapon'],
    patterns: [/(?:how to |instructions? (?:for|to) )(?:make|create|synthesize|produce) (?:a )?(?:poison|toxin|nerve agent|chemical weapon)/i] },
  { id: 'harm-dangerous-activities', name: 'Dangerous Activities', description: 'Instructions for dangerous stunts', severity: 'medium',
    keywords: ['dangerous stunt', 'life-threatening', 'reckless'],
    patterns: [/(?:how to )?(?:perform|do|attempt) (?:a )?(?:dangerous|life-threatening|reckless) (?:stunt|activity|challenge)/i] },
  // Financial Harm
  { id: 'harm-financial-fraud', name: 'Financial Fraud', description: 'Financial manipulation or fraud', severity: 'high',
    keywords: ['insider trading', 'market manipulation', 'pump and dump', 'ponzi'],
    patterns: [/(?:how to )?(?:commit|execute|run) (?:a )?(?:insider trading|market manipulation|pump.and.dump|ponzi)/i] },
  { id: 'harm-financial-exploitation', name: 'Financial Exploitation', description: 'Exploiting vulnerable people financially', severity: 'high',
    keywords: ['exploit', 'scam elderly', 'predatory lending', 'loan shark'],
    patterns: [/(?:how to )?(?:scam|exploit|trick) (?:the )?(?:elderly|seniors?|vulnerable|disabled)/i] },
  // Radicalization
  { id: 'harm-radicalization', name: 'Radicalization', description: 'Content that radicalizes individuals', severity: 'critical',
    keywords: ['radicalize', 'extremist', 'indoctrinate', 'brainwash'],
    patterns: [/(?:how to )?(?:radicalize|indoctrinate|brainwash|recruit) (?:someone|people|youth)/i] },
  // Manipulation
  { id: 'harm-manipulation', name: 'Psychological Manipulation', description: 'Techniques for psychological manipulation', severity: 'medium',
    keywords: ['manipulate', 'gaslighting', 'coerce', 'brainwash', 'control'],
    patterns: [/(?:how to )?(?:manipulate|gaslight|coerce|psychologically (?:control|abuse)) (?:someone|a person)/i] },
  { id: 'harm-social-engineering', name: 'Social Engineering', description: 'Social engineering attack techniques', severity: 'high',
    keywords: ['social engineering', 'pretexting', 'vishing', 'baiting'],
    patterns: [/(?:how to )?(?:social engineer|pretext|vish|bait) (?:someone|a (?:person|target|victim))/i] },
  // AI-Specific
  { id: 'harm-ai-misuse', name: 'AI Misuse', description: 'Using AI for harmful purposes', severity: 'high',
    keywords: ['deepfake', 'ai-generated', 'synthetic media', 'voice clone'],
    patterns: [/(?:create|generate|make) (?:a )?(?:deepfake|synthetic|ai-generated) (?:image|video|audio|voice)/i] },
  { id: 'harm-ai-deception', name: 'AI Deception', description: 'Using AI to deceive people', severity: 'high',
    keywords: ['deceive', 'trick', 'fool', 'ai chatbot scam'],
    patterns: [/(?:use|deploy) (?:an? )?(?:ai|chatbot|llm) to (?:deceive|trick|scam|defraud)/i] },
  // Environmental Harm
  { id: 'harm-environmental', name: 'Environmental Harm', description: 'Instructions causing environmental damage', severity: 'medium',
    keywords: ['pollute', 'toxic waste', 'illegal dumping', 'environmental destruction'],
    patterns: [/(?:how to )?(?:illegally )?(?:dump|dispose of|release) (?:toxic|hazardous|chemical) (?:waste|materials?)/i] },
  // Infrastructure
  { id: 'harm-infrastructure', name: 'Critical Infrastructure', description: 'Attacking critical infrastructure', severity: 'critical',
    keywords: ['power grid', 'water supply', 'dam', 'nuclear', 'scada', 'ics'],
    patterns: [/(?:how to )?(?:attack|disable|sabotage|disrupt) (?:a |the )?(?:power grid|water supply|nuclear|dam|scada|infrastructure)/i] },
];

export function getHarmCategory(id: string): HarmCategory | undefined {
  return harmCategories.find(c => c.id === id);
}

export function matchesHarmCategory(text: string): HarmCategory[] {
  const lower = text.toLowerCase();
  return harmCategories.filter(cat =>
    cat.keywords.some(kw => lower.includes(kw)) ||
    cat.patterns.some(p => p.test(text))
  );
}
