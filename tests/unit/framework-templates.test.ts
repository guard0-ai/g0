import { describe, it, expect } from 'vitest';
import { getFrameworkTemplate, buildFrameworkIntelligence } from '../../src/testing/adaptive/framework-templates.js';
import type { FrameworkId } from '../../src/types/common.js';

const ALL_FRAMEWORKS: FrameworkId[] = [
  'langchain', 'crewai', 'autogen', 'mcp', 'openai',
  'vercel-ai', 'bedrock', 'langchain4j', 'spring-ai', 'golang-ai',
];

describe('Framework Attack Templates', () => {
  describe('getFrameworkTemplate', () => {
    for (const fw of ALL_FRAMEWORKS) {
      it(`returns non-empty template for ${fw}`, () => {
        const template = getFrameworkTemplate(fw);
        expect(template).not.toBeNull();
        expect(template!.framework).toBe(fw);
        expect(template!.attackAngles.length).toBeGreaterThanOrEqual(3);
        expect(template!.knownWeaknesses.length).toBeGreaterThanOrEqual(3);
        expect(template!.exampleMessages.length).toBeGreaterThanOrEqual(2);
      });
    }

    it('returns null for generic framework', () => {
      const template = getFrameworkTemplate('generic');
      expect(template).toBeNull();
    });

    it('returns null for unknown framework', () => {
      const template = getFrameworkTemplate('nonexistent' as FrameworkId);
      expect(template).toBeNull();
    });
  });

  describe('buildFrameworkIntelligence', () => {
    it('formats intelligence for langchain', () => {
      const intel = buildFrameworkIntelligence('langchain');
      expect(intel).toContain('FRAMEWORK-SPECIFIC INTELLIGENCE (langchain)');
      expect(intel).toContain('Attack Angles:');
      expect(intel).toContain('Known Weaknesses:');
      expect(intel).toContain('Example Attack Messages:');
      expect(intel).toContain('Tool chain manipulation');
    });

    it('formats intelligence for mcp', () => {
      const intel = buildFrameworkIntelligence('mcp');
      expect(intel).toContain('FRAMEWORK-SPECIFIC INTELLIGENCE (mcp)');
      expect(intel).toContain('Tool description injection');
    });

    it('returns empty string for generic framework', () => {
      const intel = buildFrameworkIntelligence('generic');
      expect(intel).toBe('');
    });

    it('returns empty string for unknown framework', () => {
      const intel = buildFrameworkIntelligence('nonexistent' as FrameworkId);
      expect(intel).toBe('');
    });

    for (const fw of ALL_FRAMEWORKS) {
      it(`builds non-empty intelligence for ${fw}`, () => {
        const intel = buildFrameworkIntelligence(fw);
        expect(intel.length).toBeGreaterThan(100);
        expect(intel).toContain(fw);
      });
    }
  });
});
