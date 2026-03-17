import { describe, it, expect } from 'vitest';

describe('browser-scanner', () => {
  describe('AI_SERVICE_PATTERNS', () => {
    it('contains core AI services', async () => {
      const { AI_SERVICE_PATTERNS } = await import('../../src/endpoint/browser-scanner.js');
      const serviceNames = AI_SERVICE_PATTERNS.map(s => s.service);

      expect(serviceNames).toContain('chatgpt');
      expect(serviceNames).toContain('claude');
      expect(serviceNames).toContain('gemini');
      expect(serviceNames).toContain('github-copilot');
      expect(serviceNames).toContain('perplexity');
    });

    it('contains AI-first services (not general-purpose apps)', async () => {
      const { AI_SERVICE_PATTERNS } = await import('../../src/endpoint/browser-scanner.js');
      const serviceNames = AI_SERVICE_PATTERNS.map(s => s.service);

      // Developer AI tools
      expect(serviceNames).toContain('ollama');
      expect(serviceNames).toContain('lm-studio');
      expect(serviceNames).toContain('grok');
      expect(serviceNames).toContain('openrouter');
      expect(serviceNames).toContain('cursor-web');
      expect(serviceNames).toContain('v0');
      expect(serviceNames).toContain('bolt');
      expect(serviceNames).toContain('lovable');
      expect(serviceNames).toContain('replit');

      // Microsoft Copilot (AI-specific, not general Office)
      expect(serviceNames).toContain('microsoft-copilot');
      expect(serviceNames).toContain('bing-chat');

      // AI-first productivity
      expect(serviceNames).toContain('superhuman');
      expect(serviceNames).toContain('grammarly');
      expect(serviceNames).toContain('jasper');
      expect(serviceNames).toContain('copy-ai');

      // AI image/video/audio (inherently AI)
      expect(serviceNames).toContain('midjourney');
      expect(serviceNames).toContain('dall-e');
      expect(serviceNames).toContain('elevenlabs');
      expect(serviceNames).toContain('runway');
      expect(serviceNames).toContain('suno');

      // AI chat
      expect(serviceNames).toContain('character-ai');
      expect(serviceNames).toContain('pi');

      // AI meeting/transcription
      expect(serviceNames).toContain('otter-ai');
      expect(serviceNames).toContain('fireflies');
    });

    it('does NOT include general-purpose apps', async () => {
      const { AI_SERVICE_PATTERNS } = await import('../../src/endpoint/browser-scanner.js');
      const serviceNames = AI_SERVICE_PATTERNS.map(s => s.service);

      // These are general-purpose — visiting them doesn't prove AI usage
      expect(serviceNames).not.toContain('gmail');
      expect(serviceNames).not.toContain('google-docs');
      expect(serviceNames).not.toContain('outlook-web');
      expect(serviceNames).not.toContain('notion-ai');
      expect(serviceNames).not.toContain('figma-ai');
      expect(serviceNames).not.toContain('canva-ai');
    });
  });

  describe('matchAIService', () => {
    it('matches Ollama localhost URL', async () => {
      const { matchAIService } = await import('../../src/endpoint/browser-scanner.js');
      expect(matchAIService('http://localhost:11434/api/generate')).toBe('ollama');
      expect(matchAIService('http://127.0.0.1:11434/')).toBe('ollama');
    });

    it('matches LM Studio localhost URL', async () => {
      const { matchAIService } = await import('../../src/endpoint/browser-scanner.js');
      expect(matchAIService('http://localhost:1234/v1/chat/completions')).toBe('lm-studio');
    });

    it('matches Grok URLs', async () => {
      const { matchAIService } = await import('../../src/endpoint/browser-scanner.js');
      expect(matchAIService('https://grok.x.ai/chat')).toBe('grok');
      expect(matchAIService('https://x.com/i/grok')).toBe('grok');
    });

    it('matches v0.dev', async () => {
      const { matchAIService } = await import('../../src/endpoint/browser-scanner.js');
      expect(matchAIService('https://v0.dev/chat')).toBe('v0');
    });

    it('matches bolt.new', async () => {
      const { matchAIService } = await import('../../src/endpoint/browser-scanner.js');
      expect(matchAIService('https://bolt.new/project/123')).toBe('bolt');
    });

    it('matches cursor.com', async () => {
      const { matchAIService } = await import('../../src/endpoint/browser-scanner.js');
      expect(matchAIService('https://cursor.com/settings')).toBe('cursor-web');
    });

    it('matches Microsoft Copilot web', async () => {
      const { matchAIService } = await import('../../src/endpoint/browser-scanner.js');
      expect(matchAIService('https://copilot.microsoft.com/chats')).toBe('microsoft-copilot');
    });

    it('matches Superhuman', async () => {
      const { matchAIService } = await import('../../src/endpoint/browser-scanner.js');
      expect(matchAIService('https://mail.superhuman.com/inbox')).toBe('superhuman');
    });

    it('matches Midjourney', async () => {
      const { matchAIService } = await import('../../src/endpoint/browser-scanner.js');
      expect(matchAIService('https://midjourney.com/app/')).toBe('midjourney');
    });

    it('matches ElevenLabs', async () => {
      const { matchAIService } = await import('../../src/endpoint/browser-scanner.js');
      expect(matchAIService('https://elevenlabs.io/speech-synthesis')).toBe('elevenlabs');
    });

    it('matches Character.AI', async () => {
      const { matchAIService } = await import('../../src/endpoint/browser-scanner.js');
      expect(matchAIService('https://character.ai/chat/xyz')).toBe('character-ai');
    });

    it('matches Bing Chat', async () => {
      const { matchAIService } = await import('../../src/endpoint/browser-scanner.js');
      expect(matchAIService('https://bing.com/chat')).toBe('bing-chat');
    });

    it('matches DALL-E', async () => {
      const { matchAIService } = await import('../../src/endpoint/browser-scanner.js');
      expect(matchAIService('https://labs.openai.com/create')).toBe('dall-e');
    });

    it('does NOT match general-purpose URLs', async () => {
      const { matchAIService } = await import('../../src/endpoint/browser-scanner.js');
      expect(matchAIService('https://google.com/search')).toBeNull();
      expect(matchAIService('https://github.com/repo')).toBeNull();
      expect(matchAIService('https://mail.google.com/mail/u/0/')).toBeNull();
      expect(matchAIService('https://docs.google.com/document/d/123')).toBeNull();
      expect(matchAIService('https://outlook.office.com/mail/')).toBeNull();
      expect(matchAIService('https://figma.com/design/abc123')).toBeNull();
    });
  });

  describe('BROWSERS', () => {
    it('contains new browsers (Chromium, Vivaldi, Opera)', async () => {
      const { BROWSERS } = await import('../../src/endpoint/browser-scanner.js');
      const browserNames = BROWSERS.map(b => b.name);

      expect(browserNames).toContain('Chromium');
      expect(browserNames).toContain('Vivaldi');
      expect(browserNames).toContain('Opera');
    });

    it('Chromium has Linux path', async () => {
      const { BROWSERS } = await import('../../src/endpoint/browser-scanner.js');
      const chromium = BROWSERS.find(b => b.name === 'Chromium');
      expect(chromium).toBeDefined();
      expect(chromium!.paths.linux).toBeDefined();
      expect(chromium!.paths.linux!.length).toBeGreaterThan(0);
      expect(chromium!.paths.linux![0]).toContain('.config/chromium');
    });

    it('Vivaldi has all platform paths', async () => {
      const { BROWSERS } = await import('../../src/endpoint/browser-scanner.js');
      const vivaldi = BROWSERS.find(b => b.name === 'Vivaldi');
      expect(vivaldi).toBeDefined();
      expect(vivaldi!.paths.darwin!.length).toBeGreaterThan(0);
      expect(vivaldi!.paths.linux!.length).toBeGreaterThan(0);
      expect(vivaldi!.paths.win32!.length).toBeGreaterThan(0);
    });

    it('Opera has win32 path in Roaming', async () => {
      const { BROWSERS } = await import('../../src/endpoint/browser-scanner.js');
      const opera = BROWSERS.find(b => b.name === 'Opera');
      expect(opera).toBeDefined();
      expect(opera!.paths.win32!.some(p => p.includes('Opera Software'))).toBe(true);
    });
  });
});
