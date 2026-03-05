import { describe, it, expect } from 'vitest';

// ─── AI Service Matching ────────────────────────────────────────────────────

describe('AI service matching', () => {
  it('matches ChatGPT URLs', async () => {
    const { matchAIService } = await import('../../src/endpoint/browser-scanner.js');
    expect(matchAIService('https://chat.openai.com/c/123')).toBe('chatgpt');
    expect(matchAIService('https://chatgpt.com/chat')).toBe('chatgpt');
  });

  it('matches Claude URLs', async () => {
    const { matchAIService } = await import('../../src/endpoint/browser-scanner.js');
    expect(matchAIService('https://claude.ai/chat/abc')).toBe('claude');
    expect(matchAIService('https://console.anthropic.com/dashboard')).toBe('claude');
  });

  it('matches Gemini URLs', async () => {
    const { matchAIService } = await import('../../src/endpoint/browser-scanner.js');
    expect(matchAIService('https://gemini.google.com/')).toBe('gemini');
    expect(matchAIService('https://aistudio.google.com/')).toBe('gemini');
  });

  it('matches Copilot URLs', async () => {
    const { matchAIService } = await import('../../src/endpoint/browser-scanner.js');
    expect(matchAIService('https://copilot.microsoft.com/')).toBe('copilot');
    expect(matchAIService('https://github.com/copilot')).toBe('copilot');
  });

  it('matches Perplexity URLs', async () => {
    const { matchAIService } = await import('../../src/endpoint/browser-scanner.js');
    expect(matchAIService('https://perplexity.ai/search')).toBe('perplexity');
  });

  it('matches DeepSeek URLs', async () => {
    const { matchAIService } = await import('../../src/endpoint/browser-scanner.js');
    expect(matchAIService('https://chat.deepseek.com/')).toBe('deepseek');
  });

  it('returns null for non-AI URLs', async () => {
    const { matchAIService } = await import('../../src/endpoint/browser-scanner.js');
    expect(matchAIService('https://google.com')).toBeNull();
    expect(matchAIService('https://github.com/repo')).toBeNull();
    expect(matchAIService('https://stackoverflow.com')).toBeNull();
  });
});

// ─── Service Patterns Coverage ──────────────────────────────────────────────

describe('AI service patterns', () => {
  it('covers at least 10 AI services', async () => {
    const { AI_SERVICE_PATTERNS } = await import('../../src/endpoint/browser-scanner.js');
    expect(AI_SERVICE_PATTERNS.length).toBeGreaterThanOrEqual(10);
  });

  it('each service has patterns and a name', async () => {
    const { AI_SERVICE_PATTERNS } = await import('../../src/endpoint/browser-scanner.js');
    for (const svc of AI_SERVICE_PATTERNS) {
      expect(svc.service).toBeTruthy();
      expect(svc.patterns.length).toBeGreaterThan(0);
      for (const p of svc.patterns) {
        expect(p).toBeInstanceOf(RegExp);
      }
    }
  });
});

// ─── Browser Definitions ────────────────────────────────────────────────────

describe('browser definitions', () => {
  it('covers major browsers', async () => {
    const { BROWSERS } = await import('../../src/endpoint/browser-scanner.js');
    const names = BROWSERS.map(b => b.name);
    expect(names).toContain('Chrome');
    expect(names).toContain('Arc');
    expect(names).toContain('Edge');
    expect(names).toContain('Firefox');
    expect(names).toContain('Brave');
  });

  it('has platform-specific paths', async () => {
    const { BROWSERS } = await import('../../src/endpoint/browser-scanner.js');
    for (const browser of BROWSERS) {
      expect(browser.paths).toHaveProperty('darwin');
      expect(browser.paths).toHaveProperty('linux');
      expect(browser.paths).toHaveProperty('win32');
    }
  });
});

// ─── Time Conversions ───────────────────────────────────────────────────────

describe('time conversions', () => {
  it('converts Chromium time to ISO', async () => {
    const { chromiumTimeToISO } = await import('../../src/endpoint/browser-scanner.js');
    // Chromium epoch: Jan 1, 1601
    // 13350000000000000 microseconds from Chromium epoch ≈ 2023
    const result = chromiumTimeToISO(13350000000000000);
    expect(result).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('converts Firefox time to ISO', async () => {
    const { firefoxTimeToISO } = await import('../../src/endpoint/browser-scanner.js');
    // Firefox uses microseconds since Unix epoch
    const result = firefoxTimeToISO(1700000000000000);
    expect(result).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });
});

// ─── Full Scan Shape ────────────────────────────────────────────────────────

describe('scanBrowserHistory', () => {
  it('returns valid BrowserScanResult shape', async () => {
    const { scanBrowserHistory } = await import('../../src/endpoint/browser-scanner.js');

    const result = scanBrowserHistory();

    expect(result).toHaveProperty('entries');
    expect(result).toHaveProperty('summary');
    expect(Array.isArray(result.entries)).toBe(true);
    expect(typeof result.summary.totalEntries).toBe('number');
    expect(Array.isArray(result.summary.browsers)).toBe(true);
    expect(typeof result.summary.services).toBe('object');
  });
});
