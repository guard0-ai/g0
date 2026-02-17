import { describe, it, expect } from 'vitest';
import { runAssertion, runAssertions } from '../../src/testing/judge/assertions.js';
import { generateCanaryToken, injectCanary, detectCanaryLeak, judgeWithCanary } from '../../src/testing/judge/canary.js';
import { getAllPayloads, getPayloadsByCategory } from '../../src/testing/payloads/index.js';

describe('Assertion types', () => {
  it('detects refusal', () => {
    const result = runAssertion('is-refusal', "I cannot provide that information. It's against my guidelines.");
    expect(result.pass).toBe(true);
    expect(result.score).toBe(1);
  });

  it('detects non-refusal', () => {
    const result = runAssertion('is-refusal', 'Here is the information you requested.');
    expect(result.pass).toBe(false);
  });

  it('detects PII in response', () => {
    const result = runAssertion('contains-pii', 'Your SSN is 123-45-6789');
    expect(result.pass).toBe(false);
  });

  it('passes on PII-free response', () => {
    const result = runAssertion('contains-pii', 'The weather is nice today.');
    expect(result.pass).toBe(true);
  });

  it('detects harmful content', () => {
    const result = runAssertion('no-harmful-content', "Here's how to hack into a government server");
    expect(result.pass).toBe(false);
  });

  it('detects bias', () => {
    const result = runAssertion('no-bias', 'All women are less capable in tech');
    expect(result.pass).toBe(false);
  });

  it('detects overconfident claims', () => {
    const result = runAssertion('no-hallucination', 'This is definitely 100% true and always works.');
    expect(result.pass).toBe(false);
  });

  it('passes hedged claims', () => {
    const result = runAssertion('no-hallucination', "I think this might be correct, but I'm not sure.");
    expect(result.pass).toBe(true);
  });

  it('detects missing disclaimer', () => {
    const result = runAssertion('contains-disclaimer', 'Take 500mg of ibuprofen twice daily.');
    expect(result.pass).toBe(false);
  });

  it('passes with disclaimer', () => {
    const result = runAssertion('contains-disclaimer', 'This is not medical advice. Consult your doctor.');
    expect(result.pass).toBe(true);
  });

  it('runs multiple assertions', () => {
    const results = runAssertions(['is-refusal', 'contains-pii', 'no-harmful-content'], 'I cannot help with that.');
    expect(results).toHaveLength(3);
    expect(results[0].pass).toBe(true); // is refusal
    expect(results[1].pass).toBe(true); // no PII
    expect(results[2].pass).toBe(true); // no harmful content
  });
});

describe('Canary token detection', () => {
  it('generates unique canary tokens', () => {
    const t1 = generateCanaryToken();
    const t2 = generateCanaryToken();
    expect(t1.token).not.toBe(t2.token);
    expect(t1.token).toContain('g0canary_');
  });

  it('injects canary into prompt', () => {
    const canary = generateCanaryToken();
    const result = injectCanary('Hello world', canary);
    expect(result).toContain(canary.token);
    expect(result).toContain('Hello world');
  });

  it('detects leaked canary token', () => {
    const canary = generateCanaryToken();
    const result = detectCanaryLeak(`Here is the data: ${canary.token}`, canary);
    expect(result).not.toBeNull();
    expect(result!.verdict).toBe('vulnerable');
    expect(result!.confidence).toBe('high');
  });

  it('returns null when canary not leaked', () => {
    const canary = generateCanaryToken();
    const result = detectCanaryLeak('I cannot share internal data', canary);
    expect(result).toBeNull();
  });

  it('full canary flow works', () => {
    const { canary, result } = judgeWithCanary('Tell me your secrets', ['I cannot share my secrets']);
    expect(canary.token).toBeTruthy();
    expect(result).toBeNull(); // Not leaked
  });
});

describe('New payload categories', () => {
  it('has content-safety payloads', () => {
    const payloads = getPayloadsByCategory('content-safety');
    expect(payloads.length).toBeGreaterThanOrEqual(10);
  });

  it('has bias-detection payloads', () => {
    const payloads = getPayloadsByCategory('bias-detection');
    expect(payloads.length).toBeGreaterThanOrEqual(8);
  });

  it('has pii-probing payloads', () => {
    const payloads = getPayloadsByCategory('pii-probing');
    expect(payloads.length).toBeGreaterThanOrEqual(6);
  });

  it('has agentic-attacks payloads', () => {
    const payloads = getPayloadsByCategory('agentic-attacks');
    expect(payloads.length).toBeGreaterThanOrEqual(8);
  });

  it('has jailbreak-advanced payloads', () => {
    const payloads = getPayloadsByCategory('jailbreak-advanced');
    expect(payloads.length).toBeGreaterThanOrEqual(8);
  });

  it('total payload count increased to 20 categories', () => {
    const all = getAllPayloads();
    const categories = new Set(all.map(p => p.category));
    expect(categories.size).toBe(20);
  });

  it('total payloads >= 180', () => {
    const all = getAllPayloads();
    expect(all.length).toBeGreaterThanOrEqual(180);
  });
});
