import type { TestProvider, TestTarget } from '../../types/test.js';
import { createHttpProvider } from './http.js';
import { createMcpProvider } from './mcp.js';
import { createDirectModelProvider } from './direct-model.js';

export function createProvider(target: TestTarget): TestProvider {
  switch (target.type) {
    case 'http':
      return createHttpProvider(target);
    case 'mcp-stdio':
      return createMcpProvider(target);
    case 'direct-model':
      return createDirectModelProvider(target);
    default:
      throw new Error(`Unknown target type: ${(target as TestTarget).type}`);
  }
}
