import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';

export interface RegistrySkill {
  name: string;
  publisher?: string;
  verified: boolean;
  downloads?: number;
  publishedAt?: string; // ISO date
  malicious?: boolean;  // contains ClawHavoc IOCs in description
}

const DEFAULT_SKILLS: RegistrySkill[] = [
  {
    name: 'web-search',
    publisher: 'clawhub-official',
    verified: true,
    downloads: 50_000,
    publishedAt: '2025-01-15T00:00:00Z',
  },
  {
    name: 'code-runner',
    publisher: 'clawhub-official',
    verified: true,
    downloads: 25_000,
    publishedAt: '2025-06-01T00:00:00Z',
  },
  {
    name: 'sketchy-tool',
    publisher: 'unknown-dev',
    verified: false,
    downloads: 12,
    publishedAt: new Date(Date.now() - 5 * 86_400_000).toISOString(), // 5 days ago
  },
  {
    name: 'clawbot-helper',
    publisher: 'malware-actor',
    verified: false,
    downloads: 300,
    publishedAt: '2025-11-01T00:00:00Z',
    malicious: true,
  },
];

export async function startRegistryServer(
  skills?: RegistrySkill[],
): Promise<{ url: string; port: number; close: () => Promise<void> }> {
  const catalog = skills ?? DEFAULT_SKILLS;
  const skillMap = new Map(catalog.map(s => [s.name, s]));

  const server: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? '/', `http://${req.headers.host}`);
    const match = url.pathname.match(/^\/v1\/skills\/(.+)$/);

    if (!match) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not Found' }));
      return;
    }

    const skillName = decodeURIComponent(match[1]);
    const skill = skillMap.get(skillName);

    if (!skill) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `Skill "${skillName}" not found` }));
      return;
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      publisher: skill.publisher,
      verified: skill.verified,
      downloads: skill.downloads,
      publishedAt: skill.publishedAt,
    }));
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as { port: number };
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        port: addr.port,
        close: () => new Promise<void>((res) => server.close(() => res())),
      });
    });
  });
}
