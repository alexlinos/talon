import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('../env.js', () => ({
  readEnvFile: () => ({
    WEBHOOK_URL: 'http://172.18.0.1:8025/copilot',
    WEBHOOK_SECRET: 'relay-token',
  }),
}));
vi.mock('../logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import { WebhookChannel } from './webhook.js';

describe('WebhookChannel', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('speaks the copilot-mailrelay contract', async () => {
    // The relay 401s without X-Relay-Token, and builds the email subject
    // from alert_name + severity.
    const fetchMock = vi.fn(async () => new Response('250 accepted'));
    vi.stubGlobal('fetch', fetchMock);

    const channel = new WebhookChannel({} as any);
    await channel.sendMessage(
      'webhook:copilot',
      '\nDaily Threat Hunt — 2026-09-25\nScope: tnh',
    );

    const [url, init] = fetchMock.mock.calls[0] as unknown as [
      string,
      RequestInit,
    ];
    const headers = init.headers as Record<string, string>;
    const body = JSON.parse(init.body as string);

    expect(url).toBe('http://172.18.0.1:8025/copilot');
    expect(headers['X-Relay-Token']).toBe('relay-token');
    expect(body.alert_name).toBe('Daily Threat Hunt — 2026-09-25');
    expect(body.severity).toBe('Report');
    expect(body.text).toContain('Scope: tnh');
  });
});
