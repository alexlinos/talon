import { readEnvFile } from '../env.js';
import { logger } from '../logger.js';
import { registerChannel, ChannelOpts } from './registry.js';
import { Channel } from '../types.js';

// JID used by the webhook channel — tasks that want their output POSTed
// to the webhook should use this as their chat_jid.
export const WEBHOOK_JID = 'webhook:copilot';

export class WebhookChannel implements Channel {
  name = 'webhook';

  private url: string | null;
  private secret: string | null;
  private opts: ChannelOpts;
  private connected = false;

  constructor(opts: ChannelOpts) {
    this.opts = opts;
    const env = readEnvFile(['WEBHOOK_URL', 'WEBHOOK_SECRET']);
    this.url = process.env.WEBHOOK_URL || env.WEBHOOK_URL || null;
    this.secret = process.env.WEBHOOK_SECRET || env.WEBHOOK_SECRET || null;
  }

  async connect(): Promise<void> {
    if (!this.url) {
      logger.debug('Webhook channel: WEBHOOK_URL not set, skipping');
      return;
    }

    // No registerGroup here. The http channel registers the copilot group,
    // with its MCP mounts, under this JID too. A second, mount-less
    // registration for the same folder could win the scheduler's
    // find-by-folder lookup and start task containers without /workspace/extra.

    this.opts.onChatMetadata(
      WEBHOOK_JID,
      new Date().toISOString(),
      'CoPilot Webhook',
      'webhook',
      false,
    );

    this.connected = true;
    logger.info({ url: this.url }, 'Webhook channel connected');
  }

  async sendMessage(_jid: string, text: string): Promise<void> {
    if (!this.url) {
      logger.warn(
        'Webhook channel: sendMessage called but WEBHOOK_URL is not set',
      );
      return;
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (this.secret) {
      headers['Authorization'] = `Bearer ${this.secret}`;
      // copilot-mailrelay (the webhook -> email relay on the SOC host)
      // authenticates with this header instead of Authorization.
      headers['X-Relay-Token'] = this.secret;
    }

    // The relay builds the email subject from alert_name and severity. Reports
    // open with a title line (e.g. "Daily Threat Hunt — <date>"), so use it.
    const title =
      text.split('\n').find((line) => line.trim()) ?? 'Talon report';
    const body = JSON.stringify({
      text,
      alert_name: title.trim().slice(0, 150),
      severity: 'Report',
      timestamp: new Date().toISOString(),
    });

    try {
      const res = await fetch(this.url, { method: 'POST', headers, body });
      if (!res.ok) {
        logger.warn(
          { status: res.status, url: this.url },
          'Webhook channel: POST returned non-2xx',
        );
      } else {
        logger.info(
          { url: this.url, length: text.length },
          'Webhook channel: message delivered',
        );
      }
    } catch (err) {
      logger.error({ err, url: this.url }, 'Webhook channel: POST failed');
    }
  }

  isConnected(): boolean {
    return this.connected;
  }

  ownsJid(jid: string): boolean {
    return jid === WEBHOOK_JID;
  }

  async disconnect(): Promise<void> {
    this.connected = false;
  }
}

registerChannel('webhook', (opts: ChannelOpts) => {
  return new WebhookChannel(opts);
});
