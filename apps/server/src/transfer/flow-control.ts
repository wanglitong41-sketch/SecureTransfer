import { setTimeout as sleep } from 'node:timers/promises';
import { CHUNK_BYTES } from '@securetransfer/protocol';
import type { TransferDirection } from '@securetransfer/protocol';

export interface TransferFlowControl {
  waitForBytes(
    userId: string,
    direction: TransferDirection,
    bytes: number,
    signal: AbortSignal,
  ): Promise<void>;
}
export const UNLIMITED_FLOW: TransferFlowControl = {
  async waitForBytes(_userId, _direction, _bytes, signal) {
    signal.throwIfAborted();
  },
};

export interface BandwidthPolicy {
  ordinary: number;
  vip: number;
  vipUserIds: readonly string[];
}
export function readBandwidthPolicy(value?: string): BandwidthPolicy {
  const defaults = { ordinary: 256 * 1024, vip: 1024 * 1024, vipUserIds: [] };
  if (!value) return defaults;
  const policy = { ...defaults, ...JSON.parse(value) } as BandwidthPolicy;
  if (
    ![policy.ordinary, policy.vip].every(
      (rate) => Number.isSafeInteger(rate) && rate >= CHUNK_BYTES && rate <= 64 * 1024 * 1024,
    ) ||
    !Array.isArray(policy.vipUserIds) ||
    !policy.vipUserIds.every((id) => typeof id === 'string' && /^[0-9a-f-]{36}$/i.test(id))
  ) {
    throw new Error('Invalid ST_BANDWIDTH_POLICY');
  }
  return policy;
}

interface Bucket {
  tokens: number;
  updatedAt: number;
  waiting: number;
}
export class UserBandwidth implements TransferFlowControl {
  private readonly buckets = new Map<string, Bucket>();
  private readonly vip: Set<string>;
  private lastSweep = 0;
  constructor(private readonly policy: BandwidthPolicy) {
    this.vip = new Set(policy.vipUserIds.map((id) => id.toLowerCase()));
  }
  async waitForBytes(
    userId: string,
    direction: TransferDirection,
    bytes: number,
    signal: AbortSignal,
  ) {
    signal.throwIfAborted();
    if (!Number.isInteger(bytes) || bytes < 0 || bytes > CHUNK_BYTES)
      throw new Error('Invalid byte count');
    const rate = this.vip.has(userId.toLowerCase()) ? this.policy.vip : this.policy.ordinary;
    const key = userId + ':' + direction;
    const timestamp = performance.now();
    if (timestamp - this.lastSweep >= 60000) {
      for (const [id, bucket] of this.buckets) {
        if (!bucket.waiting && timestamp - bucket.updatedAt >= 60000) this.buckets.delete(id);
      }
      this.lastSweep = timestamp;
    }
    const bucket = this.buckets.get(key) ?? {
      tokens: CHUNK_BYTES,
      updatedAt: timestamp,
      waiting: 0,
    };
    this.buckets.set(key, bucket);
    bucket.waiting++;
    try {
      for (;;) {
        signal.throwIfAborted();
        const now = performance.now();
        bucket.tokens = Math.min(
          CHUNK_BYTES,
          bucket.tokens + ((now - bucket.updatedAt) * rate) / 1000,
        );
        bucket.updatedAt = now;
        if (bucket.tokens >= bytes) {
          bucket.tokens -= bytes;
          return;
        }
        await sleep(Math.max(1, Math.ceil(((bytes - bucket.tokens) * 1000) / rate)), undefined, {
          signal,
        });
      }
    } finally {
      bucket.waiting--;
    }
  }
}
