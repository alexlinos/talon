import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { _initTestDatabase, createTask, getTaskById } from './db.js';
import {
  _resetSchedulerLoopForTests,
  computeNextRun,
  repairStrandedTasks,
  startSchedulerLoop,
} from './task-scheduler.js';

describe('task scheduler', () => {
  beforeEach(() => {
    _initTestDatabase();
    _resetSchedulerLoopForTests();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('pauses due tasks with invalid group folders to prevent retry churn', async () => {
    createTask({
      id: 'task-invalid-folder',
      group_folder: '../../outside',
      chat_jid: 'bad@g.us',
      prompt: 'run',
      schedule_type: 'once',
      schedule_value: '2026-02-22T00:00:00.000Z',
      context_mode: 'isolated',
      next_run: new Date(Date.now() - 60_000).toISOString(),
      status: 'active',
      created_at: '2026-02-22T00:00:00.000Z',
    });

    const enqueueTask = vi.fn(
      (_groupJid: string, _taskId: string, fn: () => Promise<void>) => {
        void fn();
      },
    );

    startSchedulerLoop({
      registeredGroups: () => ({}),
      getSessions: () => ({}),
      queue: { enqueueTask } as any,
      onProcess: () => {},
      sendMessage: async () => {},
    });

    await vi.advanceTimersByTimeAsync(10);

    const task = getTaskById('task-invalid-folder');
    expect(task?.status).toBe('paused');
  });

  it('computeNextRun anchors interval tasks to scheduled time to prevent drift', () => {
    const scheduledTime = new Date(Date.now() - 2000).toISOString(); // 2s ago
    const task = {
      id: 'drift-test',
      group_folder: 'test',
      chat_jid: 'test@g.us',
      prompt: 'test',
      schedule_type: 'interval' as const,
      schedule_value: '60000', // 1 minute
      context_mode: 'isolated' as const,
      next_run: scheduledTime,
      last_run: null,
      last_result: null,
      status: 'active' as const,
      created_at: '2026-01-01T00:00:00.000Z',
    };

    const nextRun = computeNextRun(task);
    expect(nextRun).not.toBeNull();

    // Should be anchored to scheduledTime + 60s, NOT Date.now() + 60s
    const expected = new Date(scheduledTime).getTime() + 60000;
    expect(new Date(nextRun!).getTime()).toBe(expected);
  });

  it('computeNextRun returns null for once-tasks', () => {
    const task = {
      id: 'once-test',
      group_folder: 'test',
      chat_jid: 'test@g.us',
      prompt: 'test',
      schedule_type: 'once' as const,
      schedule_value: '2026-01-01T00:00:00.000Z',
      context_mode: 'isolated' as const,
      next_run: new Date(Date.now() - 1000).toISOString(),
      last_run: null,
      last_result: null,
      status: 'active' as const,
      created_at: '2026-01-01T00:00:00.000Z',
    };

    expect(computeNextRun(task)).toBeNull();
  });

  it('computeNextRun skips missed intervals without infinite loop', () => {
    // Task was due 10 intervals ago (missed)
    const ms = 60000;
    const missedBy = ms * 10;
    const scheduledTime = new Date(Date.now() - missedBy).toISOString();

    const task = {
      id: 'skip-test',
      group_folder: 'test',
      chat_jid: 'test@g.us',
      prompt: 'test',
      schedule_type: 'interval' as const,
      schedule_value: String(ms),
      context_mode: 'isolated' as const,
      next_run: scheduledTime,
      last_run: null,
      last_result: null,
      status: 'active' as const,
      created_at: '2026-01-01T00:00:00.000Z',
    };

    const nextRun = computeNextRun(task);
    expect(nextRun).not.toBeNull();
    // Must be in the future
    expect(new Date(nextRun!).getTime()).toBeGreaterThan(Date.now());
    // Must be aligned to the original schedule grid
    const offset =
      (new Date(nextRun!).getTime() - new Date(scheduledTime).getTime()) % ms;
    expect(offset).toBe(0);
  });

  describe('stranded tasks (active, next_run NULL)', () => {
    const base = {
      group_folder: 'copilot',
      chat_jid: 'webhook@nanoclaw',
      prompt: 'run',
      context_mode: 'group' as const,
      created_at: '2026-05-04T19:04:50.446Z',
    };

    it('schedules an active cron task that has no next_run', () => {
      // The production case: the alert digest, active since May, never run.
      createTask({
        ...base,
        id: 'copilot-alert-digest-15m',
        schedule_type: 'cron',
        schedule_value: '*/15 * * * *',
        next_run: null,
        status: 'active',
      });

      expect(repairStrandedTasks()).toBe(1);
      const task = getTaskById('copilot-alert-digest-15m');
      expect(task?.next_run).toBeTruthy();
      expect(new Date(task!.next_run!).getTime()).toBeGreaterThan(Date.now());
    });

    it('schedules an interval task without throwing on the missing anchor', () => {
      createTask({
        ...base,
        id: 'stranded-interval',
        schedule_type: 'interval',
        schedule_value: String(60 * 60 * 1000),
        next_run: null,
        status: 'active',
      });

      expect(() => repairStrandedTasks()).not.toThrow();
      const next = new Date(
        getTaskById('stranded-interval')!.next_run!,
      ).getTime();
      expect(next).toBeGreaterThan(Date.now());
      expect(next).toBeLessThanOrEqual(Date.now() + 60 * 60 * 1000);
    });

    it('does not revive paused tasks', () => {
      createTask({
        ...base,
        id: 'paused-cron',
        schedule_type: 'cron',
        schedule_value: '*/15 * * * *',
        next_run: null,
        status: 'paused',
      });

      expect(repairStrandedTasks()).toBe(0);
      expect(getTaskById('paused-cron')?.next_run).toBeNull();
    });

    it('leaves finished one-shot tasks alone', () => {
      createTask({
        ...base,
        id: 'done-once',
        schedule_type: 'once',
        schedule_value: '2026-02-22T00:00:00.000Z',
        next_run: null,
        status: 'active',
      });

      expect(repairStrandedTasks()).toBe(0);
      expect(getTaskById('done-once')?.next_run).toBeNull();
    });

    it('is repaired by the scheduler loop itself, not just on demand', async () => {
      createTask({
        ...base,
        id: 'loop-repaired',
        schedule_type: 'cron',
        schedule_value: '*/15 * * * *',
        next_run: null,
        status: 'active',
      });

      startSchedulerLoop({
        registeredGroups: () => ({}),
        getSessions: () => ({}),
        queue: { enqueueTask: vi.fn() } as any,
        onProcess: () => {},
        sendMessage: async () => {},
      });
      await vi.advanceTimersByTimeAsync(10);

      expect(getTaskById('loop-repaired')?.next_run).toBeTruthy();
    });

    it('computeNextRun handles an interval task with no next_run', () => {
      const next = computeNextRun({
        ...base,
        id: 'x',
        schedule_type: 'interval',
        schedule_value: '60000',
        next_run: null,
        status: 'active',
      } as any);
      expect(next).toBeTruthy();
      expect(Number.isNaN(new Date(next!).getTime())).toBe(false);
    });
  });
});
