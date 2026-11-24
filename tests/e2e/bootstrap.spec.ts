import { execFile } from 'node:child_process';
import { stageSevenEvidence } from '../helpers/evidence.js';
import { promisify } from 'node:util';
import { openSync, ftruncateSync, closeSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { seedFile } from '../helpers/files.js';
import { openStore } from '../../apps/server/src/database/store.js';
import { randomUUID } from 'node:crypto';
import { test, expect } from '@playwright/test';

const execFileAsync = promisify(execFile);

test('shows the built application and real HTTPS health result', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.goto('/');
  await expect(page).toHaveTitle('SecureTransfer · 安全文件传输');
  await expect(page.getByRole('heading', { level: 1 })).toContainText('让文件传输');
  await expect(page.getByRole('status')).toHaveText('服务已就绪');
  await page.getByRole('button', { name: '重新检查' }).click();
  await expect(page.getByRole('status')).toHaveText('服务已就绪');
  await page.screenshot({ path: stageSevenEvidence('home-desktop.png'), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByRole('button', { name: '重新检查' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  );
  await page.screenshot({ path: stageSevenEvidence('home-mobile.png'), fullPage: true });
  expect(errors).toEqual([]);
});

test('shows a recoverable error when the service is unavailable', async ({ page }) => {
  await page.route('**/api/health', (route) => route.abort());
  await page.goto('/');
  await expect(page.getByRole('status')).toHaveText('暂时无法连接服务');
  await page.unroute('**/api/health');
  await page.getByRole('button', { name: '重新检查' }).click();
  await expect(page.getByRole('status')).toHaveText('服务已就绪');
});

test('reuses one WSS connection for ten protocol requests and disconnects', async ({ page }) => {
  const connections: string[] = [];
  page.on('websocket', (socket) => connections.push(socket.url()));
  await page.goto('/');
  await page.getByRole('button', { name: '建立连接', exact: true }).click();
  await expect(page.getByRole('heading', { name: '连接已建立', exact: true })).toBeVisible();
  await page.getByRole('button', { name: '连续验证 10 次' }).click();
  await expect(page.getByTestId('probe-count')).toHaveText('已确认 10 / 10');
  await expect(page.getByTestId('connection-id')).toContainText('连接标识：');
  expect(connections).toEqual(['wss://localhost:8443/ws']);
  await page.screenshot({ path: stageSevenEvidence('connection-desktop.png'), fullPage: true });
  await page.getByRole('button', { name: '断开连接', exact: true }).click();
  await expect(page.getByRole('heading', { name: '连接已关闭', exact: true })).toBeVisible();
});

test('does not reconnect automatically after the authentication deadline', async ({ page }) => {
  test.setTimeout(20000);
  let connections = 0;
  page.on('websocket', () => connections++);
  await page.goto('/');
  await page.getByRole('button', { name: '建立连接', exact: true }).click();
  await expect(page.getByRole('heading', { name: '连接已建立', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: '连接已关闭', exact: true })).toBeVisible({
    timeout: 14000,
  });
  await page.waitForTimeout(1300);
  expect(connections).toBe(1);
});

test('reconnects after an abnormal transport closure and can communicate again', async ({
  page,
}) => {
  let attempts = 0;
  await page.routeWebSocket('wss://localhost:8443/ws', (socket) => {
    const server = socket.connectToServer();
    attempts++;
    if (attempts === 1)
      setTimeout(() => {
        socket.close({ code: 1011, reason: 'Test interruption' });
        server.close();
      }, 300);
  });
  await page.goto('/');
  await page.getByRole('button', { name: '建立连接', exact: true }).click();
  await expect.poll(() => attempts).toBe(2);
  await expect(page.getByRole('heading', { name: '连接已建立', exact: true })).toBeVisible();
  await page.getByRole('button', { name: '连续验证 10 次' }).click();
  await expect(page.getByTestId('probe-count')).toHaveText('已确认 10 / 10');
  await page.getByRole('button', { name: '断开连接', exact: true }).click();
});

function testUsername() {
  return 'u_' + randomUUID().replaceAll('-', '').slice(0, 16);
}
async function registerAndLogin(page: import('@playwright/test').Page, username: string) {
  await page.goto('/');
  await page.getByLabel('用户名', { exact: true }).fill(username);
  await page.getByLabel('密码', { exact: true }).fill('fixture-browser-three');
  await page.getByRole('button', { name: '注册账户', exact: true }).click();
  await expect(page.getByRole('status', { name: '账户提示' })).toContainText('注册成功');
  await page.getByLabel('密码', { exact: true }).fill('fixture-browser-three');
  await page.getByRole('button', { name: '登录', exact: true }).click();
  await expect(
    page.getByRole('heading', { name: username + ' 的文件', exact: true }),
  ).toBeVisible();
  await expect(page.getByText('还没有文件，选择一个文件开始上传。', { exact: true })).toBeVisible();
}

test('registers, logs in, loads owned files, deletes one, and logs out', async ({ page }) => {
  const username = testUsername();
  await registerAndLogin(page, username);
  const dataRoot = process.env['ST_E2E_DATA_DIR']!;
  const db = openStore(dataRoot);
  const user = db.prepare('SELECT id FROM users WHERE username=?').get(username)!;
  db.close();
  const file = seedFile(dataRoot, String(user['id']), '<img src=x onerror=alert(1)>.txt');
  await page.getByRole('button', { name: '刷新文件', exact: true }).click();
  await expect(page.getByRole('cell', { name: file.name, exact: true })).toBeVisible();
  await expect(page.locator('.file-table img')).toHaveCount(0);
  await page.screenshot({ path: stageSevenEvidence('files-desktop.png'), fullPage: true });
  await page.getByRole('button', { name: '删除', exact: true }).click();
  await page.getByRole('button', { name: '确认删除', exact: true }).click();
  await expect(page.getByText('还没有文件，选择一个文件开始上传。', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: '退出登录', exact: true }).click();
  await expect(page.getByRole('heading', { name: '登录你的账户', exact: true })).toBeVisible();
});

test('keeps credentials in memory only and requires login after refresh', async ({ page }) => {
  const username = testUsername();
  await registerAndLogin(page, username);
  const stored = await page.evaluate(() => ({
    local: localStorage.length,
    session: sessionStorage.length,
    cookie: document.cookie,
  }));
  expect(stored).toEqual({ local: 0, session: 0, cookie: '' });
  await page.reload();
  await expect(page.getByRole('heading', { name: '登录你的账户', exact: true })).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: stageSevenEvidence('account-mobile.png'), fullPage: true });
});

test('restores a real authenticated session after an abnormal closure', async ({ page }) => {
  let first: import('@playwright/test').WebSocketRoute | undefined;
  let peer: import('@playwright/test').WebSocketRoute | undefined;
  let attempts = 0;
  await page.routeWebSocket('wss://localhost:8443/ws', (socket) => {
    const server = socket.connectToServer();
    attempts++;
    if (attempts === 1) {
      first = socket;
      peer = server;
    }
  });
  const username = testUsername();
  await registerAndLogin(page, username);
  first!.close({ code: 1011, reason: 'Test disconnect' });
  peer!.close();
  await expect.poll(() => attempts).toBe(2);
  await expect(page.getByRole('heading', { name: '连接已建立', exact: true })).toBeVisible();
  await page.getByRole('button', { name: '刷新文件', exact: true }).click();
  await expect(page.getByText('会话已认证', { exact: true })).toBeVisible();
  await expect(page.getByRole('alert')).toHaveCount(0);
  await page.getByRole('button', { name: '退出登录', exact: true }).click();
});

test('reports incorrect credentials without displaying a file workspace', async ({ page }) => {
  await page.goto('/');
  await page.getByLabel('用户名', { exact: true }).fill('unknown_' + Date.now().toString(36));
  await page.getByLabel('密码', { exact: true }).fill('fixture-wrong-password');
  await page.getByRole('button', { name: '登录', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('无效');
  await expect(page.getByRole('heading', { name: '登录你的账户', exact: true })).toBeVisible();
  await expect(page.getByLabel('密码', { exact: true })).toHaveValue('');
});

test('uploads and downloads through the GUI with matching saved bytes', async ({ page }) => {
  const username = testUsername();
  await registerAndLogin(page, username);
  const content = Buffer.alloc(1024 * 1024, 0xb7);
  const name = '浏览器传输.bin';
  await page
    .getByLabel('上传文件', { exact: true })
    .setInputFiles({ name, mimeType: 'application/octet-stream', buffer: content });
  await expect(page.getByText('上传已完成 · ' + name, { exact: true })).toBeVisible({
    timeout: 20000,
  });
  const row = page.getByRole('row').filter({ has: page.getByRole('cell', { name, exact: true }) });
  await row.getByRole('button', { name: '下载', exact: true }).click();
  await expect(page.getByText('下载已校验 · ' + name, { exact: true })).toBeVisible({
    timeout: 20000,
  });
  await page.screenshot({ path: stageSevenEvidence('transfer-completed.png'), fullPage: true });
  const saved = page.waitForEvent('download');
  await page.getByRole('link', { name: '保存文件', exact: true }).click();
  const download = await saved;
  expect(download.suggestedFilename()).toBe(name);
  const result = await readFile((await download.path())!);
  expect(createHash('sha256').update(result).digest('hex')).toBe(
    createHash('sha256').update(content).digest('hex'),
  );
  await page.getByRole('button', { name: '关闭保存入口' }).click();
  await expect(page.getByRole('link', { name: '保存文件', exact: true })).toHaveCount(0);
});

test('cancels an upload and can start a new one on the same connection', async ({ page }) => {
  const username = testUsername();
  await registerAndLogin(page, username);
  await page.getByLabel('上传文件', { exact: true }).setInputFiles({
    name: 'cancel.bin',
    mimeType: 'application/octet-stream',
    buffer: Buffer.alloc(5 * 1024 * 1024),
  });
  await expect(page.getByText('正在上传 · cancel.bin', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: '取消传输', exact: true }).click();
  await expect(page.getByRole('status', { name: '账户提示' })).toContainText('传输已取消');
  await expect(page.getByRole('cell', { name: 'cancel.bin', exact: true })).toHaveCount(0);
  await page.getByLabel('上传文件', { exact: true }).setInputFiles({
    name: 'after-cancel.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('ready'),
  });
  await expect(page.getByText('上传已完成 · after-cancel.txt', { exact: true })).toBeVisible();
});

test('handles a 100 MiB browser upload and three downloads with observed memory use', async ({
  page,
  context,
  browser,
}) => {
  test.setTimeout(240000);
  const username = testUsername();
  await registerAndLogin(page, username);
  const directory = process.env['ST_E2E_DATA_DIR']!;
  const source = join(directory, 'large-100MiB.bin');
  const fd = openSync(source, 'w');
  ftruncateSync(fd, 100 * 1024 * 1024);
  closeSync(fd);
  const zeroBlock = Buffer.alloc(65536),
    hash = createHash('sha256');
  for (let n = 0; n < 1600; n++) hash.update(zeroBlock);
  const expected = hash.digest('hex');
  const pages = [page];
  const cdp = await browser.newBrowserCDPSession();
  const samples: { elapsedMs: number; browserWorkingSetBytes: number }[] = [];
  const samplingErrors: string[] = [];
  const start = performance.now();
  let sampling = true;
  const sampler = (async () => {
    while (sampling) {
      try {
        const info = (await cdp.send('SystemInfo.getProcessInfo')) as {
          processInfo: { id: number }[];
        };
        const pids = info.processInfo
          .map((process) => Number(process.id))
          .filter((id) => Number.isInteger(id) && id > 0);
        const script =
          '$sum=(Get-Process -Id ' +
          pids.join(',') +
          ' -ErrorAction SilentlyContinue | Measure-Object WorkingSet64 -Sum).Sum; ConvertTo-Json -InputObject $sum -Compress';
        const result = await execFileAsync('powershell.exe', ['-NoProfile', '-Command', script], {
          windowsHide: true,
          timeout: 5000,
        });
        const bytes = Number(result.stdout.trim());
        if (bytes > 0)
          samples.push({ elapsedMs: performance.now() - start, browserWorkingSetBytes: bytes });
      } catch {
        samplingErrors.push('Memory sample unavailable');
      }
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  })();
  try {
    await page.getByLabel('上传文件', { exact: true }).setInputFiles(source);
    await expect(page.getByText('上传已完成 · large-100MiB.bin', { exact: true })).toBeVisible({
      timeout: 120000,
    });
    const uploadMs = performance.now() - start;
    for (let n = 0; n < 2; n++) {
      const next = await context.newPage();
      pages.push(next);
      await next.goto('/');
      await next.getByLabel('用户名', { exact: true }).fill(username);
      await next.getByLabel('密码', { exact: true }).fill('fixture-browser-three');
      await next.getByRole('button', { name: '登录', exact: true }).click();
      await expect(next.getByRole('cell', { name: 'large-100MiB.bin', exact: true })).toBeVisible();
    }
    const downloadsStart = performance.now();
    await Promise.all(
      pages.map((current) =>
        current
          .getByRole('row')
          .filter({
            has: current.getByRole('cell', { name: 'large-100MiB.bin', exact: true }),
          })
          .getByRole('button', { name: '下载', exact: true })
          .click(),
      ),
    );
    await Promise.all(
      pages.map((current) =>
        expect(current.getByText('下载已校验 · large-100MiB.bin', { exact: true })).toBeVisible({
          timeout: 120000,
        }),
      ),
    );
    const threeDownloadsMs = performance.now() - downloadsStart;
    await Promise.all(pages.map((current) => current.evaluate(() => performance.now())));
    const saved = page.waitForEvent('download');
    await page.getByRole('link', { name: '保存文件', exact: true }).click();
    const download = await saved;
    const actual = createHash('sha256')
      .update(await readFile((await download.path())!))
      .digest('hex');
    expect(actual).toBe(expected);
    expect(samples.length).toBeGreaterThan(0);
    await page.setViewportSize({ width: 390, height: 844 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
      true,
    );
    await page.screenshot({ path: stageSevenEvidence('transfer-mobile.png'), fullPage: true });
    await Promise.all(
      pages.map((current) => current.getByRole('button', { name: '关闭保存入口' }).click()),
    );
    await writeFile(
      stageSevenEvidence('browser-large-file.json'),
      JSON.stringify(
        {
          result: 'PASS',
          sizeBytes: 100 * 1024 * 1024,
          concurrentPages: 3,
          expectedSha256: expected,
          savedSha256: actual,
          uploadMs,
          threeDownloadsMs,
          peakBrowserWorkingSetBytes: Math.max(
            ...samples.map((sample) => sample.browserWorkingSetBytes),
          ),
          memoryMetric:
            'Sum of working sets of this test browser process tree; shared pages can be counted more than once. Includes upload and retained Blob URLs.',
          samples,
          samplingErrors,
        },
        null,
        2,
      ),
    );
  } finally {
    sampling = false;
    await sampler;
    await cdp.detach();
    unlinkSync(source);
    for (const extra of pages.slice(1)) await extra.close();
  }
});

test('resumes a paused upload after refreshing the page', async ({ page }) => {
  const username = testUsername();
  await registerAndLogin(page, username);
  const file = {
    name: 'resume-in-edge.bin',
    mimeType: 'application/octet-stream',
    buffer: Buffer.alloc(12 * 1024 * 1024, 23),
  };
  await page.getByLabel('上传文件', { exact: true }).setInputFiles(file);
  const job = page.getByRole('region', { name: file.name });
  await expect(job.getByTestId('transfer-progress')).not.toHaveText(/^0% · 0 /);
  await job.getByRole('button', { name: '暂停上传' }).click();
  await expect(job.getByText('已暂停 · ' + file.name)).toBeVisible();
  await expect(page.getByText(/已确认 [1-9]/)).toBeVisible();
  await page.screenshot({ path: stageSevenEvidence('upload-checkpoint.png'), fullPage: true });
  await page.reload();
  await page.getByLabel('用户名').fill(username);
  await page.getByLabel('密码', { exact: true }).fill('fixture-browser-three');
  await page.getByRole('button', { name: '登录', exact: true }).click();
  await page.getByLabel('选择原文件续传').setInputFiles(file);
  await expect(page.getByText('上传已完成 · ' + file.name)).toBeVisible();
  await expect(page.getByRole('cell', { name: file.name, exact: true })).toHaveCount(1);
});

test('uploads and downloads multiple files from the same page', async ({ page }) => {
  await registerAndLogin(page, testUsername());
  const files = ['alpha.bin', 'beta.bin', 'gamma.bin'].map((name, index) => ({
    name,
    mimeType: 'application/octet-stream',
    buffer: Buffer.alloc(1024 * 1024, index + 8),
  }));
  await page.getByLabel('上传文件', { exact: true }).setInputFiles(files);
  await expect(page.getByRole('progressbar', { name: '传输进度' })).toHaveCount(3);
  for (const file of files) await expect(page.getByText('上传已完成 · ' + file.name)).toBeVisible();
  for (const file of files) {
    await page.getByRole('checkbox', { name: '选择文件 ' + file.name, exact: true }).check();
  }
  await page.getByRole('button', { name: '下载所选文件（3）', exact: true }).click();
  for (const file of files) await expect(page.getByText('下载已校验 · ' + file.name)).toBeVisible();
  await expect(page.getByRole('link', { name: '保存文件' })).toHaveCount(3);
  const audit = await readFile(join(process.env['ST_E2E_DATA_DIR']!, 'logs/audit.jsonl'), 'utf8');
  const starts = audit
    .trim()
    .split('\n')
    .map((line) => JSON.parse(line))
    .filter((event) => event.event === 'transfer_started');
  expect(starts.slice(-3).map((event) => [event.direction, event.activeTransfers])).toEqual([
    ['download', 1],
    ['download', 2],
    ['download', 3],
  ]);
  for (const file of files) {
    const region = page
      .getByRole('region', { name: file.name, exact: true })
      .filter({ has: page.getByRole('link') });
    const pending = page.waitForEvent('download');
    await region.getByRole('link', { name: '保存文件' }).click();
    const download = await pending;
    expect(await readFile((await download.path())!)).toEqual(file.buffer);
  }
  await page.screenshot({ path: stageSevenEvidence('concurrent-transfers.png'), fullPage: true });
});

test('enrolls a non-extractable browser key, logs in with it and revokes it', async ({ page }) => {
  const username = testUsername();
  await registerAndLogin(page, username);
  await page.getByText('公钥管理', { exact: true }).click();
  await page.getByLabel('当前账号密码').fill('fixture-browser-three');
  await page.getByRole('button', { name: '登记公钥' }).click();
  await expect(page.getByText('公钥已登记。')).toBeVisible();
  const extractable = await page.evaluate(
    () =>
      new Promise<boolean>((resolve, reject) => {
        const open = indexedDB.open('securetransfer-keys');
        open.onerror = () => reject(open.error);
        open.onsuccess = () => {
          const db = open.result;
          const read = db.transaction('keys', 'readonly').objectStore('keys').getAll();
          read.onerror = () => {
            db.close();
            reject(read.error);
          };
          read.onsuccess = () => {
            db.close();
            resolve(read.result[0].privateKey.extractable);
          };
        };
      }),
  );
  expect(extractable).toBe(false);
  await page.getByRole('button', { name: '退出登录' }).click();
  await page.reload();
  await page.getByLabel('用户名').fill(username);
  await page.getByRole('button', { name: '使用公钥登录' }).click();
  await expect(page.getByRole('heading', { name: username + ' 的文件' })).toBeVisible();
  await page.screenshot({ path: stageSevenEvidence('public-key-login.png'), fullPage: true });
  await page.getByText('公钥管理', { exact: true }).click();
  await page.getByLabel('当前账号密码').fill('fixture-browser-three');
  await page.getByRole('button', { name: '撤销公钥' }).click();
  await expect(page.getByRole('heading', { name: '登录你的账户' })).toBeVisible();
  await expect(page.getByRole('button', { name: '使用公钥登录' })).toHaveCount(0);
});
