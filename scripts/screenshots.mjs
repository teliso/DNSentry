// Regenerates the console screenshots in docs/images from a throw-away demo
// instance: a fake upstream, a local rule list and some generated traffic.
//
//   pnpm screenshots            # builds ./cmd/dnsentry and uses Chromium from Playwright
//   CHROME=/path/to/chrome pnpm screenshots
//
// Requires Go, a built console (pnpm build) and a Chromium browser.
import { spawn, execFileSync } from 'node:child_process';
import dgram from 'node:dgram';
import http from 'node:http';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const out = path.join(root, 'docs', 'images');
const work = mkdtempSync(path.join(tmpdir(), 'dnsentry-shots-'));
const PORTS = { dns: 25353, web: 28080, list: 28099, upstream: 25399, slow: 25398 };

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const cleanups = [];

// A minimal DNS responder: answers A queries with 203.0.113.x, other types empty.
function fakeUpstream(port, maxDelay) {
  const socket = dgram.createSocket('udp4');
  socket.on('message', (msg, rinfo) => {
    let i = 12;
    while (msg[i] !== 0) i += msg[i] + 1;
    const question = msg.subarray(12, i + 5);
    const qtype = msg.readUInt16BE(i + 1);
    const answer = qtype === 1 ? Buffer.concat([Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, 203, 0, 113]), Buffer.from([1 + Math.floor(Math.random() * 250)])]) : Buffer.alloc(0);
    const header = Buffer.from([msg[0], msg[1], 0x81, 0x80, msg[4], msg[5], 0, answer.length ? 1 : 0, 0, 0, 0, 0]);
    setTimeout(() => socket.send(Buffer.concat([header, question, answer]), rinfo.port, rinfo.address), Math.random() * maxDelay);
  });
  socket.bind(port, '127.0.0.1');
  cleanups.push(() => socket.close());
}

function query(name, type = 1) {
  return new Promise((resolve) => {
    const socket = dgram.createSocket('udp4');
    const labels = name.split('.').flatMap((label) => [Buffer.from([label.length]), Buffer.from(label)]);
    const id = Buffer.alloc(2);
    id.writeUInt16BE(Math.floor(Math.random() * 65536));
    const tail = Buffer.alloc(4);
    tail.writeUInt16BE(type, 0);
    tail.writeUInt16BE(1, 2);
    const packet = Buffer.concat([id, Buffer.from([1, 0, 0, 1, 0, 0, 0, 0, 0, 0]), ...labels, Buffer.from([0]), tail]);
    let finished = false;
    const done = () => { if (finished) return; finished = true; socket.close(); resolve(); };
    socket.once('message', done);
    setTimeout(done, 1500);
    socket.send(packet, PORTS.dns, '127.0.0.1');
  });
}

async function traffic() {
  const normal = ['www.example.com', 'api.github.com', 'cdn.jsdelivr.net', 'fonts.gstatic.com', 'mail.google.com', 'updates.microsoft.com', 'store.steampowered.com', 'news.ycombinator.com', 'weather.apple.com'];
  const blocked = ['ads.doubleclick.test', 'tracker.analytics.test', 'telemetry.badcorp.test', 'ads.example.net'];
  for (let i = 0; i < 700; i++) {
    const name = Math.random() < 0.22 ? blocked[i % blocked.length] : normal[Math.floor(Math.random() ** 1.6 * normal.length)];
    await query(name, Math.random() < 0.85 ? 1 : 28);
  }
  await query('nas.home.arpa');
}

async function waitFor(url) {
  for (let i = 0; i < 50; i++) {
    try { if ((await fetch(url)).ok) return; } catch { /* not up yet */ }
    await sleep(200);
  }
  throw new Error(`${url} did not come up`);
}

try {
  // Demo rule list served over HTTP, and the instance's configuration.
  const hosts = ['ads', 'track', 'metrics', 'pixel', 'telemetry', 'beacon'];
  const list = ['! Demo list', ...Array.from({ length: 1800 }, (_, i) => `||${hosts[i % hosts.length]}${i}.${['example', 'adnet', 'tracker'][i % 3]}.test^`)].join('\n');
  const listServer = http.createServer((_, res) => res.end(list)).listen(PORTS.list, '127.0.0.1');
  cleanups.push(() => listServer.close());
  fakeUpstream(PORTS.upstream, 30);
  fakeUpstream(PORTS.slow, 150);

  const rules = path.join(work, 'rules.txt');
  writeFileSync(rules, '||ads.doubleclick.test^\n||tracker.analytics.test^\n||telemetry.badcorp.test^\nads.example.net\n@@||good.badcorp.test^\n');
  const config = path.join(work, 'config.yaml');
  writeFileSync(config, `version: 1
dns:
  listens: ["127.0.0.1:${PORTS.dns}"]
  upstreams: ["127.0.0.1:${PORTS.upstream}", "127.0.0.1:${PORTS.slow}", "127.0.0.1:1"]
  upstream_mode: load_balance
  blocking_mode: nxdomain
  private_reverse: true
  local_records:
    - { domain: nas.home.arpa, type: A, value: 192.168.1.10, ttl: 300 }
    - { domain: printer.home.arpa, type: A, value: 192.168.1.20, ttl: 300 }
    - { domain: router.home.arpa, type: A, value: 192.168.1.1, ttl: 300 }
  upstream_routes:
    - { name: 公司内网, domains: [corp.example.com], upstreams: ["10.0.0.1:53"] }
web:
  listen: 127.0.0.1:${PORTS.web}
cache:
  enabled: true
  size: 8388608
  optimistic: true
rules:
  local_file: ${rules}
  sources:
    - { url: "http://127.0.0.1:${PORTS.list}/list.txt", name: AdGuard DNS 过滤器, enabled: true, interval_minutes: 1440 }
`);

  const binary = path.join(work, process.platform === 'win32' ? 'dnsentry.exe' : 'dnsentry');
  execFileSync('go', ['build', '-o', binary, './cmd/dnsentry'], { cwd: root, stdio: 'inherit' });
  const server = spawn(binary, ['-config', config], { stdio: 'ignore', env: { ...process.env, DNSENTRY_API_TOKEN: '' } });
  cleanups.push(() => server.kill());
  process.on('exit', () => server.kill()); // also on an uncaught error
  const base = `http://127.0.0.1:${PORTS.web}`;
  await waitFor(`${base}/healthz`);
  await traffic();

  // A little configuration history for the maintenance page.
  for (const change of [{ block_aaaa: true }, { upstream_mode: 'parallel' }, { block_aaaa: false, upstream_mode: 'load_balance' }]) {
    const current = await (await fetch(`${base}/api/config`)).json();
    const response = await fetch(`${base}/api/config`, { method: 'PUT', headers: { 'Content-Type': 'application/json', Origin: base }, body: JSON.stringify({ ...current, ...change }) });
    if (!response.ok) throw new Error(`config update failed: ${response.status}`);
  }
  await sleep(1500);

  const executablePath = process.env.CHROME || (existsSync(chromium.executablePath()) ? undefined : '/opt/pw-browsers/chromium');
  const browser = await chromium.launch({ executablePath, args: ['--no-sandbox'] });
  mkdirSync(out, { recursive: true });
  const shots = [
    ['dashboard', 'overview', 1500], ['logs', 'logs', 900], ['sources', 'filters/sources', 800], ['rules', 'filters/rules', 900],
    ['dns-settings', 'dns/upstreams', 800], ['routes', 'dns/routes', 800], ['records', 'dns/records', 800],
    ['service-settings', 'settings/network', 1100], ['config-history', 'settings/maintenance', 900]
  ];
  const page = await (await browser.newContext({ viewport: { width: 1280, height: 800 } })).newPage();
  for (const [name, hash, limit] of shots) {
    await page.setViewportSize({ width: 1280, height: limit });
    await page.goto(`${base}/#${hash}`);
    await page.waitForTimeout(900);
    if (hash === 'filters/rules') await page.fill('input[placeholder*="example.com"]', 'ads.doubleclick.test').catch(() => {});
    const height = await page.evaluate(() => document.documentElement.scrollHeight);
    await page.screenshot({ path: path.join(out, `${name}.png`), clip: { x: 0, y: 0, width: 1280, height: Math.min(height, limit) } });
    console.log('wrote', `docs/images/${name}.png`);
  }
  const mobile = await (await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 })).newPage();
  await mobile.goto(`${base}/#overview`);
  await mobile.waitForTimeout(900);
  await mobile.screenshot({ path: path.join(out, 'mobile.png') });
  console.log('wrote docs/images/mobile.png');
  await browser.close();
} finally {
  for (const cleanup of cleanups) cleanup();
  rmSync(work, { recursive: true, force: true });
}
