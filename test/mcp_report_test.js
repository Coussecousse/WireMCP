const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const PCAP_DIR = 'D:\\dev\\PCAP tests';
const REPORT_DIR = path.join(__dirname, '..', 'reports');

const PCAPS = [
  { file: '2024-09-04-traffic-analysis-exercise.pcap', label: '2024-09-04 (C2 beacon)' },
  { file: '2024-11-26-traffic-analysis-exercise.pcap', label: '2024-11-26 (normal+AD)' },
  { file: '2025-01-22-traffic-analysis-exercise.pcap', label: '2025-01-22 (TeamViewer)' },
  { file: '2025-06-13-traffic-analysis-exercise.pcap', label: '2025-06-13 (typosquatting)' },
  { file: '2026-01-31-traffic-analysis-exercise.pcap', label: '2026-01-31 (malformed)' },
  { file: '2026-02-28-traffic-analysis-exercise.pcap', label: '2026-02-28 (fakeurl)' },
];

let reqId = 0;
class McpClient {
  constructor(proc) {
    this.proc = proc;
    this.buf = '';
    this.handlers = new Map();
    proc.stdout.on('data', (d) => {
      this.buf += d.toString();
      this._processBuffer();
    });
  }
  _processBuffer() {
    const lines = this.buf.split('\n');
    for (let i = 0; i < lines.length - 1; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      try {
        const msg = JSON.parse(line);
        if (msg.id !== undefined && this.handlers.has(msg.id)) {
          this.handlers.get(msg.id)(msg);
          this.handlers.delete(msg.id);
        }
      } catch (e) { /* skip */ }
    }
    this.buf = lines[lines.length - 1];
  }
  async send(msg) {
    return new Promise((resolve, reject) => {
      const id = msg.id || ++reqId;
      const req = JSON.stringify({ ...msg, id }) + '\n';
      this.handlers.set(id, resolve);
      const timeout = setTimeout(() => {
        this.handlers.delete(id);
        reject(new Error(`Timeout id=${id}`));
      }, 300000);
      this.proc.stdin.write(req);
      const orig = resolve;
      resolve = (v) => { clearTimeout(timeout); orig(v); };
    });
  }
  async init() {
    await this.send({ jsonrpc: '2.0', method: 'initialize', params: { protocolVersion: '0.1.0', capabilities: {}, clientInfo: { name: 'report-test', version: '1' } } });
    this.proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
  }
  async callTool(name, args) {
    return await this.send({ jsonrpc: '2.0', method: 'tools/call', params: { name, arguments: args } });
  }
  close() {
    this.proc.stdin.end();
    this.proc.kill();
  }
}

async function main() {
  console.log('=== WireMCP Report Generator ===\n');
  fs.mkdirSync(REPORT_DIR, { recursive: true });

  for (const { file: pcapFile, label } of PCAPS) {
    const pcapPath = path.join(PCAP_DIR, pcapFile);
    const reportName = `incident-report-${pcapFile.replace('.pcap', '.md')}`;
    const reportPath = path.join(REPORT_DIR, reportName);

    console.log(`\n${'='.repeat(60)}`);
    console.log(`📄 ${label}`);
    console.log(`   ${pcapPath}`);
    console.log(`   → ${reportPath}`);
    console.log(`${'='.repeat(60)}`);

    const proc = spawn('node', ['index.js'], {
      cwd: path.join(__dirname, '..'),
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    proc.stderr.on('data', () => {});
    const mcp = new McpClient(proc);
    await mcp.init();

    try {
      const start = Date.now();
      const resp = await mcp.callTool('generate_incident_report', { pcapPath, outputPath: reportPath });
      const elapsed = ((Date.now() - start) / 1000).toFixed(1);
      if (resp.error) {
        console.log(`❌ (${elapsed}s): ${resp.error.message}`);
      } else {
        const text = resp.result?.content?.[0]?.text || '';
        console.log(`✅ (${elapsed}s): ${text.split('\n')[0]}`);
      }
    } catch (err) {
      console.log(`❌ ${err.message}`);
    }

    mcp.close();
    await new Promise(r => setTimeout(r, 500));
  }

  console.log('\nDone! Reports generated in: ' + REPORT_DIR);
}

main().catch(console.error);
