// index.js - WireMCP Server
const axios = require('axios');
const { exec } = require('child_process');
const { promisify } = require('util');
const which = require('which');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const execAsync = promisify(exec);
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { z } = require('zod');

// Redirect console.log to stderr
const originalConsoleLog = console.log;
console.log = (...args) => console.error(...args);

// Dynamically locate tshark
async function findTshark() {
  try {
    const tsharkPath = await which('tshark');
    console.error(`Found tshark at: ${tsharkPath}`);
    return tsharkPath;
  } catch (err) {
    console.error('which failed to find tshark:', err.message);
    const fallbacks = process.platform === 'win32'
      ? ['D:\\wireshark\\tshark.exe', 'C:\\Program Files\\Wireshark\\tshark.exe', 'C:\\Program Files (x86)\\Wireshark\\tshark.exe']
      : ['/usr/bin/tshark', '/usr/local/bin/tshark', '/opt/homebrew/bin/tshark', '/Applications/Wireshark.app/Contents/MacOS/tshark'];
    
    for (const path of fallbacks) {
      try {
        await execAsync(`${path} -v`);
        console.error(`Found tshark at fallback: ${path}`);
        return path;
      } catch (e) {
        console.error(`Fallback ${path} failed: ${e.message}`);
      }
    }
    throw new Error('tshark not found. Please install Wireshark (https://www.wireshark.org/download.html) and ensure tshark is in your PATH.');
  }
}

// Initialize MCP server
const server = new McpServer({
  name: 'wiremcp',
  version: '1.0.0',
});

// ===== Utility Functions =====

function trimPackets(packets, maxChars = 720000) {
  let jsonString = JSON.stringify(packets);
  if (jsonString.length > maxChars) {
    const trimCount = Math.max(1, Math.floor(packets.length * (maxChars / jsonString.length)));
    const trimmed = packets.slice(0, trimCount);
    console.error(`Trimmed packets from ${packets.length} to ${trimCount} to fit ${maxChars} chars`);
    return trimmed;
  }
  return packets;
}

function parseTsharkJson(stdout) {
  try {
    return JSON.parse(stdout);
  } catch (err) {
    console.error(`Failed to parse tshark JSON output: ${err.message}`);
    console.error(`Raw output (first 500 chars): ${stdout.slice(0, 500)}`);
    throw new Error(`Invalid tshark output: ${err.message}`);
  }
}

const ETH_IP_ICMP_OFFSET = 14 + 20 + 8;

function parseIcmpPayloadsFromHex(hexOutput) {
  const result = {};
  let currentFrame = null;
  let currentBytes = [];

  const lines = hexOutput.split('\n');
  for (const line of lines) {
    const frameMatch = line.match(/Frame (\d+):/);
    if (frameMatch) {
      if (currentFrame !== null && currentBytes.length > ETH_IP_ICMP_OFFSET) {
        const payload = currentBytes.slice(ETH_IP_ICMP_OFFSET);
        if (payload.length > 0) {
          result[currentFrame] = Buffer.from(payload).toString('hex').toUpperCase();
        }
      }
      currentFrame = parseInt(frameMatch[1]);
      currentBytes = [];
      continue;
    }

    const hexMatch = line.match(/^\s*[0-9a-f]{4}\s+((?:[0-9a-f]{2}\s)+)/);
    if (hexMatch && currentFrame !== null) {
      const hexBytes = hexMatch[1].trim().split(/\s+/).filter(b => b.length === 2);
      for (const b of hexBytes) {
        currentBytes.push(parseInt(b, 16));
      }
    }
  }

  if (currentFrame !== null && currentBytes.length > ETH_IP_ICMP_OFFSET) {
    const payload = currentBytes.slice(ETH_IP_ICMP_OFFSET);
    if (payload.length > 0) {
      result[currentFrame] = Buffer.from(payload).toString('hex').toUpperCase();
    }
  }

  return result;
}

async function extractRawIcmpPayloads(pcapPath, filter) {
  const tsharkPath = await findTshark();
  const icmpFilter = filter || 'icmp';
  const filterFlag = ` -Y "${icmpFilter}"`;
  const { stdout } = await execAsync(
    `${tsharkPath} -r "${pcapPath}"${filterFlag} -x`,
    { maxBuffer: 50 * 1024 * 1024, env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
  );
  return parseIcmpPayloadsFromHex(stdout);
}

// Tool 1: Capture live packet data
const TSHARK_ICMP_FIELDS = '-e icmp.type -e icmp.code -e icmp.seq -e icmp.ident -e icmp.checksum -e data.len -e data.data';
const TSHARK_ICMPV6_FIELDS = '-e icmpv6.type -e icmpv6.code';
const TSHARK_META_FIELDS = '-e ip.id -e ip.ttl -e frame.time_epoch -e frame.protocols';
const TSHARK_UDP_FIELDS = '-e udp.srcport -e udp.dstport';

server.tool(
  'capture_packets',
  'Capture live traffic and provide raw packet data as JSON for LLM analysis (supports TCP, UDP, HTTP, ICMP, ICMPv6)',
  {
    interface: z.string().optional().default('en0').describe('Network interface to capture from (e.g., eth0, en0)'),
    duration: z.number().optional().default(5).describe('Capture duration in seconds'),
    filter: z.string().optional().describe('Display filter to apply (e.g., "icmp")'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { interface, duration, filter } = args;
      const tempPcap = 'temp_capture.pcap';
      console.error(`Capturing packets on ${interface} for ${duration}s`);

      await execAsync(
        `${tsharkPath} -i ${interface} -w ${tempPcap} -a duration:${duration}`,
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );

      const filterFlag = filter ? ` -Y "${filter}"` : '';
      const { stdout, stderr } = await execAsync(
        `${tsharkPath} -r "${tempPcap}" -T json -e frame.number -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.flags ${TSHARK_UDP_FIELDS} ${TSHARK_ICMP_FIELDS} ${TSHARK_ICMPV6_FIELDS} ${TSHARK_META_FIELDS} -e http.request.method -e http.response.code${filterFlag}`,
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );
      if (stderr) console.error(`tshark stderr: ${stderr}`);
      let packets;
      try { packets = JSON.parse(stdout); } catch (e) { throw new Error(`Failed to parse tshark output: ${e.message}`); }

      const maxChars = 720000;
      let jsonString = JSON.stringify(packets);
      if (jsonString.length > maxChars) {
        const trimFactor = maxChars / jsonString.length;
        const trimCount = Math.max(1, Math.floor(packets.length * trimFactor));
        packets = packets.slice(0, trimCount);
        jsonString = JSON.stringify(packets);
        console.error(`Trimmed packets from ${packets.length} to ${trimCount} to fit ${maxChars} chars`);
      }

      await fs.unlink(tempPcap).catch(err => console.error(`Failed to delete ${tempPcap}: ${err.message}`));

      return {
        content: [{
          type: 'text',
          text: `Captured packet data (JSON for LLM analysis):\n${jsonString}`,
        }],
      };
    } catch (error) {
      console.error(`Error in capture_packets: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Tool 2: Capture and provide summary statistics
server.tool(
  'get_summary_stats',
  'Capture live traffic and provide protocol hierarchy statistics for LLM analysis',
  {
    interface: z.string().optional().default('en0').describe('Network interface to capture from (e.g., eth0, en0)'),
    duration: z.number().optional().default(5).describe('Capture duration in seconds'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { interface, duration } = args;
      const tempPcap = 'temp_capture.pcap';
      console.error(`Capturing summary stats on ${interface} for ${duration}s`);

      await execAsync(
        `${tsharkPath} -i ${interface} -w ${tempPcap} -a duration:${duration}`,
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );

      const { stdout, stderr } = await execAsync(
        `${tsharkPath} -r "${tempPcap}" -qz io,phs`,
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );
      if (stderr) console.error(`tshark stderr: ${stderr}`);

      await fs.unlink(tempPcap).catch(err => console.error(`Failed to delete ${tempPcap}: ${err.message}`));

      return {
        content: [{
          type: 'text',
          text: `Protocol hierarchy statistics for LLM analysis:\n${stdout}`,
        }],
      };
    } catch (error) {
      console.error(`Error in get_summary_stats: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Tool 3: Capture and provide conversation stats
server.tool(
  'get_conversations',
  'Capture live traffic and provide TCP/UDP conversation statistics for LLM analysis',
  {
    interface: z.string().optional().default('en0').describe('Network interface to capture from (e.g., eth0, en0)'),
    duration: z.number().optional().default(5).describe('Capture duration in seconds'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { interface, duration } = args;
      const tempPcap = 'temp_capture.pcap';
      console.error(`Capturing conversations on ${interface} for ${duration}s`);

      await execAsync(
        `${tsharkPath} -i ${interface} -w ${tempPcap} -a duration:${duration}`,
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );

      const { stdout, stderr } = await execAsync(
        `${tsharkPath} -r "${tempPcap}" -qz conv,tcp`,
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );
      if (stderr) console.error(`tshark stderr: ${stderr}`);

      await fs.unlink(tempPcap).catch(err => console.error(`Failed to delete ${tempPcap}: ${err.message}`));

      return {
        content: [{
          type: 'text',
          text: `TCP/UDP conversation statistics for LLM analysis:\n${stdout}`,
        }],
      };
    } catch (error) {
      console.error(`Error in get_conversations: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Tool 4: Capture traffic and check threats against URLhaus
server.tool(
  'check_threats',
  'Capture live traffic and check IPs against URLhaus blacklist',
  {
    interface: z.string().optional().default('en0').describe('Network interface to capture from (e.g., eth0, en0)'),
    duration: z.number().optional().default(5).describe('Capture duration in seconds'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { interface, duration } = args;
      const tempPcap = 'temp_capture.pcap';
      console.error(`Capturing traffic on ${interface} for ${duration}s to check threats`);

      await execAsync(
        `${tsharkPath} -i ${interface} -w ${tempPcap} -a duration:${duration}`,
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );

      const { stdout } = await execAsync(
        `${tsharkPath} -r "${tempPcap}" -T fields -e ip.src -e ip.dst`,
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );
      const ips = [...new Set(stdout.split('\n').flatMap(line => line.split('\t')).filter(ip => ip && ip !== 'unknown'))];
      console.error(`Captured ${ips.length} unique IPs: ${ips.join(', ')}`);

      const urlhausUrl = 'https://urlhaus.abuse.ch/downloads/text/';
      console.error(`Fetching URLhaus blacklist from ${urlhausUrl}`);
      let urlhausData;
      let urlhausThreats = [];
      try {
        const response = await axios.get(urlhausUrl);
        console.error(`URLhaus response status: ${response.status}, length: ${response.data.length} chars`);
        console.error(`URLhaus raw data (first 200 chars): ${response.data.slice(0, 200)}`);
        const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
        urlhausData = [...new Set(response.data.split('\n')
          .map(line => {
            const match = line.match(ipRegex);
            return match ? match[0] : null;
          })
          .filter(ip => ip))];
        console.error(`URLhaus lookup successful: ${urlhausData.length} blacklist IPs fetched`);
        console.error(`Sample URLhaus IPs: ${urlhausData.slice(0, 5).join(', ') || 'None'}`);
        urlhausThreats = ips.filter(ip => urlhausData.includes(ip));
        console.error(`Checked IPs against URLhaus: ${urlhausThreats.length} threats found - ${urlhausThreats.join(', ') || 'None'}`);
      } catch (e) {
        console.error(`Failed to fetch URLhaus data: ${e.message}`);
        urlhausData = [];
      }

      const outputText = `Captured IPs:\n${ips.join('\n')}\n\n` +
        `Threat check against URLhaus blacklist:\n${
          urlhausThreats.length > 0 ? `Potential threats: ${urlhausThreats.join(', ')}` : 'No threats detected in URLhaus blacklist.'
        }`;

      await fs.unlink(tempPcap).catch(err => console.error(`Failed to delete ${tempPcap}: ${err.message}`));

      return {
        content: [{ type: 'text', text: outputText }],
      };
    } catch (error) {
      console.error(`Error in check_threats: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Tool 5: Check a specific IP against URLhaus IOCs
server.tool(
  'check_ip_threats',
  'Check a given IP address against URLhaus blacklist for IOCs',
  {
    ip: z.string().regex(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/).describe('IP address to check (e.g., 192.168.1.1)'),
  },
  async (args) => {
    try {
      const { ip } = args;
      console.error(`Checking IP ${ip} against URLhaus blacklist`);

      const urlhausUrl = 'https://urlhaus.abuse.ch/downloads/text/';
      console.error(`Fetching URLhaus blacklist from ${urlhausUrl}`);
      let urlhausData;
      let isThreat = false;
      try {
        const response = await axios.get(urlhausUrl);
        console.error(`URLhaus response status: ${response.status}, length: ${response.data.length} chars`);
        console.error(`URLhaus raw data (first 200 chars): ${response.data.slice(0, 200)}`);
        const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
        urlhausData = [...new Set(response.data.split('\n')
          .map(line => {
            const match = line.match(ipRegex);
            return match ? match[0] : null;
          })
          .filter(ip => ip))];
        console.error(`URLhaus lookup successful: ${urlhausData.length} blacklist IPs fetched`);
        console.error(`Sample URLhaus IPs: ${urlhausData.slice(0, 5).join(', ') || 'None'}`);
        isThreat = urlhausData.includes(ip);
        console.error(`IP ${ip} checked against URLhaus: ${isThreat ? 'Threat found' : 'No threat found'}`);
      } catch (e) {
        console.error(`Failed to fetch URLhaus data: ${e.message}`);
        urlhausData = [];
      }

      const outputText = `IP checked: ${ip}\n\n` +
        `Threat check against URLhaus blacklist:\n${
          isThreat ? 'Potential threat detected in URLhaus blacklist.' : 'No threat detected in URLhaus blacklist.'
        }`;

      return {
        content: [{ type: 'text', text: outputText }],
      };
    } catch (error) {
      console.error(`Error in check_ip_threats: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Tool 6: Analyze an existing PCAP file for general context
server.tool(
  'analyze_pcap',
  'Analyze a PCAP file and provide general packet data as JSON for LLM analysis (supports TCP, UDP, HTTP, ICMP, ICMPv6)',
  {
    pcapPath: z.string().describe('Path to the PCAP file to analyze (e.g., ./demo.pcap)'),
    filter: z.string().optional().describe('Display filter to apply (e.g., "icmp" or "http")'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { pcapPath, filter } = args;
      console.error(`Analyzing PCAP file: ${pcapPath}`);

      // Check if file exists
      await fs.access(pcapPath);

      // Extract broad packet data
      const filterFlag = filter ? ` -Y "${filter}"` : '';
      const { stdout, stderr } = await execAsync(
        `${tsharkPath} -r "${pcapPath}" -T json -e frame.number -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport ${TSHARK_UDP_FIELDS} ${TSHARK_ICMP_FIELDS} ${TSHARK_ICMPV6_FIELDS} ${TSHARK_META_FIELDS} -e http.host -e http.request.uri${filterFlag}`,
        { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );
      if (stderr) console.error(`tshark stderr: ${stderr}`);
      let packets;
      try { packets = JSON.parse(stdout); } catch (e) { throw new Error(`Invalid tshark output: ${e.message}`); }

      const ips = [...new Set(packets.flatMap(p => [
        p._source?.layers['ip.src']?.[0],
        p._source?.layers['ip.dst']?.[0]
      ]).filter(ip => ip))];
      console.error(`Found ${ips.length} unique IPs: ${ips.join(', ')}`);

      const urls = packets
        .filter(p => p._source?.layers['http.host'] && p._source?.layers['http.request.uri'])
        .map(p => `http://${p._source.layers['http.host'][0]}${p._source.layers['http.request.uri'][0]}`);
      console.error(`Found ${urls.length} URLs: ${urls.join(', ') || 'None'}`);

      const protocols = [...new Set(packets.map(p => p._source?.layers['frame.protocols']?.[0]))].filter(p => p);
      console.error(`Found protocols: ${protocols.join(', ') || 'None'}`);

      const maxChars = 720000;
      let jsonString = JSON.stringify(packets);
      if (jsonString.length > maxChars) {
        const trimFactor = maxChars / jsonString.length;
        const trimCount = Math.max(1, Math.floor(packets.length * trimFactor));
        packets = packets.slice(0, trimCount);
        jsonString = JSON.stringify(packets);
        console.error(`Trimmed packets from ${packets.length} to ${trimCount} to fit ${maxChars} chars`);
      }

      const outputText = `Analyzed PCAP: ${pcapPath}\n\n` +
        `Unique IPs:\n${ips.join('\n')}\n\n` +
        `URLs:\n${urls.length > 0 ? urls.join('\n') : 'None'}\n\n` +
        `Protocols:\n${protocols.join('\n') || 'None'}\n\n` +
        `Packet Data (JSON for LLM):\n${jsonString}`;

      return {
        content: [{ type: 'text', text: outputText }],
      };
    } catch (error) {
      console.error(`Error in analyze_pcap: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Tool 7: Extract credentials from a PCAP file
server.tool(
    'extract_credentials',
    'Extract potential credentials (HTTP Basic Auth, FTP, Telnet) from a PCAP file for LLM analysis',
    {
      pcapPath: z.string().describe('Path to the PCAP file to analyze (e.g., ./demo.pcap)'),
      filter: z.string().optional().describe('Display filter to apply (e.g., "http" or "ftp")'),
    },
    async (args) => {
      try {
        const tsharkPath = await findTshark();
        const { pcapPath, filter } = args;
        console.error(`Extracting credentials from PCAP file: ${pcapPath}`);
        const filterFlag = filter ? ` -Y "${filter}"` : '';
  
        await fs.access(pcapPath);
  
        // Extract plaintext credentials
        const { stdout: plaintextOut } = await execAsync(
          `${tsharkPath} -r "${pcapPath}"${filterFlag} -T fields -e http.authbasic -e ftp.request.command -e ftp.request.arg -e telnet.data -e frame.number`,
          { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
        );

        // Extract Kerberos credentials
        const { stdout: kerberosOut } = await execAsync(
          `${tsharkPath} -r "${pcapPath}"${filterFlag} -T fields -e kerberos.CNameString -e kerberos.realm -e kerberos.cipher -e kerberos.type -e kerberos.msg_type -e frame.number`,
          { env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
        );

        const lines = plaintextOut.split('\n').filter(line => line.trim());
        const packets = lines.map(line => {
          const [authBasic, ftpCmd, ftpArg, telnetData, frameNumber] = line.split('\t');
          return {
            authBasic: authBasic || '',
            ftpCmd: ftpCmd || '',
            ftpArg: ftpArg || '',
            telnetData: telnetData || '',
            frameNumber: frameNumber || ''
          };
        });
  
        const credentials = {
          plaintext: [],
          encrypted: []
        };
  
        // Process HTTP Basic Auth
        packets.forEach(p => {
          if (p.authBasic) {
            const [username, password] = Buffer.from(p.authBasic, 'base64').toString().split(':');
            credentials.plaintext.push({ type: 'HTTP Basic Auth', username, password, frame: p.frameNumber });
          }
        });
  
        // Process FTP
        packets.forEach(p => {
          if (p.ftpCmd === 'USER') {
            credentials.plaintext.push({ type: 'FTP', username: p.ftpArg, password: '', frame: p.frameNumber });
          }
          if (p.ftpCmd === 'PASS') {
            const lastUser = credentials.plaintext.findLast(c => c.type === 'FTP' && !c.password);
            if (lastUser) lastUser.password = p.ftpArg;
          }
        });
  
        // Process Telnet
        packets.forEach(p => {
          if (p.telnetData) {
            const telnetStr = p.telnetData.trim();
            if (telnetStr.toLowerCase().includes('login:') || telnetStr.toLowerCase().includes('password:')) {
              credentials.plaintext.push({ type: 'Telnet Prompt', data: telnetStr, frame: p.frameNumber });
            } else if (telnetStr && !telnetStr.match(/[A-Z][a-z]+:/) && !telnetStr.includes(' ')) {
              const lastPrompt = credentials.plaintext.findLast(c => c.type === 'Telnet Prompt');
              if (lastPrompt && lastPrompt.data.toLowerCase().includes('login:')) {
                credentials.plaintext.push({ type: 'Telnet', username: telnetStr, password: '', frame: p.frameNumber });
              } else if (lastPrompt && lastPrompt.data.toLowerCase().includes('password:')) {
                const lastUser = credentials.plaintext.findLast(c => c.type === 'Telnet' && !c.password);
                if (lastUser) lastUser.password = telnetStr;
                else credentials.plaintext.push({ type: 'Telnet', username: '', password: telnetStr, frame: p.frameNumber });
              }
            }
          }
        });

        // Process Kerberos credentials
        const kerberosLines = kerberosOut.split('\n').filter(line => line.trim());
        kerberosLines.forEach(line => {
          const [cname, realm, cipher, type, msgType, frameNumber] = line.split('\t');
          
          if (cipher && type) {
            let hashFormat = '';
            // Format hash based on message type
            if (msgType === '10' || msgType === '30') { // AS-REQ or TGS-REQ
              hashFormat = '$krb5pa$23$';
              if (cname) hashFormat += `${cname}$`;
              if (realm) hashFormat += `${realm}$`;
              hashFormat += cipher;
            } else if (msgType === '11') { // AS-REP
              hashFormat = '$krb5asrep$23$';
              if (cname) hashFormat += `${cname}@`;
              if (realm) hashFormat += `${realm}$`;
              hashFormat += cipher;
            }

            if (hashFormat) {
              credentials.encrypted.push({
                type: 'Kerberos',
                hash: hashFormat,
                username: cname || 'unknown',
                realm: realm || 'unknown',
                frame: frameNumber,
                crackingMode: msgType === '11' ? 'hashcat -m 18200' : 'hashcat -m 7500'
              });
            }
          }
        });

        console.error(`Found ${credentials.plaintext.length} plaintext and ${credentials.encrypted.length} encrypted credentials`);
  
        const outputText = `Analyzed PCAP: ${pcapPath}\n\n` +
          `Plaintext Credentials:\n${credentials.plaintext.length > 0 ? 
            credentials.plaintext.map(c => 
              c.type === 'Telnet Prompt' ? 
                `${c.type}: ${c.data} (Frame ${c.frame})` : 
                `${c.type}: ${c.username}:${c.password} (Frame ${c.frame})`
            ).join('\n') : 
            'None'}\n\n` +
          `Encrypted/Hashed Credentials:\n${credentials.encrypted.length > 0 ?
            credentials.encrypted.map(c =>
              `${c.type}: User=${c.username} Realm=${c.realm} (Frame ${c.frame})\n` +
              `Hash=${c.hash}\n` +
              `Cracking Command: ${c.crackingMode}\n`
            ).join('\n') :
            'None'}\n\n` +
          `Note: Encrypted credentials can be cracked using tools like John the Ripper or hashcat.\n` +
          `For Kerberos hashes:\n` +
          `- AS-REQ/TGS-REQ: hashcat -m 7500 or john --format=krb5pa-md5\n` +
          `- AS-REP: hashcat -m 18200 or john --format=krb5asrep`;
  
        return {
          content: [{ type: 'text', text: outputText }],
        };
      } catch (error) {
        console.error(`Error in extract_credentials: ${error.message}`);
        return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
      }
    }
  );

// Tool 8: Extract ICMP payload data from a PCAP file
server.tool(
  'extract_icmp_data',
  'Extract and decode ICMP payload data from a PCAP file, useful for finding hidden data in ICMP packets',
  {
    pcapPath: z.string().describe('Path to the PCAP file to analyze (e.g., ./demo.pcap)'),
    filter: z.string().optional().describe('Display filter to apply (e.g., "icmp" or "icmp.type==8")'),
  },
  async (args) => {
    try {
      const { pcapPath, filter } = args;
      const payloads = await extractRawIcmpPayloads(pcapPath, filter);
      const frameNumbers = Object.keys(payloads).sort((a, b) => a - b);

      let outputText = `ICMP Payload Analysis for: ${pcapPath}\n\n`;
      if (frameNumbers.length === 0) {
        outputText += 'No ICMP payload data found.\n';
      } else {
        outputText += `Found ICMP payloads in ${frameNumbers.length} frame(s):\n\n`;
        for (const frameNum of frameNumbers) {
          const hex = payloads[frameNum];
          const ascii = Buffer.from(hex, 'hex').toString('utf8');
          const base64 = Buffer.from(hex, 'hex').toString('base64');
          outputText += `Frame ${frameNum}:\n`;
          outputText += `  Hex (${hex.length / 2} bytes): ${hex}\n`;
          outputText += `  ASCII: ${ascii}\n`;
          outputText += `  Base64: ${base64}\n\n`;
        }
      }

      return {
        content: [{ type: 'text', text: outputText }],
      };
    } catch (error) {
      console.error(`Error in extract_icmp_data: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

// Add prompts for each tool
server.prompt(
  'capture_packets_prompt',
  {
    interface: z.string().optional().describe('Network interface to capture from'),
    duration: z.number().optional().describe('Duration in seconds to capture'),
  },
  ({ interface = 'en0', duration = 5 }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze the network traffic on interface ${interface} for ${duration} seconds and provide insights about:
1. The types of traffic observed
2. Any notable patterns or anomalies
3. Key IP addresses and ports involved
4. Potential security concerns`
      }
    }]
  })
);

server.prompt(
  'summary_stats_prompt',
  {
    interface: z.string().optional().describe('Network interface to capture from'),
    duration: z.number().optional().describe('Duration in seconds to capture'),
  },
  ({ interface = 'en0', duration = 5 }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please provide a summary of network traffic statistics from interface ${interface} over ${duration} seconds, focusing on:
1. Protocol distribution
2. Traffic volume by protocol
3. Notable patterns in protocol usage
4. Potential network health indicators`
      }
    }]
  })
);

server.prompt(
  'conversations_prompt',
  {
    interface: z.string().optional().describe('Network interface to capture from'),
    duration: z.number().optional().describe('Duration in seconds to capture'),
  },
  ({ interface = 'en0', duration = 5 }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze network conversations on interface ${interface} for ${duration} seconds and identify:
1. Most active IP pairs
2. Conversation durations and data volumes
3. Unusual communication patterns
4. Potential indicators of network issues`
      }
    }]
  })
);

server.prompt(
  'check_threats_prompt',
  {
    interface: z.string().optional().describe('Network interface to capture from'),
    duration: z.number().optional().describe('Duration in seconds to capture'),
  },
  ({ interface = 'en0', duration = 5 }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze traffic on interface ${interface} for ${duration} seconds and check for security threats:
1. Compare captured IPs against URLhaus blacklist
2. Identify potential malicious activity
3. Highlight any concerning patterns
4. Provide security recommendations`
      }
    }]
  })
);

server.prompt(
  'check_ip_threats_prompt',
  {
    ip: z.string().describe('IP address to check'),
  },
  ({ ip }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze the following IP address (${ip}) for potential security threats:
1. Check against URLhaus blacklist
2. Evaluate the IP's reputation
3. Identify any known malicious activity
4. Provide security recommendations`
      }
    }]
  })
);

server.prompt(
  'analyze_pcap_prompt',
  {
    pcapPath: z.string().describe('Path to the PCAP file'),
  },
  ({ pcapPath }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze the PCAP file at ${pcapPath} and provide insights about:
1. Overall traffic patterns
2. Unique IPs and their interactions
3. Protocols and services used (including ICMP)
4. Notable events or anomalies
5. Potential security concerns`
      }
    }]
  })
);

server.prompt(
  'extract_credentials_prompt',
  {
    pcapPath: z.string().describe('Path to the PCAP file'),
  },
  ({ pcapPath }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze the PCAP file at ${pcapPath} for potential credential exposure:
1. Look for plaintext credentials (HTTP Basic Auth, FTP, Telnet)
2. Identify Kerberos authentication attempts
3. Extract any hashed credentials
4. Provide security recommendations for credential handling`
      }
    }]
  })
);

server.prompt(
  'extract_icmp_data_prompt',
  {
    pcapPath: z.string().describe('Path to the PCAP file'),
  },
  ({ pcapPath }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze the PCAP file at ${pcapPath} for ICMP data:
1. Extract and decode any ICMP payloads
2. Look for hidden messages or data in ICMP packets
3. Analyze ICMP types and codes used
4. Check for ICMP tunneling or data exfiltration`
      }
    }]
  })
);

server.tool(
  'follow_tcp_stream',
  'Follow a TCP stream from a PCAP file and return the reconstructed conversation for protocol analysis',
  {
    pcapPath: z.string().describe('Path to the PCAP file to analyze'),
    stream: z.number().int().min(0).describe('TCP stream index to follow (e.g., 0, 1, 2...)'),
    mode: z.enum(['ascii', 'hex', 'raw']).optional().default('ascii').describe('Output mode: ascii readable text, hex dump, or raw binary'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { pcapPath, stream, mode } = args;
      await fs.access(pcapPath);
      const { stdout } = await execAsync(
        `${tsharkPath} -r "${pcapPath}" -q -z "follow,tcp,${mode},${stream}"`,
        { maxBuffer: 50 * 1024 * 1024, env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );
      return {
        content: [{ type: 'text', text: `TCP Stream ${stream} (${mode} mode):\n\n${stdout}` }],
      };
    } catch (error) {
      console.error(`Error in follow_tcp_stream: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

server.prompt(
  'follow_tcp_stream_prompt',
  {
    pcapPath: z.string().describe('Path to the PCAP file'),
    stream: z.number().describe('TCP stream index to follow'),
  },
  ({ pcapPath, stream = 0 }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze TCP stream ${stream} from ${pcapPath} and describe:
1. The protocol and application-layer conversation
2. Any notable data transfers or commands
3. Security implications of the communication`
      }
    }]
  })
);

server.tool(
  'get_expert_info',
  'Extract expert information (errors, warnings, notes, malformed packets, chats) from a PCAP file for anomaly detection',
  {
    pcapPath: z.string().describe('Path to the PCAP file to analyze'),
    filter: z.string().optional().describe('Display filter to narrow scope (e.g., "http" or "tcp.port==80")'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { pcapPath, filter } = args;
      await fs.access(pcapPath);
      const filterFlag = filter ? ` -Y "${filter}"` : '';
      const { stdout } = await execAsync(
        `${tsharkPath} -r "${pcapPath}"${filterFlag} -z expert`,
        { maxBuffer: 10 * 1024 * 1024, env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );
      const severityCounts = {};
      for (const line of stdout.split('\n')) {
        const match = line.match(/^\s*(Error|Warning|Note|Chat)\s+/i);
        if (match) severityCounts[match[1]] = (severityCounts[match[1]] || 0) + 1;
      }
      const summary = Object.entries(severityCounts).map(([k, v]) => `  ${k}: ${v}`).join('\n');
      return {
        content: [{
          type: 'text',
          text: `Expert Info for: ${pcapPath}\n\nSummary:\n${summary || '  None'}\n\nDetails:\n${stdout}`,
        }],
      };
    } catch (error) {
      console.error(`Error in get_expert_info: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

server.prompt(
  'get_expert_info_prompt',
  {
    pcapPath: z.string().describe('Path to the PCAP file'),
  },
  ({ pcapPath }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze the expert info from ${pcapPath} and highlight:
1. Errors and malformed packets that indicate issues
2. Warnings that suggest potential security events
3. Overall network health assessment`
      }
    }]
  })
);

server.tool(
  'extract_http_objects',
  'Extract HTTP objects (files, images, scripts, documents) from a PCAP file and compute SHA256 hashes for malware analysis',
  {
    pcapPath: z.string().describe('Path to the PCAP file to analyze'),
    filter: z.string().optional().describe('Display filter to narrow extraction scope'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { pcapPath, filter } = args;
      await fs.access(pcapPath);
      const filterFlag = filter ? ` -Y "${filter}"` : '';
      const tmpDir = `http_objects_${Date.now()}`;
      await fs.mkdir(tmpDir, { recursive: true });
      try {
        await execAsync(
          `${tsharkPath} -r "${pcapPath}"${filterFlag} --export-objects "http,${tmpDir}"`,
          { maxBuffer: 50 * 1024 * 1024, env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
        );
      } catch (e) {
        if (!e.message.includes('export-objects')) throw e;
      }
      const files = await fs.readdir(tmpDir).catch(() => []);
      const fileInfos = [];
      for (const file of files) {
        const filePath = path.join(tmpDir, file);
        try {
          const stat = await fs.stat(filePath);
          const content = await fs.readFile(filePath);
          const hash = crypto.createHash('sha256').update(content).digest('hex');
          fileInfos.push({ filename: file, size: stat.size, sha256: hash });
        } catch (e) {
          console.error(`Failed to process extracted file ${file}: ${e.message}`);
        }
      }
      for (const file of files) {
        await fs.unlink(path.join(tmpDir, file)).catch(() => {});
      }
      await fs.rmdir(tmpDir).catch(() => {});
      return {
        content: [{
          type: 'text',
          text: `HTTP Objects extracted from: ${pcapPath}\n\n${fileInfos.length > 0 ? fileInfos.map(f => `  ${f.filename}\n    Size: ${f.size} bytes\n    SHA256: ${f.sha256}`).join('\n\n') : 'No HTTP objects found to extract.'}`,
        }],
      };
    } catch (error) {
      console.error(`Error in extract_http_objects: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

server.prompt(
  'extract_http_objects_prompt',
  {
    pcapPath: z.string().describe('Path to the PCAP file'),
  },
  ({ pcapPath }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze the HTTP objects extracted from ${pcapPath}:
1. Identify any suspicious files (executables, scripts, archives)
2. Check SHA256 hashes against known malware databases
3. Assess the risk level of downloaded content`
      }
    }]
  })
);

server.tool(
  'get_pcap_statistics',
  'Get protocol hierarchy, endpoint, or conversation statistics from a PCAP file for traffic profiling',
  {
    pcapPath: z.string().describe('Path to the PCAP file to analyze'),
    type: z.enum(['protocol-hierarchy', 'endpoints', 'conversations']).optional().default('protocol-hierarchy').describe('Type of statistics to compute'),
    filter: z.string().optional().describe('Display filter to scope statistics'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { pcapPath, type, filter } = args;
      await fs.access(pcapPath);
      const filterFlag = filter ? ` -Y "${filter}"` : '';
      let statFlag;
      switch (type) {
        case 'protocol-hierarchy': statFlag = '-z io,phs'; break;
        case 'endpoints': statFlag = '-z endpoints,ip'; break;
        case 'conversations': statFlag = '-z conv,tcp'; break;
      }
      const { stdout } = await execAsync(
        `${tsharkPath} -r "${pcapPath}"${filterFlag} -q ${statFlag}`,
        { maxBuffer: 10 * 1024 * 1024, env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );
      return {
        content: [{ type: 'text', text: `Statistics (${type}) for: ${pcapPath}\n\n${stdout}` }],
      };
    } catch (error) {
      console.error(`Error in get_pcap_statistics: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

server.prompt(
  'get_pcap_statistics_prompt',
  {
    pcapPath: z.string().describe('Path to the PCAP file'),
    type: z.string().optional().describe('Type of statistics'),
  },
  ({ pcapPath, type = 'protocol-hierarchy' }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze the ${type} statistics from ${pcapPath} and describe:
1. The dominant protocols and traffic patterns
2. Any unusual protocol usage or anomalies
3. Overall traffic profile and what it reveals about the host`
      }
    }]
  })
);

server.tool(
  'get_conversation_timeline',
  'Generate a chronological timeline of network events from a PCAP file, grouped by time windows for incident reconstruction',
  {
    pcapPath: z.string().describe('Path to the PCAP file to analyze'),
    interval: z.number().positive().optional().default(60).describe('Time interval in seconds for each summary window'),
    filter: z.string().optional().describe('Display filter to scope the timeline'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { pcapPath, interval, filter } = args;
      await fs.access(pcapPath);
      const filterFlag = filter ? ` -Y "${filter}"` : '';
      const { stdout } = await execAsync(
        `${tsharkPath} -r "${pcapPath}"${filterFlag} -T json -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e _ws.col.Protocol -e frame.protocols -e tcp.srcport -e tcp.dstport -e http.request.method -e http.request.uri -e http.response.code -e dns.qry.name -e icmp.type -e tls.handshake.extensions_server_name`,
        { maxBuffer: 50 * 1024 * 1024, env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );
      let packets;
      try { packets = JSON.parse(stdout); } catch (e) { throw new Error(`Invalid tshark output: ${e.message}`); }
      if (packets.length === 0) return { content: [{ type: 'text', text: 'No packets found.' }] };
      const times = packets.map(p => parseFloat(p._source?.layers['frame.time_epoch']?.[0])).filter(t => !isNaN(t));
      if (times.length === 0) return { content: [{ type: 'text', text: 'No timestamp data available.' }] };
      const startTime = Math.min(...times);
      const endTime = Math.max(...times);
      const windows = {};
      for (const p of packets) {
        const t = parseFloat(p._source?.layers['frame.time_epoch']?.[0]);
        if (isNaN(t)) continue;
        const windowStart = Math.floor((t - startTime) / interval) * interval;
        const key = `${windowStart}-${windowStart + interval}`;
        if (!windows[key]) windows[key] = { start: windowStart, packets: [] };
        windows[key].packets.push(p);
      }
      let timeline = `Timeline (${interval}s windows) from ${new Date(startTime * 1000).toISOString()} to ${new Date(endTime * 1000).toISOString()}\n\n`;
      for (const [key, win] of Object.entries(windows).sort((a, b) => a[1].start - b[1].start)) {
        const timeStr = new Date((startTime + win.start) * 1000).toISOString();
        timeline += `[${timeStr}] Window +${win.start}s to +${win.start + interval}s (${win.packets.length} packets)\n`;
        const protocols = {};
        const conversations = {};
        const dnsQueries = new Set();
        const httpReqs = [];
        const httpResps = [];
        const tlsSnis = new Set();
        const icmpTypes = new Set();
        for (const p of win.packets) {
          const layers = p._source?.layers;
          const proto = layers['_ws.col.Protocol']?.[0] || layers['frame.protocols']?.[0] || 'unknown';
          protocols[proto] = (protocols[proto] || 0) + 1;
          const src = `${layers['ip.src']?.[0]}:${layers['tcp.srcport']?.[0] || '*'}`;
          const dst = `${layers['ip.dst']?.[0]}:${layers['tcp.dstport']?.[0] || '*'}`;
          if (src && dst) conversations[`${src} → ${dst}`] = (conversations[`${src} → ${dst}`] || 0) + 1;
          if (layers['dns.qry.name']?.[0]) dnsQueries.add(layers['dns.qry.name'][0]);
          if (layers['http.request.method']?.[0]) httpReqs.push(`${layers['http.request.method'][0]} ${layers['http.request.uri']?.[0] || ''}`);
          if (layers['http.response.code']?.[0]) httpResps.push(`HTTP ${layers['http.response.code'][0]}`);
          if (layers['tls.handshake.extensions_server_name']?.[0]) tlsSnis.add(layers['tls.handshake.extensions_server_name'][0]);
          if (layers['icmp.type']?.[0]) icmpTypes.add(`type ${layers['icmp.type'][0]}`);
        }
        const topConvs = Object.entries(conversations).sort((a, b) => b[1] - a[1]).slice(0, 5);
        timeline += `  Protocols: ${Object.entries(protocols).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([p, c]) => `${p}(${c})`).join(', ')}\n`;
        timeline += `  Top Conversations:\n${topConvs.map(([c, n]) => `    ${c} (${n} pkts)`).join('\n')}\n`;
        if (dnsQueries.size > 0) timeline += `  DNS Queries: ${[...dnsQueries].slice(0, 10).join(', ')}\n`;
        if (httpReqs.length > 0) timeline += `  HTTP Requests: ${httpReqs.slice(0, 5).join(', ')}\n`;
        if (httpResps.length > 0) timeline += `  HTTP Responses: ${[...new Set(httpResps)].join(', ')}\n`;
        if (tlsSnis.size > 0) timeline += `  TLS SNI: ${[...tlsSnis].join(', ')}\n`;
        if (icmpTypes.size > 0) timeline += `  ICMP: ${[...icmpTypes].join(', ')}\n`;
        timeline += '\n';
      }
      if (timeline.length > 720000) timeline = timeline.slice(0, 720000) + '\n\n[Truncated due to length...]';
      return {
        content: [{ type: 'text', text: timeline }],
      };
    } catch (error) {
      console.error(`Error in get_conversation_timeline: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

server.prompt(
  'get_conversation_timeline_prompt',
  {
    pcapPath: z.string().describe('Path to the PCAP file'),
  },
  ({ pcapPath }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze the conversation timeline from ${pcapPath} and provide:
1. A chronological narrative of network events
2. Key phases of activity (normal traffic vs. malicious)
3. Timeline of C2 communication or data exfiltration
4. Recommendations for further investigation`
      }
    }]
  })
);

server.tool(
  'search_payloads',
  'Search for patterns (strings, hex) in TCP packet payloads from a PCAP file, useful for finding exfiltrated data or C2 commands',
  {
    pcapPath: z.string().describe('Path to the PCAP file to analyze'),
    pattern: z.string().describe('Pattern to search for in packet payloads (case-insensitive string match)'),
    filter: z.string().optional().describe('Display filter to narrow search scope (e.g., "http" or "ip.addr==1.2.3.4")'),
    context: z.number().int().min(0).max(50).optional().default(0).describe('Number of surrounding packets to include as context'),
    maxResults: z.number().int().min(1).max(100).optional().default(20).describe('Maximum number of matching frames to return'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { pcapPath, pattern, filter, context, maxResults } = args;
      await fs.access(pcapPath);
      const filterPrefix = filter ? `${filter} and ` : '';
      const hexPattern = Buffer.from(pattern, 'utf8').toString('hex').replace(/(..)/g, '$1:').replace(/:$/, '');
      const { stdout } = await execAsync(
        `${tsharkPath} -r "${pcapPath}" -Y "${filterPrefix}frame contains ${hexPattern}" -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e _ws.col.Protocol`,
        { maxBuffer: 50 * 1024 * 1024, env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );
      const lines = stdout.trim().split('\n').filter(l => l.trim());
      let output = `Search results for "${pattern}" in: ${pcapPath}\n\n`;
      if (lines.length === 0) {
        output += 'No matches found.';
      } else {
        output += `Found ${lines.length} matching packet(s). Showing first ${Math.min(lines.length, maxResults)}:\n\n`;
        const matchFrames = lines.map(l => l.split('\t')[0]).filter(Boolean);
        for (let i = 0; i < Math.min(matchFrames.length, maxResults); i++) {
          output += `Frame ${matchFrames[i]}: ${lines[i]}\n`;
          if (context > 0) {
            const startFrame = Math.max(1, parseInt(matchFrames[i]) - context);
            const endFrame = parseInt(matchFrames[i]) + context;
            const { stdout: hexOut } = await execAsync(
              `${tsharkPath} -r "${pcapPath}" -Y "frame.number >= ${startFrame} && frame.number <= ${endFrame}" -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Protocol`,
              { maxBuffer: 10 * 1024 * 1024, env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
            );
            output += `  Context (${context} before/after):\n${hexOut.split('\n').map(l => `    ${l}`).join('\n').slice(0, 2000)}\n`;
          }
          output += '\n';
        }
        if (lines.length > maxResults) output += `... and ${lines.length - maxResults} more matches\n`;
      }
      return {
        content: [{ type: 'text', text: output }],
      };
    } catch (error) {
      console.error(`Error in search_payloads: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

server.prompt(
  'search_payloads_prompt',
  {
    pcapPath: z.string().describe('Path to the PCAP file'),
    pattern: z.string().describe('Pattern to search for'),
  },
  ({ pcapPath, pattern }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze the search results for pattern "${pattern}" in ${pcapPath}:
1. Identify context and significance of each match
2. Correlate matches with other network events
3. Assess if this indicates malicious activity or data exfiltration`
      }
    }]
  })
);

server.tool(
  'extract_tls_metadata',
  'Extract TLS metadata (SNI, certificate common names, TLS versions) from a PCAP file for identifying encrypted C2 channels',
  {
    pcapPath: z.string().describe('Path to the PCAP file to analyze'),
    filter: z.string().optional().describe('Display filter to scope extraction (e.g., "tls")'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { pcapPath, filter } = args;
      await fs.access(pcapPath);
      const filterFlag = filter ? ` -Y "${filter}"` : '';
      const { stdout } = await execAsync(
        `${tsharkPath} -r "${pcapPath}"${filterFlag} -T json -e frame.number -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tls.handshake.extensions_server_name -e tls.handshake.version`,
        { maxBuffer: 50 * 1024 * 1024, env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );
      let packets;
      try { packets = JSON.parse(stdout); } catch (e) { throw new Error(`Invalid tshark output: ${e.message}`); }
      const connections = {};
      for (const p of packets) {
        const layers = p._source?.layers;
        const src = `${layers['ip.src']?.[0]}:${layers['tcp.srcport']?.[0]}`;
        const dst = `${layers['ip.dst']?.[0]}:${layers['tcp.dstport']?.[0]}`;
        const key = `${src} → ${dst}`;
        if (!connections[key]) connections[key] = { src, dst, sni: new Set(), versions: new Set(), frames: [] };
        connections[key].frames.push(layers['frame.number']?.[0]);
        if (layers['tls.handshake.extensions_server_name']?.[0]) connections[key].sni.add(layers['tls.handshake.extensions_server_name'][0]);
        if (layers['tls.handshake.version']?.[0]) connections[key].versions.add(layers['tls.handshake.version'][0]);
      }
      let output = `TLS Metadata for: ${pcapPath}\n\n`;
      const connKeys = Object.keys(connections);
      if (connKeys.length === 0) {
        output += 'No TLS connections found.';
      } else {
        output += `Found ${connKeys.length} TLS connection(s):\n\n`;
        for (const [key, conn] of Object.entries(connections)) {
          output += `  ${conn.dst}\n`;
          output += `    Frames: ${conn.frames[0]}–${conn.frames[conn.frames.length - 1]}\n`;
          if (conn.sni.size > 0) output += `    SNI: ${[...conn.sni].join(', ')}\n`;

          if (conn.versions.size > 0) output += `    TLS Versions: ${[...conn.versions].join(', ')}\n`;
          output += '\n';
        }
      }
      return {
        content: [{ type: 'text', text: output }],
      };
    } catch (error) {
      console.error(`Error in extract_tls_metadata: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

server.prompt(
  'extract_tls_metadata_prompt',
  {
    pcapPath: z.string().describe('Path to the PCAP file'),
  },
  ({ pcapPath }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze the TLS metadata from ${pcapPath} and identify:
1. Suspicious TLS connections to unusual domains
2. Self-signed certificates or certificate anomalies
3. Encrypted C2 channels or data exfiltration
4. Overall TLS security posture`
      }
    }]
  })
);

server.tool(
  'get_endpoint_stats',
  'List all unique IP endpoints with packet counts, traffic direction, and protocol breakdown from a PCAP file',
  {
    pcapPath: z.string().describe('Path to the PCAP file to analyze'),
    filter: z.string().optional().describe('Display filter to scope endpoint analysis'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { pcapPath, filter } = args;
      await fs.access(pcapPath);
      const filterFlag = filter ? ` -Y "${filter}"` : '';
      const { stdout: ipsStdout } = await execAsync(
        `${tsharkPath} -r "${pcapPath}"${filterFlag} -T fields -e ip.src -e ip.dst -e _ws.col.Protocol`,
        { maxBuffer: 50 * 1024 * 1024, env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
      );
      const lines = ipsStdout.trim().split('\n').filter(l => l.trim());
      const ipStats = {};
      for (const line of lines) {
        const [src, dst, proto] = line.split('\t');
        if (src && !ipStats[src]) ipStats[src] = { asSrc: 0, asDst: 0, protocols: new Set() };
        if (dst && !ipStats[dst]) ipStats[dst] = { asSrc: 0, asDst: 0, protocols: new Set() };
        if (src) { ipStats[src].asSrc++; if (proto) ipStats[src].protocols.add(proto); }
        if (dst) { ipStats[dst].asDst++; if (proto) ipStats[dst].protocols.add(proto); }
      }
      const sorted = Object.entries(ipStats).sort((a, b) => (b[1].asSrc + b[1].asDst) - (a[1].asSrc + a[1].asDst));
      let output = `Endpoint Statistics for: ${pcapPath}\n\n`;
      output += `${'IP'.padEnd(17)} ${'Src Pkts'.padStart(9)} ${'Dst Pkts'.padStart(9)} ${'Total'.padStart(8)}  Protocol Mix\n`;
      output += `${'─'.repeat(17)} ${'─'.repeat(9)} ${'─'.repeat(9)} ${'─'.repeat(8)}  ${'─'.repeat(20)}\n`;
      for (const [ip, stats] of sorted) {
        const total = stats.asSrc + stats.asDst;
        output += `${ip.padEnd(17)} ${String(stats.asSrc).padStart(9)} ${String(stats.asDst).padStart(9)} ${String(total).padStart(8)}  ${[...stats.protocols].slice(0, 5).join(', ')}\n`;
      }
      output += `\nTotal unique IPs: ${sorted.length}\n`;
      return {
        content: [{ type: 'text', text: output }],
      };
    } catch (error) {
      console.error(`Error in get_endpoint_stats: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

server.prompt(
  'get_endpoint_stats_prompt',
  {
    pcapPath: z.string().describe('Path to the PCAP file'),
  },
  ({ pcapPath }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please analyze the endpoint statistics from ${pcapPath} and identify:
1. Most active hosts and their roles
2. Unusual communication patterns between endpoints
3. Potential beaconing or C2 traffic indicators
4. Hosts that warrant deeper investigation`
      }
    }]
  })
);

server.tool(
  'generate_incident_report',
  'Generate a comprehensive incident report from a PCAP file with executive summary, IOCs, timeline, Wireshark verification steps, and remediation recommendations',
  {
    pcapPath: z.string().describe('Path to the PCAP file to analyze'),
    outputPath: z.string().optional().describe('Path to save the report (optional, prints to output if not provided)'),
    focus: z.string().optional().describe('Optional display filter to focus analysis (e.g., "ip.addr==1.2.3.4")'),
  },
  async (args) => {
    try {
      const tsharkPath = await findTshark();
      const { pcapPath, outputPath, focus } = args;
      await fs.access(pcapPath);
      const fname = path.basename(pcapPath);
      const filterFlag = focus ? ` -Y "${focus}"` : '';
      const filterDesc = focus ? ` (filtered: ${focus})` : '';

      let report = '';
      const dateStr = new Date().toISOString().split('T')[0];

      // ── File info ──
      const stat = await fs.stat(pcapPath);
      const fileSizeMB = (stat.size / (1024 * 1024)).toFixed(1);

      let packetCount = '?';
      try {
        const { stdout: cnt } = await execAsync(
          `${tsharkPath} -r "${pcapPath}"${filterFlag} -T fields -e frame.number`,
          { maxBuffer: 10 * 1024 * 1024, env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
        );
        packetCount = cnt.trim().split('\n').filter(l => l.trim()).length.toString();
      } catch {}

      // ── Expert info (top errors/warnings) ──
      let expertSummary = '';
      let expertAnomalies = [];
      try {
        const { stdout: expert } = await execAsync(
          `${tsharkPath} -r "${pcapPath}"${filterFlag} -T fields -e frame.number -e _ws.expert.message -e _ws.expert.severity -e _ws.expert.group`,
          { maxBuffer: 50 * 1024 * 1024, env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
        );
        const sevMap = { '0': 'Chat', '1': 'Note', '2': 'Warning', '3': 'Error', Chat: 'Chat', Note: 'Note', Warning: 'Warning', Error: 'Error' };
        const expertLines = expert.trim().split('\n').filter(l => l.trim() && l.includes('\t') && !l.includes('tshark:'));
        const severityCounts = { Error: 0, Warning: 0, Note: 0, Chat: 0 };
        const uniqueMessages = {};
        for (const line of expertLines) {
          const parts = line.split('\t');
          const rawSev = (parts[2] || '').trim();
          const sev = sevMap[rawSev] || 'Note';
          const msg = (parts[1] || '').trim();
          if (sev === 'Error' || sev === 3) severityCounts.Error++;
          else if (sev === 'Warning' || sev === 2) severityCounts.Warning++;
          else if (sev === 'Note' || sev === 1) severityCounts.Note++;
          else severityCounts.Chat++;
          if (msg && !uniqueMessages[msg]) uniqueMessages[msg] = { severity: sev === 3 ? 'Error' : sev === 2 ? 'Warning' : 'Note', count: 1 };
          else if (msg && uniqueMessages[msg]) uniqueMessages[msg].count++;
        }
        expertSummary = `Errors: ${severityCounts.Error}, Warnings: ${severityCounts.Warning}, Notes: ${severityCounts.Note}`;
        expertAnomalies = Object.entries(uniqueMessages)
          .sort((a, b) => b[1].count - a[1].count)
          .slice(0, 10)
          .map(([msg, info]) => ({ msg, severity: info.severity, count: info.count }));
      } catch {}

      // ── Endpoint stats (top talkers) ──
      let topTalkers = [];
      let totalIPs = 0;
      try {
        const { stdout: ips } = await execAsync(
          `${tsharkPath} -r "${pcapPath}"${filterFlag} -T fields -e ip.src -e ip.dst -e _ws.col.Protocol`,
          { maxBuffer: 50 * 1024 * 1024, env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
        );
        const ipLines = ips.trim().split('\n').filter(l => l.trim());
        const ipStats = {};
        for (const line of ipLines) {
          const [src, dst, proto] = line.split('\t');
          if (src && !ipStats[src]) ipStats[src] = { asSrc: 0, asDst: 0, protocols: new Set() };
          if (dst && !ipStats[dst]) ipStats[dst] = { asSrc: 0, asDst: 0, protocols: new Set() };
          if (src) { ipStats[src].asSrc++; if (proto) ipStats[src].protocols.add(proto); }
          if (dst) { ipStats[dst].asDst++; if (proto) ipStats[dst].protocols.add(proto); }
        }
        const sorted = Object.entries(ipStats).sort((a, b) => (b[1].asSrc + b[1].asDst) - (a[1].asSrc + a[1].asDst));
        totalIPs = sorted.length;
        topTalkers = sorted.slice(0, 10).map(([ip, st]) => ({ ip, total: st.asSrc + st.asDst, src: st.asSrc, dst: st.asDst, protos: [...st.protocols].slice(0, 5).join(', ').replace(/\n/g, ', ') }));
      } catch {}

      // ── Timeline summary ──
      let timelineSummary = '';
      let timelineEvents = [];
      try {
        const { stdout: tl } = await execAsync(
          `${tsharkPath} -r "${pcapPath}"${filterFlag} -T fields -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e _ws.col.Protocol`,
          { maxBuffer: 50 * 1024 * 1024, env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
        );
        const tlLines = tl.trim().split('\n').filter(l => l.trim());
        if (tlLines.length > 0) {
          const first = tlLines[0].split('\t');
          const last = tlLines[tlLines.length - 1].split('\t');
          const duration = last[1] && first[1] ? (parseFloat(last[1]) - parseFloat(first[1])).toFixed(1) : '?';
          timelineSummary = `${tlLines.length} packets over ${duration}s`;
          // Key time-based events (sample at intervals)
          const interval = Math.max(1, Math.floor(tlLines.length / 10));
          for (let i = 0; i < tlLines.length; i += interval) {
            const parts = tlLines[i].split('\t');
            if (parts[1]) timelineEvents.push({ time: parts[1], count: 1 });
          }
        }
      } catch {}

      // ── TLS metadata (suspicious SNIs) ──
      let tlsConnections = [];
      let suspiciousSNIs = [];
      try {
        const { stdout: tlsJson } = await execAsync(
          `${tsharkPath} -r "${pcapPath}"${filterFlag} -Y "tls.handshake.type == 1" -T json -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tls.handshake.extensions_server_name -e tls.handshake.version`,
          { maxBuffer: 50 * 1024 * 1024, env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
        );
        let packets;
        try { packets = JSON.parse(tlsJson); } catch {}
        if (packets && packets.length > 0) {
          const connMap = {};
          for (const p of packets) {
            const layers = p._source?.layers;
            if (!layers) continue;
            const srcIp = layers['ip.src']?.[0];
            const dstIp = layers['ip.dst']?.[0];
            const srcPort = layers['tcp.srcport']?.[0];
            const dstPort = layers['tcp.dstport']?.[0];
            if (!srcIp || !dstIp) continue;
            const src = `${srcIp}:${srcPort || '?'}`;
            const dst = `${dstIp}:${dstPort || '?'}`;
            const sni = layers['tls.handshake.extensions_server_name']?.[0];
            const ver = layers['tls.handshake.version']?.[0];
            const key = `${srcIp}→${dstIp}`;
            if (!connMap[key]) connMap[key] = { src, dst, sni: new Set(), versions: new Set(), frames: [] };
            connMap[key].frames.push(layers['frame.number']?.[0]);
            if (sni) connMap[key].sni.add(sni);
            if (ver) connMap[key].versions.add(ver);
          }
          tlsConnections = Object.entries(connMap).map(([key, c]) => ({
            dst: c.dst,
            sni: [...c.sni].join(', '),
            version: [...c.versions].join(', '),
            frames: c.frames.length > 0 ? `${c.frames[0]}–${c.frames[c.frames.length - 1]}` : '?',
            frameCount: c.frames.length,
          }));

          const suspiciousKeywords = ['\.xyz', '\.top', '\.club', '\.download', '\.work', '\.gq', '\.ml', '\.cf', 'tk', 'ddns', 'duckdns', 'no-ip', 'servehttp', 'serveftp', 'dynamic-dns', 'redirectme'];
          const c2Snis = ['whitepepper', 'dyngate', 'trycloudflare', 'communicationfirewall-security', 'holiday-forever', 'megafilehub', 'whooptm', 'msgas', 'datamicrosoft', 'windows-msgas', 'bellantonicioccolato', 'nemotoads', 'bluemoontuesday'];
          for (const c of tlsConnections) {
            if (c.sni) {
              const lower = c.sni.toLowerCase();
              const isSuspicious = suspiciousKeywords.some(k => lower.includes(k.replace(/^\\\./, '.')));
              const isIP = /^\d+\.\d+\.\d+\.\d+$/.test(c.sni);
              const isC2 = c2Snis.some(k => lower.includes(k));
              if (isSuspicious || isIP || isC2) suspiciousSNIs.push(c);
            }
          }
        }
      } catch {}

      // ── HTTP objects ──
      let httpObjects = [];
      try {
        const tmpDir = `http_objects_${Date.now()}`;
        await fs.mkdir(tmpDir, { recursive: true });
        await execAsync(
          `${tsharkPath} -r "${pcapPath}"${filterFlag} --export-objects "http,${tmpDir}"`,
          { maxBuffer: 50 * 1024 * 1024, env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
        );
        const files = await fs.readdir(tmpDir).catch(() => []);
        for (const file of files) {
          const fpath = path.join(tmpDir, file);
          try {
            const fstat = await fs.stat(fpath);
            const hash = crypto.createHash('sha256').update(await fs.readFile(fpath)).digest('hex');
            httpObjects.push({ name: file, size: fstat.size, sha256: hash });
          } catch {}
        }
        // Cleanup
        for (const file of files) {
          try { await fs.unlink(path.join(tmpDir, file)); } catch {}
        }
        try { await fs.rmdir(tmpDir); } catch {}
      } catch {}

      // ── Search for C2/IOC patterns ──
      let searchResults = {};
      const c2Patterns = [
        { pattern: 'fakeurl.htm', filter: 'http', label: 'RAT fakeurl.htm (NetSupport)' },
        { pattern: 'set_agent', filter: 'http', label: 'C2 agent registration' },
        { pattern: '/api/file/get-file/', filter: 'http', label: 'C2 file download API' },
        { pattern: '.ps1', filter: 'http', label: 'PowerShell script download' },
        { pattern: 'foots.php', filter: 'http', label: 'C2 beacon foots.php' },
        { pattern: '/eval/', filter: 'http', label: 'HTTP eval()' },
        { pattern: 'base64_decode', filter: 'http', label: 'base64_decode' },
        { pattern: 'cmd.exe', filter: '', label: 'cmd.exe in payload' },
        { pattern: 'powershell', filter: '', label: 'PowerShell in payload' },
        { pattern: 'passwd', filter: '', label: 'passwd in payload' },
      ];
      for (const { pattern, filter: f, label } of c2Patterns) {
        try {
          const filterPrefix = f ? `${f} and ` : '';
          const hexP = Buffer.from(pattern, 'utf8').toString('hex').replace(/(..)/g, '$1:').replace(/:$/, '');
          const { stdout } = await execAsync(
            `${tsharkPath} -r "${pcapPath}" -Y "${filterPrefix}frame contains ${hexP}" -T fields -e frame.number`,
            { maxBuffer: 10 * 1024 * 1024, env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
          );
          const count = stdout.trim().split('\n').filter(l => l.trim()).length;
          if (count > 0) searchResults[label] = count;
        } catch {}
      }
      // Also detect typosquatting domains via DNS
      try {
        const { stdout: dnsOut } = await execAsync(
          `${tsharkPath} -r "${pcapPath}" -Y "dns.flags.response == 0" -T fields -e dns.qry.name`,
          { maxBuffer: 10 * 1024 * 1024, env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
        );
        const dnsNames = dnsOut.trim().split('\n').filter(l => l.trim());
        const safeDomains = ['login.microsoftonline.com', 'microsoftonline.com', 'microsoft.com', 'update.microsoft.com', 'delivery.mp.microsoft.com'];
        const susDomains = dnsNames.filter(d => {
          const clean = d.trim().toLowerCase();
          if (safeDomains.some(s => clean === s || clean.endsWith('.' + s))) return false;
          return /\.su$|\.xyz$|\.top$|\.cc$|\.lat$|\.cyou$/.test(clean) ||
            /microsoft[^.]/.test(clean) || /windows-[^.]/.test(clean) ||
            clean.includes('whitepepper') || clean.includes('dyngate') ||
            clean.includes('trycloudflare') || clean.includes('fakeurl') ||
            clean.includes('netsupport') || clean.includes('nemotoads') ||
            clean.includes('bluemoontuesday') || clean.includes('massfriction') ||
            clean.includes('msgas') || clean.includes('easyas123') ||
            clean.includes('datamicrosoft') || clean.includes('win11office') ||
            clean.includes('event-time-microsoft') || clean.includes('eventdata-microsoft') ||
            clean.includes('event-datamicrosoft');
        });
        if (susDomains.length > 0) {
          const uniqueSus = [...new Set(susDomains)];
          searchResults[`Suspicious DNS (${uniqueSus.length} domains: ${uniqueSus.slice(0, 5).map(d => d.trim()).join(', ')}${uniqueSus.length > 5 ? '...' : ''})`] = susDomains.length;
        }
      } catch {}

      // ── Try common TCP streams ──
      let interestingStreams = [];
      for (let sid = 0; sid <= 20; sid++) {
        try {
          const { stdout: stream } = await execAsync(
            `${tsharkPath} -r "${pcapPath}"${filterFlag} -z follow,tcp,ascii,${sid}`,
            { maxBuffer: 10 * 1024 * 1024, env: { ...process.env, PATH: `${process.env.PATH}:/usr/bin:/usr/local/bin:/opt/homebrew/bin` } }
          );
          const clean = stream.trim();
          // Extract data bytes (skip header/footer metadata lines)
          const dataLines = clean.split('\n').filter(l => {
            const t = l.trim();
            return t && !t.startsWith('=') && !t.startsWith('Follow:') && !t.startsWith('Filter:') && !t.startsWith('Node') && t.length > 10;
          });
          const dataContent = dataLines.join('\n').slice(0, 500);
          // Only keep streams with actual application data
          const hasRealData = dataContent.length > 50 && !dataContent.includes('DHCP') && !/^\d+\s+\d+\.\d+\s+/.test(dataContent);
          if (hasRealData) interestingStreams.push({ stream: sid, size: clean.length, preview: dataContent.slice(0, 500) });
        } catch {}
      }

      // ═══════════════════════════════════════════
      // BUILD THE REPORT
      // ═══════════════════════════════════════════

      report += `# Incident Report — ${fname}\n\n`;
      report += `**Generated:** ${dateStr}  \n`;
      report += `**PCAP:** \`${fname}\` (${fileSizeMB} MB, ${packetCount} packets)${filterDesc}  \n`;
      report += `**Tool:** WireMCP via MCP protocol\n\n`;

      // ── Section 1: Executive Summary ──
      const hasCritical = Object.keys(searchResults).length > 0 || suspiciousSNIs.length > 0;
      const status = hasCritical ? '⚠️  SUSPICIOUS ACTIVITY DETECTED' : '✅ NO CLEAR COMPROMISE';
      report += `## 1. Executive Summary\n\n`;
      report += `**Status:** ${status}\n\n`;
      if (expertSummary) report += `**Traffic Overview:** ${expertSummary}. ${totalIPs} unique IPs. ${timelineSummary}.\n\n`;
      if (Object.keys(searchResults).length > 0) {
        report += `**🔴 CRITICAL — C2/IOC Patterns:**\n`;
        for (const [label, count] of Object.entries(searchResults)) {
          report += `- ${label}: ${count} hit(s)\n`;
        }
        report += '\n';
      }
      if (suspiciousSNIs.length > 0) {
        report += `**🟡 Suspicious TLS Connections:** ${suspiciousSNIs.length} connection(s) to suspicious destinations.\n\n`;
        for (const c of suspiciousSNIs) {
          report += `- ${c.dst} → SNI: \`${c.sni}\`\n`;
        }
        report += '\n';
      }
      if (httpObjects.length > 0) {
        const uniqueHashes = new Set(httpObjects.map(o => o.sha256));
        report += `**HTTP Objects:** ${httpObjects.length} file(s) transferred (${uniqueHashes.size} unique).\n\n`;
      }

      // ── Section 2: Network Topology & Key Hosts ──
      report += `## 2. Network Topology & Key Hosts\n\n`;
      if (topTalkers.length > 0) {
        report += `**Key Hosts (top 5 by traffic):**\n\n`;
        for (const t of topTalkers.slice(0, 5)) {
          report += `- \`${t.ip.trim()}\`: ${t.total} pkts (${t.protos.trim()})\n`;
        }
        report += `\nTotal IPs in capture: ${totalIPs}\n\n`;
      }

      // ── Section 3: IOCs ──
      report += `## 3. Indicators of Compromise (IOCs)\n\n`;

      if (suspiciousSNIs.length > 0) {
        report += `### Suspicious TLS Connections\n\n`;
        report += `| Destination | SNI | TLS Version | Frames |\n`;
        report += `|-------------|-----|-------------|--------|\n`;
        for (const c of suspiciousSNIs) {
          report += `| \`${c.dst}\` | ${c.sni} | ${c.version} | ${c.frames} |\n`;
        }
        report += '\n';
      }

      if (tlsConnections.length > 0 && suspiciousSNIs.length === 0) {
        const nonMicrosoft = tlsConnections.filter(c => c.sni && !c.sni.includes('microsoft') && !c.sni.includes('msn.com') && !c.sni.includes('bing.com') && !c.sni.includes('live.com') && !c.sni.includes('windows.com') && !c.sni.includes('office') && !c.sni.includes('skype') && !c.sni.includes('google') && !c.sni.includes('gstatic') && !c.sni.includes('azure'));
        if (nonMicrosoft.length > 0) {
          report += `### Non-Microsoft TLS Connections\n\n`;
          report += `| Destination | SNI |\n`;
          report += `|-------------|-----|\n`;
          for (const c of nonMicrosoft.slice(0, 10)) {
            report += `| \`${c.dst}\` | ${c.sni || '(none)'} |\n`;
          }
          if (nonMicrosoft.length > 10) report += `| ... and ${nonMicrosoft.length - 10} more | |\n`;
          report += '\n';
        }
      }

      if (Object.keys(searchResults).length > 0) {
        report += `### Suspicious Payload Patterns\n\n`;
        report += `| Pattern | Matches |\n`;
        report += `|---------|---------|\n`;
        for (const [label, count] of Object.entries(searchResults)) {
          report += `| ${label} | ${count} |\n`;
        }
        report += '\n';
      }

      if (httpObjects.length > 0) {
        report += `### HTTP Objects Transferred\n\n`;
        report += `| File | Size | SHA256 |\n`;
        report += `|------|------|--------|\n`;
        const hashGroups = {};
        for (const obj of httpObjects) {
          const key = obj.sha256;
          if (!hashGroups[key]) hashGroups[key] = { size: obj.size, sha256: obj.sha256, names: [], count: 0 };
          hashGroups[key].names.push(obj.name);
          hashGroups[key].count++;
        }
        for (const [, group] of Object.entries(hashGroups)) {
          const nameDisplay = group.count > 1 ? `${group.names[0]} (+${group.count - 1} more)` : group.names[0];
          report += `| ${nameDisplay} | ${group.size} bytes | \`${group.sha256}\` |\n`;
        }
        report += '\n';
      }

      if (interestingStreams.length > 0) {
        report += `### Interesting TCP Streams\n\n`;
        for (const s of interestingStreams) {
          report += `**Stream ${s.stream}** (${s.size} bytes):\n\`\`\`\n${s.preview}\n\`\`\`\n\n`;
        }
      }

      const criticalAnomalies = expertAnomalies.filter(a => a.severity === 'Error' || a.severity === 'Warning');
      if (criticalAnomalies.length > 0) {
        report += `### Protocol Anomalies (Errors/Warnings only)\n\n`;
        report += `| Severity | Message | Occurrences |\n`;
        report += `|----------|---------|-------------|\n`;
        for (const a of criticalAnomalies) {
          const icon = a.severity === 'Error' ? '🔴' : '🟡';
          report += `| ${icon} ${a.severity} | ${a.msg.replace(/\|/g, '\\|')} | ${a.count} |\n`;
        }
        report += '\n';
      }

      // ── Section 4: Wireshark Verification Steps ──
      report += `## 4. Wireshark Verification Steps\n\n`;
      report += `The following display filters and procedures can be used in **Wireshark GUI** to verify each finding:\n\n`;

      // Verification for top talkers
      if (topTalkers.length > 0) {
        const topIP = topTalkers[0].ip;
        report += `### 4.1 Verify Top Talkers\n\n`;
        report += `**Display filter:**\n\`\`\`\nip.addr == ${topIP}\n\`\`\`\n`;
        report += `**Procedure:** Apply this filter in Wireshark to isolate all traffic to/from the most active host. Use \`Statistics > Endpoints\` to see all communicating hosts.\n\n`;

        if (topTalkers.length > 1) {
          report += `**To see traffic between top 2 hosts:**\n\`\`\`\nip.addr == ${topTalkers[0].ip} && ip.addr == ${topTalkers[1].ip}\n\`\`\`\n\n`;
        }
      }

      // Verification for TLS
      if (tlsConnections.length > 0) {
        report += `### 4.2 Verify TLS Connections\n\n`;
        report += `**To view all TLS handshakes:**\n\`\`\`\ntls.handshake.type == 1\n\`\`\`\n`;
        report += `**To see TLS Client Hellos (with SNI):**\n\`\`\`\ntls.handshake.type == 1 && tls.handshake.extensions_server_name\n\`\`\`\n`;

        if (suspiciousSNIs.length > 0) {
          report += `**To filter specific suspicious SNI:**\n\`\`\`\ntls.handshake.extensions_server_name == "${suspiciousSNIs[0].sni}"\n\`\`\`\n`;
        }

        report += `**Procedure:** Right-click a TLS packet → \`Follow > TLS Stream\` to decrypt the session (if keys are available). Use \`Statistics > TLS\` for aggregate TLS analysis.\n\n`;
      }

      // Verification for suspicious patterns
      if (Object.keys(searchResults).length > 0) {
        report += `### 4.3 Verify Suspicious Payload Patterns\n\n`;
        for (const [label, count] of Object.entries(searchResults).slice(0, 3)) {
          const pattern = label.includes('(') ? label.split('(')[1]?.split(')')[0] || label : label;
          report += `**Pattern: \`${label}\`** (${count} matches)\n`;
          report += `**Display filter:**\n\`\`\`\nframe contains "${pattern}"\n\`\`\`\n`;
          report += `**Procedure:** Apply this filter, then right-click a matching packet → \`Follow > TCP Stream\` to see the full conversation context.\n\n`;
        }
      }

      // Verification for HTTP objects
      if (httpObjects.length > 0) {
        report += `### 4.4 Verify HTTP Objects\n\n`;
        report += `**To see all HTTP requests:**\n\`\`\`\nhttp.request\n\`\`\`\n`;
        report += `**To export objects in Wireshark GUI:** \`File > Export Objects > HTTP...\` — this lists all HTTP objects transferred with MD5 hashes and sizes.\n\n`;
        report += `**For binary content analysis:** Right-click the object → \`Export Packet Bytes\` → save and analyze with external tools (VirusTotal, pestudio, etc.)\n\n`;
      }

      // Verification for expert info
      if (expertAnomalies.length > 0) {
        report += `### 4.5 Verify Protocol Anomalies\n\n`;
        report += `**Open Expert Info dialog:** \`Analyze > Expert Info\` (or \`Analyze > Expert Info Composite\`).\n\n`;
        report += `**To filter error severity in the packet list:** Use \`Analyze > Display Filter\` with:\n\`\`\`\n_ws.expert.severity >= 2\n\`\`\`\n*(severity 2=Warning, 3=Error)*\n`;
        report += `*Note: Expert info errors are shown as red circles (Error), yellow diamonds (Warning), cyan squares (Note) in Wireshark's packet list.*\n\n`;
      }

      // General Wireshark investigation workflow
      report += `### 4.6 General Wireshark Investigation Workflow\n\n`;
      report += `1. **Initial triage:** \`Statistics > Protocol Hierarchy\` — identify unusual protocols\n`;
      report += `2. **Find top talkers:** \`Statistics > Endpoints\` (IPv4 tab) — sort by packets\n`;
      report += `3. **Timeline analysis:** \`Statistics > I/O Graph\` — set 1s interval, look for periodic bursts (beaconing)\n`;
      report += `4. **DNS investigation:** \`dns.flags.response == 0\` — look for suspicious domains\n`;
      report += `5. **HTTP analysis:** \`http.request\` — review URIs, User-Agents, POST data\n`;
      report += `6. **TLS inspection:** \`tls.handshake.type == 1\` — identify SNIs and JA3 fingerprints\n`;
      report += `7. **Stream reassembly:** Right-click any packet → \`Follow > TCP/UDP/TLS Stream\`\n`;
      report += `8. **Export objects:** \`File > Export Objects > HTTP/SMB/IMF...\` — extract transferred files\n`;
      report += `9. **Coloring rules:** \`View > Coloring Rules\` — apply custom rules to highlight C2 traffic, DNS anomalies, etc.\n`;
      report += `10. **Extract IOCs:** Use \`tshark\` CLI for automated extraction (pipe to grep/cut/jq)\n\n`;

      // ── Section 5: Timeline ──
      report += `## 5. Traffic Timeline\n\n`;
      if (timelineSummary) {
        report += `**Duration:** ${timelineSummary}\n\n`;
        report += `| Time (relative) | Event Count |\n`;
        report += `|----------------|-------------|\n`;
        for (const ev of timelineEvents.slice(0, 15)) {
          report += `| +${ev.time}s | ${ev.count} packets |\n`;
        }
        if (timelineEvents.length > 15) report += `| ... and ${timelineEvents.length - 15} more intervals | |\n`;
        report += '\n';
      } else {
        report += `No timeline data available.\n\n`;
      }

      // ── Section 6: Remediation Steps ──
      report += `## 6. Remediation Steps\n\n`;
      report += `Based on the analysis of this PCAP, the following remediation steps are recommended:\n\n`;

      if (suspiciousSNIs.length > 0 || Object.keys(searchResults).length > 0) {
        report += `1. **Isolate affected hosts** — Immediately quarantine any hosts communicating with suspicious destinations.\n`;
        report += `2. **Block malicious IPs** — Add identified C2 IPs to firewall blocklist.\n`;
        report += `3. **DNS sinkhole** — Add suspicious domains to DNS blocklist/sinkhole.\n`;
        if (suspiciousSNIs.length > 0) {
          report += `4. **Inspect TLS traffic** — If decryption keys are available, decrypt TLS streams to examine encrypted payloads.\n`;
        }
        if (httpObjects.length > 0) {
          report += `5. **Analyze extracted objects** — Submit extracted HTTP objects to VirusTotal or sandbox for malware analysis.\n`;
        }
        report += `6. **Credentials reset** — Reset passwords for any users observed in the traffic.\n`;
        report += `7. **Full host scan** — Perform EDR/AV scan on affected hosts, check for persistence mechanisms.\n`;
        report += `8. **Retain evidence** — Preserve the PCAP and any extracted artifacts for forensic analysis and threat intelligence sharing.\n`;
      } else {
        report += `1. **No clear compromise indicators** — This traffic appears benign. Continue routine monitoring.\n`;
        report += `2. **Baseline establishment** — Document normal traffic patterns for future comparison.\n`;
        report += `3. **Periodic review** — Re-run this tool on a regular basis to establish a baseline of normal behavior.\n`;
      }
      report += '\n';

      // ── Footer ──
      report += `---\n*Report generated by WireMCP — Wireshark MCP Server*\n`;

      // ── Save or return ──
      if (outputPath) {
        await fs.writeFile(outputPath, report, 'utf8');
        return {
          content: [{ type: 'text', text: `Report saved to: ${outputPath}\n\nSummary: ${packetCount} packets, ${totalIPs} IPs, ${tlsConnections.length} TLS connections, ${httpObjects.length} HTTP objects, ${Object.keys(searchResults).length} pattern matches.` }],
        };
      }

      return {
        content: [{ type: 'text', text: report }],
      };
    } catch (error) {
      console.error(`Error in generate_incident_report: ${error.message}`);
      return { content: [{ type: 'text', text: `Error: ${error.message}` }], isError: true };
    }
  }
);

server.prompt(
  'generate_incident_report_prompt',
  {
    pcapPath: z.string().describe('Path to the PCAP file'),
  },
  ({ pcapPath }) => ({
    messages: [{
      role: 'user',
      content: {
        type: 'text',
        text: `Please generate a comprehensive incident report for ${pcapPath}. Include:
1. Executive summary with key findings
2. Top talkers and network topology analysis
3. All indicators of compromise (IOCs) extracted from TLS, HTTP, and payload analysis
4. Wireshark verification steps for each finding
5. Traffic timeline
6. Remediation recommendations`
      }
    }]
  })
);

module.exports = {
  findTshark, trimPackets, parseTsharkJson,
  parseIcmpPayloadsFromHex, extractRawIcmpPayloads
};

// Start the server only when run directly
if (require.main === module) {
  server.connect(new StdioServerTransport())
    .then(() => console.error('WireMCP Server is running...'))
    .catch(err => {
      console.error('Failed to start WireMCP:', err);
      process.exit(1);
    });
}