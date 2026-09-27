/**
 * NetPulse Packet Engine
 * Simulates, dissectors, and manages real-time network traffic streams across OSI layers:
 * Layer 3 (IPv4/IPv6), Layer 4 (TCP/UDP/ICMP), and Layer 7 (HTTP/2, DNS, TLS 1.3, WS).
 */

export class PacketEngine {
  constructor() {
    this.packets = [];
    this.maxBufferSize = 250;
    this.packetCounter = 1000;
    this.isRunning = false;
    this.speed = 1.0; // Multiplier
    this.intervalId = null;
    this.scenario = 'normal'; // 'normal', 'syn_flood', 'port_scan', 'dns_tunnel', 'exfiltration'

    // Statistics
    this.stats = {
      total: 0,
      tcp: 0,
      udp: 0,
      tls: 0,
      dns: 0,
      http: 0,
      threats: 0,
      bytesTransferred: 0
    };

    // Listeners
    this.packetCallbacks = [];
    this.alertCallbacks = [];

    // Internal state machines for realistic sessions
    this.sessionQueue = [];
  }

  onPacket(callback) {
    this.packetCallbacks.push(callback);
  }

  onAlert(callback) {
    this.alertCallbacks.push(callback);
  }

  setScenario(scenarioName) {
    this.scenario = scenarioName;
    if (this.scenario !== 'normal') {
      this.triggerAlert({
        title: `SCENARIO ACTIVATED: ${scenarioName.toUpperCase().replace('_', ' ')}`,
        level: scenarioName === 'syn_flood' || scenarioName === 'dns_tunnel' ? 'critical' : 'warning',
        timestamp: new Date().toLocaleTimeString(),
        message: `Network monitor entering test vector: ${scenarioName}`
      });
    }
  }

  start() {
    if (this.isRunning) return;
    this.isRunning = true;
    this.loop();
  }

  stop() {
    this.isRunning = false;
    if (this.intervalId) {
      clearTimeout(this.intervalId);
    }
  }

  loop() {
    if (!this.isRunning) return;

    let delay = Math.floor((180 + Math.random() * 320) / this.speed);

    if (this.scenario === 'syn_flood') {
      delay = Math.floor(40 / this.speed);
      this.generateSynFloodPacket();
    } else if (this.scenario === 'port_scan') {
      delay = Math.floor(100 / this.speed);
      this.generatePortScanPacket();
    } else if (this.scenario === 'dns_tunnel') {
      delay = Math.floor(150 / this.speed);
      this.generateDnsTunnelPacket();
    } else {
      this.generateNormalTraffic();
    }

    this.intervalId = setTimeout(() => this.loop(), delay);
  }

  /**
   * Generates standard Internet traffic (TCP Handshakes, TLS 1.3, HTTP/2, DNS)
   */
  generateNormalTraffic() {
    const clients = ['192.168.1.105', '192.168.1.112', '10.0.0.45', '172.16.4.22'];
    const servers = [
      { ip: '104.21.44.18', host: 'api.github.com', port: 443 },
      { ip: '1.1.1.1', host: 'one.one.one.one', port: 53 },
      { ip: '142.250.190.46', host: 'services.google.com', port: 443 },
      { ip: '151.101.65.140', host: 'cdn.fastly.net', port: 80 }
    ];

    const client = clients[Math.floor(Math.random() * clients.length)];
    const server = servers[Math.floor(Math.random() * servers.length)];
    const clientPort = Math.floor(49152 + Math.random() * 16000);

    const protoRoll = Math.random();
    let packet;

    if (protoRoll < 0.25) {
      // DNS Query
      const domains = ['api.github.com', 'raw.githubusercontent.com', 'cloudflare-dns.com', 'npm.registry.org'];
      const targetDomain = domains[Math.floor(Math.random() * domains.length)];
      const queryId = `0x${Math.floor(Math.random() * 65535).toString(16).padStart(4, '0')}`;
      packet = this.buildPacket({
        srcIp: client,
        dstIp: '1.1.1.1',
        srcPort: clientPort,
        dstPort: 53,
        protocol: 'DNS',
        flags: 'UDP',
        length: 64 + targetDomain.length,
        status: 'QUERY',
        info: `Standard query ${queryId} A ${targetDomain}`,
        payload: `Flags: 0x0100 (Standard query)\nQuestions: 1\nQuery: ${targetDomain} (Type A, Class IN)`,
        threatLevel: 'normal'
      });
    } else if (protoRoll < 0.55) {
      // TLS 1.3 Handshake or Application Data
      const isClientHello = Math.random() > 0.6;
      packet = this.buildPacket({
        srcIp: isClientHello ? client : server.ip,
        dstIp: isClientHello ? server.ip : client,
        srcPort: isClientHello ? clientPort : 443,
        dstPort: isClientHello ? 443 : clientPort,
        protocol: 'TLS 1.3',
        flags: '[PSH, ACK]',
        length: isClientHello ? 512 : Math.floor(100 + Math.random() * 1200),
        status: isClientHello ? 'CLIENT_HELLO' : 'ENCRYPTED_DATA',
        info: isClientHello 
          ? `Client Hello (SNI: ${server.host}, Cipher: TLS_AES_128_GCM_SHA256)`
          : `Application Data Protocol: http/1.1 (Encrypted Record)`,
        payload: isClientHello
          ? `TLSv1.3 Record Layer: Handshake Protocol: Client Hello\nVersion: TLS 1.3 (0x0304)\nServer Name Indication: ${server.host}`
          : `TLSv1.3 Record Layer: Application Data\nLength: 1420 bytes\nEncrypted Payload: AES-GCM (HMAC verified)`,
        threatLevel: 'normal'
      });
    } else if (protoRoll < 0.85) {
      // HTTP/2 or REST API
      const endpoints = ['/v1/telemetry', '/api/users/profile', '/healthz', '/socket.io/?EIO=4'];
      const ep = endpoints[Math.floor(Math.random() * endpoints.length)];
      const methods = ['GET', 'POST'];
      const m = methods[Math.floor(Math.random() * methods.length)];
      packet = this.buildPacket({
        srcIp: client,
        dstIp: server.ip,
        srcPort: clientPort,
        dstPort: server.port,
        protocol: 'HTTP/2',
        flags: '[ACK]',
        length: 280 + Math.floor(Math.random() * 400),
        status: '200 OK',
        info: `HEADERS frame: ${m} ${ep} -> 200 OK`,
        payload: `${m} ${ep} HTTP/2.0\nHost: ${server.host}\nUser-Agent: NetPulse-Agent/2.4\nAccept: application/json\nContent-Type: application/json`,
        threatLevel: 'normal'
      });
    } else {
      // TCP SYN / ACK Handshake
      const flags = ['[SYN]', '[SYN, ACK]', '[ACK]'];
      const selectedFlag = flags[Math.floor(Math.random() * flags.length)];
      packet = this.buildPacket({
        srcIp: client,
        dstIp: server.ip,
        srcPort: clientPort,
        dstPort: server.port,
        protocol: 'TCP',
        flags: selectedFlag,
        length: 54,
        status: 'ESTABLISHED',
        info: `Seq=${Math.floor(Math.random() * 100000)} Win=64240 Len=0 MSS=1460`,
        payload: `Transmission Control Protocol, Src Port: ${clientPort}, Dst Port: ${server.port}\nFlags: ${selectedFlag}\nWindow Size: 64240`,
        threatLevel: 'normal'
      });
    }

    this.emitPacket(packet);
  }

  generateSynFloodPacket() {
    const spoofedIp = `${Math.floor(Math.random() * 223 + 1)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    const victimIp = '10.0.0.1';
    const packet = this.buildPacket({
      srcIp: spoofedIp,
      dstIp: victimIp,
      srcPort: Math.floor(1024 + Math.random() * 64000),
      dstPort: 443,
      protocol: 'TCP',
      flags: '[SYN]',
      length: 60,
      status: 'HALF_OPEN',
      info: `[ALERT: SYN FLOOD] Spoofed handshake attempt without ACK`,
      payload: `Transmission Control Protocol, Flags: [SYN]\nAttacker: ${spoofedIp} -> Victim: ${victimIp}:443\nPossible DoS/DDoS signature detected`,
      threatLevel: 'threat'
    });
    this.emitPacket(packet);
  }

  generatePortScanPacket() {
    const scannerIp = '198.51.100.42';
    const victimIp = '10.0.0.1';
    const ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443];
    const targetPort = ports[Math.floor(Math.random() * ports.length)];
    const packet = this.buildPacket({
      srcIp: scannerIp,
      dstIp: victimIp,
      srcPort: 54321,
      dstPort: targetPort,
      protocol: 'TCP',
      flags: '[SYN]',
      length: 44,
      status: 'PROBE',
      info: `[SCAN DETECTED] Probe on port ${targetPort} (${this.getPortService(targetPort)})`,
      payload: `Reconnaissance Probe: SYN stealth scan directed at Port ${targetPort}\nSignature: Nmap OS/Service fingerprinting`,
      threatLevel: 'threat'
    });
    this.emitPacket(packet);
  }

  generateDnsTunnelPacket() {
    const exfilData = this.randomHex(24);
    const domain = `${exfilData}.tunnel.darkops-c2.net`;
    const packet = this.buildPacket({
      srcIp: '192.168.1.105',
      dstIp: '8.8.8.8',
      srcPort: 51234,
      dstPort: 53,
      protocol: 'DNS',
      flags: 'UDP',
      length: 84 + domain.length,
      status: 'EXFILTRATION',
      info: `[ANOMALY: DNS TUNNEL] Query exceeds entropy threshold: ${domain.substring(0, 28)}...`,
      payload: `DNS Query: ${domain}\nHigh Shannon Entropy: Subdomain payload encoded covert channel data.`,
      threatLevel: 'threat'
    });
    this.emitPacket(packet);
  }

  buildPacket(options) {
    this.packetCounter++;
    const now = new Date();
    const timeStr = now.toTimeString().split(' ')[0] + '.' + now.getMilliseconds().toString().padStart(3, '0');

    // Generate raw byte representation
    const rawBytes = this.generateRawBytes(options.payload || options.info);
    const entropy = this.calculateShannonEntropy(rawBytes);

    const packet = {
      id: this.packetCounter,
      time: timeStr,
      srcIp: options.srcIp,
      dstIp: options.dstIp,
      srcPort: options.srcPort,
      dstPort: options.dstPort,
      protocol: options.protocol,
      flags: options.flags || '',
      length: options.length || rawBytes.length,
      status: options.status || 'OK',
      info: options.info,
      payload: options.payload || '',
      rawBytes: rawBytes,
      entropy: entropy,
      threatLevel: options.threatLevel || 'normal'
    };

    return packet;
  }

  emitPacket(packet) {
    this.packets.unshift(packet);
    if (this.packets.length > this.maxBufferSize) {
      this.packets.pop();
    }

    // Update stats
    this.stats.total++;
    this.stats.bytesTransferred += packet.length;
    if (packet.protocol.includes('TCP')) this.stats.tcp++;
    if (packet.protocol.includes('UDP')) this.stats.udp++;
    if (packet.protocol.includes('TLS')) this.stats.tls++;
    if (packet.protocol.includes('DNS')) this.stats.dns++;
    if (packet.protocol.includes('HTTP')) this.stats.http++;
    if (packet.threatLevel === 'threat') this.stats.threats++;

    this.packetCallbacks.forEach(cb => cb(packet, this.stats));
  }

  triggerAlert(alert) {
    this.alertCallbacks.forEach(cb => cb(alert));
  }

  calculateShannonEntropy(bytes) {
    if (!bytes || bytes.length === 0) return 0;
    const freq = new Array(256).fill(0);
    for (let i = 0; i < bytes.length; i++) {
      freq[bytes[i]]++;
    }
    let entropy = 0;
    const len = bytes.length;
    for (let i = 0; i < 256; i++) {
      if (freq[i] > 0) {
        const p = freq[i] / len;
        entropy -= p * Math.log2(p);
      }
    }
    return parseFloat(entropy.toFixed(3));
  }

  generateRawBytes(text) {
    const bytes = [];
    // Ethernet + IP header mock bytes
    const headerPrefix = [0x45, 0x00, 0x02, 0x1c, 0x7a, 0x3f, 0x40, 0x00, 0x40, 0x06, 0x9a, 0x14];
    bytes.push(...headerPrefix);
    for (let i = 0; i < text.length; i++) {
      bytes.push(text.charCodeAt(i) & 0xff);
    }
    return bytes;
  }

  randomHex(len) {
    let result = '';
    const hexChars = '0123456789abcdef';
    for (let i = 0; i < len; i++) {
      result += hexChars[Math.floor(Math.random() * 16)];
    }
    return result;
  }

  getPortService(port) {
    const services = {
      21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
      80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 3306: 'MySQL',
      5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-Alt'
    };
    return services[port] || 'Unknown';
  }
}
