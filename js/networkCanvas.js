/**
 * NetPulse Dynamic Network Topology & Packet Stream Canvas
 * Renders an interactive cybernetic node graph with traveling packet pulses,
 * latency indicators, and firewall intercept animations.
 */

export class NetworkCanvas {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d');
    this.dpr = window.devicePixelRatio || 1;
    this.width = 0;
    this.height = 0;

    // Topology nodes
    this.nodes = [];
    this.links = [];
    this.pulses = [];

    // Protocol color mapping
    this.protocolColors = {
      'DNS': '#00f0ff',
      'TLS 1.3': '#d946ef',
      'HTTP/2': '#10b981',
      'TCP': '#f59e0b',
      'UDP': '#38bdf8',
      'THREAT': '#ff0055'
    };

    this.animId = null;
    this.init();
  }

  init() {
    this.resize();
    window.addEventListener('resize', () => this.resize());
    this.setupTopology();
    this.loop();
  }

  resize() {
    const parent = this.canvas.parentElement;
    this.width = parent.clientWidth || 800;
    this.height = parent.clientHeight || 320;
    this.canvas.width = this.width * this.dpr;
    this.canvas.height = this.height * this.dpr;
    this.canvas.style.width = `${this.width}px`;
    this.canvas.style.height = `${this.height}px`;
    this.ctx.scale(this.dpr, this.dpr);
    this.setupTopology();
  }

  setupTopology() {
    const w = this.width;
    const h = this.height;

    // Create 5 key network hops across the canvas
    this.nodes = [
      { id: 'client', label: 'Client Device', sub: '192.168.1.105', x: w * 0.10, y: h * 0.50, icon: '💻', radius: 24, status: 'online' },
      { id: 'gateway', label: 'Gateway Router', sub: '192.168.1.1', x: w * 0.30, y: h * 0.50, icon: '📡', radius: 22, status: 'online' },
      { id: 'dns', label: 'Edge DNS / Anycast', sub: '1.1.1.1', x: w * 0.50, y: h * 0.25, icon: '🌐', radius: 22, status: 'online' },
      { id: 'waf', label: 'WAF / Firewall', sub: 'Threat Filter', x: w * 0.50, y: h * 0.75, icon: '🛡️', radius: 22, status: 'online' },
      { id: 'cdn', label: 'Cloudflare CDN', sub: 'Edge Proxy', x: w * 0.70, y: h * 0.50, icon: '⚡', radius: 24, status: 'online' },
      { id: 'origin', label: 'Origin Cluster', sub: '10.0.0.1:443', x: w * 0.90, y: h * 0.50, icon: '🗄️', radius: 26, status: 'online' }
    ];

    // Interconnections
    this.links = [
      { from: 'client', to: 'gateway' },
      { from: 'gateway', to: 'dns' },
      { from: 'gateway', to: 'waf' },
      { from: 'dns', to: 'cdn' },
      { from: 'waf', to: 'cdn' },
      { from: 'cdn', to: 'origin' }
    ];
  }

  /**
   * Spawn a traveling packet animation based on real packet emitted
   */
  spawnPacketPulse(packet) {
    const isThreat = packet.threatLevel === 'threat';
    const color = isThreat ? this.protocolColors['THREAT'] : (this.protocolColors[packet.protocol] || '#00f0ff');

    // Route: Client -> Gateway -> (WAF or DNS) -> CDN -> Origin
    const route = ['client', 'gateway'];
    if (packet.protocol === 'DNS' || isThreat && packet.protocol === 'DNS') {
      route.push('dns', 'cdn', 'origin');
    } else {
      route.push('waf', 'cdn', 'origin');
    }

    this.pulses.push({
      route: route,
      currentHop: 0,
      progress: 0,
      speed: isThreat ? 0.045 : 0.025,
      color: color,
      isThreat: isThreat,
      length: packet.length
    });
  }

  update() {
    for (let i = this.pulses.length - 1; i >= 0; i--) {
      const p = this.pulses[i];
      p.progress += p.speed;

      if (p.progress >= 1) {
        p.progress = 0;
        p.currentHop++;

        // If packet completed all hops or blocked at WAF
        if (p.isThreat && p.route[p.currentHop] === 'waf') {
          // Blocked at firewall!
          this.triggerBlockEffect(this.getNode('waf'));
          this.pulses.splice(i, 1);
          continue;
        }

        if (p.currentHop >= p.route.length - 1) {
          this.pulses.splice(i, 1);
        }
      }
    }
  }

  triggerBlockEffect(node) {
    if (!node) return;
    node.blockedPing = 1.0;
  }

  getNode(id) {
    return this.nodes.find(n => n.id === id);
  }

  render() {
    this.ctx.clearRect(0, 0, this.width, this.height);

    // 1. Draw Links
    for (const link of this.links) {
      const n1 = this.getNode(link.from);
      const n2 = this.getNode(link.to);
      if (!n1 || !n2) continue;

      this.ctx.beginPath();
      this.ctx.moveTo(n1.x, n1.y);
      this.ctx.lineTo(n2.x, n2.y);
      this.ctx.strokeStyle = 'rgba(0, 240, 255, 0.12)';
      this.ctx.lineWidth = 2;
      this.ctx.setLineDash([4, 4]);
      this.ctx.stroke();
      this.ctx.setLineDash([]);
    }

    // 2. Draw Traveling Pulses
    for (const p of this.pulses) {
      const n1 = this.getNode(p.route[p.currentHop]);
      const n2 = this.getNode(p.route[p.currentHop + 1]);
      if (!n1 || !n2) continue;

      const px = n1.x + (n2.x - n1.x) * p.progress;
      const py = n1.y + (n2.y - n1.y) * p.progress;

      // Glow Halo
      const grad = this.ctx.createRadialGradient(px, py, 0, px, py, p.isThreat ? 14 : 9);
      grad.addColorStop(0, p.color);
      grad.addColorStop(1, 'rgba(0, 0, 0, 0)');

      this.ctx.fillStyle = grad;
      this.ctx.beginPath();
      this.ctx.arc(px, py, p.isThreat ? 14 : 9, 0, Math.PI * 2);
      this.ctx.fill();

      // Solid bright nucleus
      this.ctx.fillStyle = '#ffffff';
      this.ctx.beginPath();
      this.ctx.arc(px, py, p.isThreat ? 4 : 2.5, 0, Math.PI * 2);
      this.ctx.fill();
    }

    // 3. Draw Nodes
    for (const node of this.nodes) {
      // Firewall blocked animation ping
      if (node.blockedPing && node.blockedPing > 0) {
        node.blockedPing -= 0.03;
        this.ctx.beginPath();
        this.ctx.arc(node.x, node.y, node.radius + (1 - node.blockedPing) * 35, 0, Math.PI * 2);
        this.ctx.strokeStyle = `rgba(255, 0, 85, ${node.blockedPing})`;
        this.ctx.lineWidth = 2.5;
        this.ctx.stroke();
      }

      // Outer Node Ring
      this.ctx.beginPath();
      this.ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
      this.ctx.fillStyle = '#060d17';
      this.ctx.fill();
      this.ctx.strokeStyle = 'rgba(0, 240, 255, 0.4)';
      this.ctx.lineWidth = 2;
      this.ctx.stroke();

      // Node Icon
      this.ctx.font = '16px monospace';
      this.ctx.textAlign = 'center';
      this.ctx.textBaseline = 'middle';
      this.ctx.fillText(node.icon, node.x, node.y - 1);

      // Node Label
      this.ctx.font = '11px "JetBrains Mono", monospace';
      this.ctx.fillStyle = '#f8fafc';
      this.ctx.fillText(node.label, node.x, node.y + node.radius + 14);

      // Sub label
      this.ctx.font = '9px "JetBrains Mono", monospace';
      this.ctx.fillStyle = '#64748b';
      this.ctx.fillText(node.sub, node.x, node.y + node.radius + 26);
    }
  }

  loop() {
    this.update();
    this.render();
    this.animId = requestAnimationFrame(() => this.loop());
  }
}
