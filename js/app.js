/**
 * NetPulse Main Application Controller
 * Coordinates Packet Engine, Network Canvas, Hex Viewer, Security Tools, and Audio Telemetry.
 */

import { PacketEngine } from './packetEngine.js';
import { NetworkCanvas } from './networkCanvas.js';
import { HexViewer } from './hexViewer.js';
import { SecurityTools } from './securityTools.js';
import { SonarAudio } from './sonarAudio.js';

class NetPulseApp {
  constructor() {
    this.engine = new PacketEngine();
    this.canvas = null;
    this.hexViewer = null;
    this.audio = new SonarAudio();

    this.selectedPacket = null;
    this.isAutoScroll = true;
    this.protocolFilter = 'ALL';
    this.searchQuery = '';
    this.threatsOnly = false;
  }

  init() {
    // 1. Initialize Canvas & Hex Viewer
    const canvasEl = document.getElementById('network-canvas');
    if (canvasEl) {
      this.canvas = new NetworkCanvas(canvasEl);
    }
    this.hexViewer = new HexViewer('hex-dump-container', 'protocol-tree-container');

    // 2. Wire Up Listeners & Controls
    this.setupEventListeners();
    this.setupToolsTabs();
    this.setupEntropyTool();
    this.setupJwtTool();
    this.setupConverterTool();
    this.setupPacketCrafter();

    // 3. Subscribe to Packet Engine Events
    this.engine.onPacket((packet, stats) => this.handleIncomingPacket(packet, stats));
    this.engine.onAlert((alert) => this.handleAlert(alert));

    // 4. Start Capture Stream
    this.engine.start();
  }

  handleIncomingPacket(packet, stats) {
    // Canvas pulse animation
    if (this.canvas) {
      this.canvas.spawnPacketPulse(packet);
    }

    // Audio feedback
    if (packet.threatLevel === 'threat') {
      this.audio.playThreatAlert();
    } else {
      this.audio.playPacketBlip(packet.protocol);
    }

    // Update Telemetry Header Stats
    this.updateStatsUI(stats);

    // Insert row if passes filter
    if (this.packetMatchesFilters(packet)) {
      this.renderPacketRow(packet);
    }

    // Default select first packet if none selected
    if (!this.selectedPacket) {
      this.selectPacket(packet);
    }
  }

  handleAlert(alert) {
    const banner = document.getElementById('alert-banner');
    const textEl = document.getElementById('alert-text');
    if (banner && textEl) {
      textEl.textContent = `[${alert.timestamp}] ${alert.title}: ${alert.message}`;
      banner.classList.add('active');

      setTimeout(() => {
        banner.classList.remove('active');
      }, 7000);
    }
  }

  updateStatsUI(stats) {
    const totalEl = document.getElementById('stat-total-packets');
    const bytesEl = document.getElementById('stat-total-bytes');
    const threatsEl = document.getElementById('stat-threats');

    if (totalEl) totalEl.textContent = stats.total.toLocaleString();
    if (threatsEl) threatsEl.textContent = stats.threats.toLocaleString();
    if (bytesEl) {
      const kb = (stats.bytesTransferred / 1024).toFixed(1);
      bytesEl.textContent = `${kb} KB`;
    }
  }

  renderPacketRow(packet) {
    const tbody = document.getElementById('packet-table-body');
    if (!tbody) return;

    const tr = document.createElement('tr');
    tr.className = `packet-row ${packet.threatLevel === 'threat' ? 'threat-row' : ''}`;
    tr.dataset.packetId = packet.id;

    // Protocol badge class
    let protoClass = 'proto-TCP';
    if (packet.protocol.includes('DNS')) protoClass = 'proto-DNS';
    else if (packet.protocol.includes('TLS')) protoClass = 'proto-TLS';
    else if (packet.protocol.includes('HTTP')) protoClass = 'proto-HTTP';
    else if (packet.protocol.includes('UDP')) protoClass = 'proto-UDP';

    tr.innerHTML = `
      <td>${packet.id}</td>
      <td style="color: var(--text-muted); font-size: 0.72rem;">${packet.time}</td>
      <td style="color: var(--neon-cyan);">${packet.srcIp}:${packet.srcPort}</td>
      <td style="color: var(--neon-blue);">${packet.dstIp}:${packet.dstPort}</td>
      <td><span class="proto-badge ${protoClass}">${packet.protocol}</span></td>
      <td>${packet.length}</td>
      <td style="max-width: 260px; overflow: hidden; text-overflow: ellipsis;">${this.escape(packet.info)}</td>
    `;

    tr.addEventListener('click', () => {
      this.selectPacket(packet);
    });

    tbody.appendChild(tr);

    // Limit DOM table rows to 120 for 60fps performance
    if (tbody.children.length > 120) {
      tbody.removeChild(tbody.firstChild);
    }

    if (this.isAutoScroll) {
      const wrapper = document.getElementById('packet-table-wrapper');
      if (wrapper) wrapper.scrollTop = wrapper.scrollHeight;
    }
  }

  selectPacket(packet) {
    this.selectedPacket = packet;

    // Highlight row
    const rows = document.querySelectorAll('.packet-row');
    rows.forEach(r => {
      if (r.dataset.packetId === String(packet.id)) {
        r.classList.add('selected');
      } else {
        r.classList.remove('selected');
      }
    });

    // Render in Hex Dump & Tree
    if (this.hexViewer) {
      this.hexViewer.renderPacket(packet);
    }
  }

  packetMatchesFilters(packet) {
    if (this.threatsOnly && packet.threatLevel !== 'threat') return false;
    if (this.protocolFilter !== 'ALL' && !packet.protocol.includes(this.protocolFilter)) return false;

    if (this.searchQuery) {
      const q = this.searchQuery.toLowerCase();
      const haystack = `${packet.srcIp} ${packet.dstIp} ${packet.protocol} ${packet.info} ${packet.status}`.toLowerCase();
      if (!haystack.includes(q)) return false;
    }

    return true;
  }

  setupEventListeners() {
    // Start / Pause capture button
    const toggleBtn = document.getElementById('btn-toggle-capture');
    if (toggleBtn) {
      toggleBtn.addEventListener('click', () => {
        if (this.engine.isRunning) {
          this.engine.stop();
          toggleBtn.textContent = '▶ RESUME STREAM';
          toggleBtn.classList.remove('active');
        } else {
          this.engine.start();
          toggleBtn.textContent = '⏸ PAUSE STREAM';
          toggleBtn.classList.add('active');
        }
      });
    }

    // Audio Sonar toggle
    const audioBtn = document.getElementById('btn-toggle-audio');
    if (audioBtn) {
      audioBtn.addEventListener('click', () => {
        const isEnabled = this.audio.toggle();
        audioBtn.classList.toggle('active', isEnabled);
        audioBtn.textContent = isEnabled ? '🔊 SONAR ON' : '🔇 SONAR MUTED';
      });
    }

    // Clear buffer button
    const clearBtn = document.getElementById('btn-clear-stream');
    if (clearBtn) {
      clearBtn.addEventListener('click', () => {
        const tbody = document.getElementById('packet-table-body');
        if (tbody) tbody.innerHTML = '';
        this.selectedPacket = null;
      });
    }

    // Scenario Attack vector select
    const scenarioSelect = document.getElementById('select-scenario');
    if (scenarioSelect) {
      scenarioSelect.addEventListener('change', (e) => {
        this.engine.setScenario(e.target.value);
      });
    }

    // Protocol filter select
    const protoSelect = document.getElementById('select-proto-filter');
    if (protoSelect) {
      protoSelect.addEventListener('change', (e) => {
        this.protocolFilter = e.target.value;
      });
    }

    // Search input
    const searchInput = document.getElementById('input-search-filter');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        this.searchQuery = e.target.value.trim();
      });
    }

    // Threats only checkbox
    const threatCheck = document.getElementById('check-threats-only');
    if (threatCheck) {
      threatCheck.addEventListener('change', (e) => {
        this.threatsOnly = e.target.checked;
      });
    }

    // Auto-scroll toggle
    const autoScrollBtn = document.getElementById('btn-auto-scroll');
    if (autoScrollBtn) {
      autoScrollBtn.addEventListener('click', () => {
        this.isAutoScroll = !this.isAutoScroll;
        autoScrollBtn.classList.toggle('active', this.isAutoScroll);
      });
    }

    // Export JSON capture
    const exportBtn = document.getElementById('btn-export-capture');
    if (exportBtn) {
      exportBtn.addEventListener('click', () => {
        const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(this.engine.packets, null, 2));
        const dlAnchor = document.createElement('a');
        dlAnchor.setAttribute('href', dataStr);
        dlAnchor.setAttribute('download', `netpulse-capture-${Date.now()}.json`);
        dlAnchor.click();
      });
    }
  }

  setupToolsTabs() {
    const tabs = document.querySelectorAll('.tab-btn');
    const contents = document.querySelectorAll('.tab-content');

    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        tabs.forEach(t => t.classList.remove('active'));
        contents.forEach(c => c.classList.remove('active'));

        tab.classList.add('active');
        const targetId = tab.dataset.target;
        const targetEl = document.getElementById(targetId);
        if (targetEl) targetEl.classList.add('active');
      });
    });
  }

  setupEntropyTool() {
    const input = document.getElementById('entropy-input');
    const scoreEl = document.getElementById('entropy-score');
    const fillEl = document.getElementById('entropy-fill');
    const catEl = document.getElementById('entropy-category');

    const updateEntropy = () => {
      if (!input) return;
      const text = input.value;
      const result = SecurityTools.calculateEntropy(text);

      if (scoreEl) scoreEl.textContent = `${result.score} / 8.0 bits`;
      if (catEl) {
        catEl.textContent = result.category;
        catEl.style.color = result.risk === 'high' ? 'var(--neon-red)' : (result.risk === 'medium' ? 'var(--neon-amber)' : 'var(--neon-green)');
      }
      if (fillEl) {
        const pct = (result.score / 8.0) * 100;
        fillEl.style.width = `${pct}%`;
      }
    };

    if (input) {
      input.addEventListener('input', updateEntropy);
      updateEntropy();
    }
  }

  setupJwtTool() {
    const input = document.getElementById('jwt-input');
    const output = document.getElementById('jwt-output');
    const btn = document.getElementById('btn-inspect-jwt');

    if (btn && input && output) {
      btn.addEventListener('click', () => {
        const result = SecurityTools.decodeJWT(input.value);
        output.textContent = JSON.stringify(result, null, 2);
      });
    }
  }

  setupConverterTool() {
    const input = document.getElementById('conv-input');
    const output = document.getElementById('conv-output');
    const btns = document.querySelectorAll('.btn-conv-action');

    btns.forEach(btn => {
      btn.addEventListener('click', () => {
        const action = btn.dataset.action;
        if (input && output) {
          output.value = SecurityTools.convertPayload(input.value, action);
        }
      });
    });
  }

  setupPacketCrafter() {
    const transmitBtn = document.getElementById('btn-transmit-packet');
    if (!transmitBtn) return;

    transmitBtn.addEventListener('click', () => {
      const srcIp = document.getElementById('craft-src-ip').value || '192.168.1.99';
      const dstIp = document.getElementById('craft-dst-ip').value || '10.0.0.1';
      const proto = document.getElementById('craft-proto').value || 'TCP';
      const flags = document.getElementById('craft-flags').value || '[SYN]';
      const payload = document.getElementById('craft-payload').value || 'CUSTOM_INJECTED_PROBE';

      const customPacket = this.engine.buildPacket({
        srcIp,
        dstIp,
        srcPort: Math.floor(40000 + Math.random() * 20000),
        dstPort: 443,
        protocol: proto,
        flags: flags,
        status: 'INJECTED',
        info: `[MANUAL INJECTION] Custom crafted packet transmitted to ${dstIp}`,
        payload: payload,
        threatLevel: flags.includes('RST') || flags.includes('SYN') ? 'warning' : 'normal'
      });

      this.engine.emitPacket(customPacket);

      const msgEl = document.getElementById('craft-status-msg');
      if (msgEl) {
        msgEl.textContent = `✓ Packet #${customPacket.id} injected into live stream!`;
        setTimeout(() => { msgEl.textContent = ''; }, 3000);
      }
    });
  }

  escape(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
}

// Start app on DOMContentLoaded
window.addEventListener('DOMContentLoaded', () => {
  const app = new NetPulseApp();
  app.init();
});
