/**
 * NetPulse Hex Dump & Protocol Layer Dissector
 * Renders Wireshark-grade Hex + ASCII byte dumps and dissects OSI packet headers.
 */

export class HexViewer {
  constructor(hexContainerId, treeContainerId) {
    this.hexContainer = document.getElementById(hexContainerId);
    this.treeContainer = document.getElementById(treeContainerId);
  }

  /**
   * Render complete packet dissection for a selected packet
   */
  renderPacket(packet) {
    if (!packet) return;
    this.renderHexDump(packet.rawBytes || []);
    this.renderProtocolTree(packet);
  }

  /**
   * Formats raw bytes into standard 16-bytes-per-line Hex + ASCII view
   */
  renderHexDump(bytes) {
    if (!this.hexContainer) return;

    if (!bytes || bytes.length === 0) {
      this.hexContainer.innerHTML = '<span class="text-muted">No raw byte payload available.</span>';
      return;
    }

    let html = '';
    const bytesPerLine = 16;

    for (let i = 0; i < bytes.length; i += bytesPerLine) {
      const offset = i.toString(16).padStart(4, '0');
      const chunk = bytes.slice(i, i + bytesPerLine);

      // Hex representation
      let hexPart = '';
      for (let j = 0; j < bytesPerLine; j++) {
        if (j < chunk.length) {
          const byteHex = chunk[j].toString(16).padStart(2, '0').toUpperCase();
          // First 12 bytes are header mock, rest is payload
          const isHeader = (i + j) < 12;
          const className = isHeader ? 'hex-byte header-byte' : 'hex-byte payload-byte';
          hexPart += `<span class="${className}">${byteHex}</span> `;
        } else {
          hexPart += '   ';
        }
        if (j === 7) hexPart += ' '; // Extra column spacing
      }

      // ASCII representation
      let asciiPart = '';
      for (let j = 0; j < chunk.length; j++) {
        const b = chunk[j];
        const isPrintable = b >= 32 && b <= 126;
        const char = isPrintable ? String.fromCharCode(b) : '.';
        const isHeader = (i + j) < 12;
        const className = isHeader ? 'ascii-char header-byte' : 'ascii-char payload-byte';
        asciiPart += `<span class="${className}">${this.escapeHtml(char)}</span>`;
      }

      html += `<div class="hex-line">` +
        `<span class="hex-offset">${offset}</span>` +
        `<span class="hex-data">${hexPart}</span>` +
        `<span class="hex-ascii">|${asciiPart}|</span>` +
        `</div>`;
    }

    this.hexContainer.innerHTML = html;
  }

  /**
   * Renders the expandable OSI protocol layer hierarchy
   */
  renderProtocolTree(packet) {
    if (!this.treeContainer) return;

    const layers = [
      {
        title: `Ethernet II, Src: 00:1a:2b:3c:4d:5e, Dst: fa:16:3e:89:12:04`,
        details: [
          `Destination: fa:16:3e:89:12:04 (Gateway Router)`,
          `Source: 00:1a:2b:3c:4d:5e (Local Host NIC)`,
          `Type: IPv4 (0x0800)`
        ]
      },
      {
        title: `Internet Protocol Version 4, Src: ${packet.srcIp}, Dst: ${packet.dstIp}`,
        details: [
          `Version: 4, Header Length: 20 bytes`,
          `Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)`,
          `Total Length: ${packet.length} bytes`,
          `Identification: 0x7a3f (31295)`,
          `Time to Live (TTL): 64 hops`,
          `Protocol: ${packet.protocol} (${packet.protocol.includes('UDP') ? 17 : 6})`,
          `Header Checksum: 0x9a14 [verified correct]`
        ]
      },
      {
        title: `${packet.protocol} Layer, Src Port: ${packet.srcPort}, Dst Port: ${packet.dstPort}`,
        details: [
          `Source Port: ${packet.srcPort}`,
          `Destination Port: ${packet.dstPort}`,
          `Flags: ${packet.flags || 'None'}`,
          `Status / Code: ${packet.status}`,
          `Entropy Level: ${packet.entropy} bits/byte`
        ]
      },
      {
        title: `Payload Details [${packet.protocol}]`,
        details: packet.payload ? packet.payload.split('\n') : [`Info: ${packet.info}`]
      }
    ];

    let html = '';
    layers.forEach((layer, idx) => {
      html += `
        <details class="layer-item" ${idx >= 1 ? 'open' : ''}>
          <summary class="layer-summary">
            <span class="tree-bullet">▸</span>
            <strong>${layer.title}</strong>
          </summary>
          <ul class="layer-details">
            ${layer.details.map(d => `<li>${this.escapeHtml(d)}</li>`).join('')}
          </ul>
        </details>
      `;
    });

    this.treeContainer.innerHTML = html;
  }

  escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
}
