/**
 * NetPulse Security & Cryptographic Toolbox
 * Includes:
 * 1. Shannon Entropy Calculator (Malware & Encrypted C2 detection)
 * 2. JWT Inspector & Vulnerability Checker
 * 3. Multi-format Payload Converter (Hex, Base64, URL, ROT13, Binary)
 * 4. Custom Packet Crafting & Injection
 */

export class SecurityTools {
  /**
   * Calculates Shannon Entropy of a string (0 - 8 bits/byte)
   */
  static calculateEntropy(text) {
    if (!text || text.length === 0) return { score: 0, category: 'Empty' };

    const freq = {};
    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      freq[char] = (freq[char] || 0) + 1;
    }

    let entropy = 0;
    const len = text.length;
    for (const char in freq) {
      const p = freq[char] / len;
      entropy -= p * Math.log2(p);
    }

    entropy = parseFloat(entropy.toFixed(3));

    let category = 'Plaintext Code / Text';
    let risk = 'low';

    if (entropy > 7.1) {
      category = 'Encrypted / High Randomness (Shellcode / Packed Binary)';
      risk = 'high';
    } else if (entropy > 5.2) {
      category = 'Obfuscated / Base64 / Encoded Stream';
      risk = 'medium';
    } else if (entropy < 2.5) {
      category = 'Low Entropy / Repetitive Pattern';
      risk = 'low';
    }

    return { score: entropy, category, risk };
  }

  /**
   * Decode and inspect JSON Web Tokens
   */
  static decodeJWT(jwtString) {
    try {
      const parts = jwtString.trim().split('.');
      if (parts.length !== 3) {
        return { error: 'Invalid JWT structure: Token must contain exactly 3 segments separated by dots.' };
      }

      const decodeBase64Url = (str) => {
        let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4) {
          base64 += '=';
        }
        return JSON.parse(decodeURIComponent(escape(atob(base64))));
      };

      const header = decodeBase64Url(parts[0]);
      const payload = decodeBase64Url(parts[1]);
      const signature = parts[2];

      const vulnerabilities = [];
      if (header.alg && header.alg.toLowerCase() === 'none') {
        vulnerabilities.push('CRITICAL: Token algorithm set to "none" (Authentication Bypass vulnerability)');
      }
      if (payload.exp && Date.now() / 1000 > payload.exp) {
        vulnerabilities.push(`WARNING: Token expired on ${new Date(payload.exp * 1000).toLocaleString()}`);
      }

      return {
        header,
        payload,
        signature,
        vulnerabilities
      };
    } catch (e) {
      return { error: `Failed to decode JWT: ${e.message}` };
    }
  }

  /**
   * Converts input string across various formats
   */
  static convertPayload(input, action) {
    if (!input) return '';

    try {
      switch (action) {
        case 'to-base64':
          return btoa(unescape(encodeURIComponent(input)));
        case 'from-base64':
          return decodeURIComponent(escape(atob(input)));
        case 'to-hex':
          return Array.from(input)
            .map(c => c.charCodeAt(0).toString(16).padStart(2, '0'))
            .join(' ');
        case 'from-hex':
          const cleanHex = input.replace(/\s+/g, '');
          let hexOut = '';
          for (let i = 0; i < cleanHex.length; i += 2) {
            hexOut += String.fromCharCode(parseInt(cleanHex.substr(i, 2), 16));
          }
          return hexOut;
        case 'to-url':
          return encodeURIComponent(input);
        case 'from-url':
          return decodeURIComponent(input);
        case 'rot13':
          return input.replace(/[a-zA-Z]/g, function (c) {
            return String.fromCharCode(
              (c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26
            );
          });
        default:
          return input;
      }
    } catch (err) {
      return `[ERROR: ${err.message}]`;
    }
  }
}
