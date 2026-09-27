/**
 * NetPulse Cybernetic Audio Telemetry Engine
 * Generates tactile hacker audio feedback:
 * - High-speed packet tick pulses
 * - Handshake success chime
 * - Tactical threat alarm / intercept radar ping
 * Zero external audio files required!
 */

export class SonarAudio {
  constructor() {
    this.ctx = null;
    this.isEnabled = false;
    this.masterGain = null;
  }

  init() {
    if (this.ctx) return;
    const AudioContext = window.AudioContext || window.webkitAudioContext;
    this.ctx = new AudioContext();
    this.masterGain = this.ctx.createGain();
    this.masterGain.gain.setValueAtTime(0.2, this.ctx.currentTime);
    this.masterGain.connect(this.ctx.destination);
  }

  toggle() {
    this.init();
    if (this.ctx.state === 'suspended') {
      this.ctx.resume();
    }
    this.isEnabled = !this.isEnabled;
    return this.isEnabled;
  }

  /**
   * Subtle high-frequency blip for standard packet ingress
   */
  playPacketBlip(protocol) {
    if (!this.isEnabled || !this.ctx) return;

    const osc = this.ctx.createOscillator();
    const gain = this.ctx.createGain();

    let freq = 1200;
    if (protocol === 'DNS') freq = 1600;
    if (protocol === 'TLS 1.3') freq = 900;
    if (protocol === 'HTTP/2') freq = 1400;

    osc.type = 'sine';
    osc.frequency.setValueAtTime(freq, this.ctx.currentTime);

    gain.gain.setValueAtTime(0.04, this.ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.0001, this.ctx.currentTime + 0.04);

    osc.connect(gain);
    gain.connect(this.masterGain);

    osc.start();
    osc.stop(this.ctx.currentTime + 0.045);
  }

  /**
   * Tactical alert siren for security threat detections
   */
  playThreatAlert() {
    if (!this.isEnabled || !this.ctx) return;

    const osc = this.ctx.createOscillator();
    const gain = this.ctx.createGain();

    osc.type = 'sawtooth';
    osc.frequency.setValueAtTime(350, this.ctx.currentTime);
    osc.frequency.linearRampToValueAtTime(180, this.ctx.currentTime + 0.25);

    gain.gain.setValueAtTime(0.15, this.ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, this.ctx.currentTime + 0.28);

    osc.connect(gain);
    gain.connect(this.masterGain);

    osc.start();
    osc.stop(this.ctx.currentTime + 0.3);
  }
}
