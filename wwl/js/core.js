/* core.js - Web Wireshark Lite 共享工具函数 */
(function (global) {
  'use strict';
  const WWL = global.WWL = global.WWL || {};

  function pad(n, w) {
    let s = String(n);
    while (s.length < w) s = '0' + s;
    return s;
  }
  WWL.pad = pad;

  function hex4(n) { return pad((n & 0xffff).toString(16).toUpperCase(), 4); }
  WWL.hex4 = hex4;
  function hex8(n) { return pad((n >>> 0).toString(16).toUpperCase(), 8); }
  WWL.hex8 = hex8;

  function u8hex(b) { return pad(b.toString(16), 2); }
  WWL.u8hex = u8hex;

  function macToString(bytes, offset) {
    offset = offset || 0;
    let out = '';
    for (let i = 0; i < 6; i++) {
      if (i) out += ':';
      out += u8hex(bytes[offset + i]);
    }
    return out;
  }
  WWL.macToString = macToString;

  function ip4ToString(bytes, offset) {
    offset = offset || 0;
    return bytes[offset] + '.' + bytes[offset + 1] + '.' + bytes[offset + 2] + '.' + bytes[offset + 3];
  }
  WWL.ip4ToString = ip4ToString;

  function ip6ToString(bytes, offset) {
    offset = offset || 0;
    const groups = [];
    for (let i = 0; i < 16; i += 2) groups.push((bytes[offset + i] << 8) | bytes[offset + i + 1]);
    let bestStart = -1, bestLen = 0;
    for (let i = 0; i < 8;) {
      if (groups[i] === 0) {
        let j = i;
        while (j < 8 && groups[j] === 0) j++;
        if (j - i > bestLen) { bestLen = j - i; bestStart = i; }
        i = j;
      } else i++;
    }
    if (bestLen < 2) bestStart = -1;
    const parts = [];
    for (let i = 0; i < 8; i++) {
      if (i === bestStart) { parts.push(''); i += bestLen - 1; continue; }
      parts.push(groups[i].toString(16));
    }
    let s = parts.join(':');
    if (bestStart >= 0) s = s.replace(/:{3,}/, '::');
    return s;
  }
  WWL.ip6ToString = ip6ToString;

  function formatBytes(n) {
    if (!isFinite(n)) return '-';
    if (n < 1024) return n + ' B';
    const units = ['KB', 'MB', 'GB', 'TB'];
    let v = n, u = 'B';
    for (let i = 0; i < units.length; i++) {
      if (v < 1024) break;
      v /= 1024;
      u = units[i];
    }
    return (v >= 100 ? v.toFixed(0) : v.toFixed(1)) + ' ' + u;
  }
  WWL.formatBytes = formatBytes;

  function formatTime(ts) {
    if (!isFinite(ts)) return '-';
    const d = new Date(ts * 1000);
    if (isNaN(d.getTime())) return '-';
    const frac = ts - Math.floor(ts);
    const f = Math.round(frac * 1e6);
    let s = d.toISOString().replace('T', ' ').replace('Z', '');
    s = s.slice(0, 19) + '.' + pad(f, 6);
    return s;
  }
  WWL.formatTime = formatTime;

  function formatDuration(sec) {
    if (!isFinite(sec) || sec < 0) return '-';
    if (sec < 1) return (sec * 1000).toFixed(2) + ' ms';
    if (sec < 60) return sec.toFixed(3) + ' s';
    const m = Math.floor(sec / 60);
    const s = sec - m * 60;
    if (m < 60) return m + ' min ' + s.toFixed(1) + ' s';
    const h = Math.floor(m / 60);
    return h + ' h ' + (m % 60) + ' min';
  }
  WWL.formatDuration = formatDuration;

  function makeHexDump(u8, startOffset) {
    const rows = [];
    const n = u8.length;
    startOffset = startOffset || 0;
    for (let i = 0; i < n; i += 16) {
      const end = Math.min(i + 16, n);
      let hex = '', ascii = '';
      for (let j = i; j < end; j++) {
        hex += u8hex(u8[j]) + ' ';
        const c = u8[j];
        ascii += (c >= 32 && c <= 126) ? String.fromCharCode(c) : '.';
      }
      rows.push({ off: startOffset + i, hex: hex.trim(), ascii: ascii });
    }
    return rows;
  }
  WWL.makeHexDump = makeHexDump;

  function makeInterner() {
    const m = new Map();
    return function (s) {
      let v = m.get(s);
      if (v === undefined) { v = s; m.set(s, v); }
      return v;
    };
  }
  WWL.makeInterner = makeInterner;

  WWL.isIPv4Str = function (s) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(s); };
  WWL.isIPv6Str = function (s) { return typeof s === 'string' && s.indexOf(':') >= 0; };

  WWL.ETHER_TYPES = {
    0x0800: 'IPv4', 0x86dd: 'IPv6', 0x0806: 'ARP', 0x8035: 'RARP',
    0x8100: '802.1Q VLAN', 0x88a8: '802.1ad QinQ', 0x9100: 'QinQ',
    0x8847: 'MPLS', 0x8848: 'MPLS', 0x8864: 'PPPoE Session', 0x8863: 'PPPoE Discovery',
    0x88cc: 'LLDP', 0x8808: 'PAUSE', 0x88b5: 'IEEE 802.1X', 0x2000: 'Cisco Discovery Protocol',
    0x8809: 'Slow Protocols (LACP)', 0x888e: 'EAPOL (802.1X)', 0x9000: 'Ethernet Configuration Test'
  };

  WWL.WELL_KNOWN_PORTS = {
    20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 80: 'HTTP', 110: 'POP3', 123: 'NTP',
    137: 'NetBIOS-NS', 143: 'IMAP', 161: 'SNMP', 179: 'BGP', 194: 'IRC',
    389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 514: 'Syslog',
    587: 'SMTP', 853: 'DoT', 990: 'FTPS', 993: 'IMAPS', 995: 'POP3S',
    1080: 'SOCKS', 1194: 'OpenVPN', 1900: 'SSDP', 3306: 'MySQL', 3389: 'RDP',
    5060: 'SIP', 5061: 'SIPS', 5222: 'XMPP', 5353: 'mDNS', 5432: 'PostgreSQL',
    6379: 'Redis', 8080: 'HTTP', 8443: 'HTTPS', 8888: 'HTTP', 9090: 'HTTP',
    27017: 'MongoDB'
  };

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }
  WWL.escapeHtml = escapeHtml;
})(typeof window !== 'undefined' ? window : globalThis);
