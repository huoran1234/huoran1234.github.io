/* stats.js - 协议统计、流量统计、Top Talkers、Top Ports */
(function (global) {
  'use strict';
  const WWL = global.WWL = global.WWL || {};

  const PROTO_LABEL = {
    tcp: 'TCP', udp: 'UDP', http: 'HTTP', tls: 'TLS', dns: 'DNS', dhcp: 'DHCP',
    icmp: 'ICMP', icmpv6: 'ICMPv6', arp: 'ARP', ipv4: 'IPv4', ipv6: 'IPv6',
    igmp: 'IGMP', esp: 'ESP', ah: 'AH', gre: 'GRE', ospf: 'OSPF', sctp: 'SCTP',
    mpls: 'MPLS', ppp: 'PPP', llc: 'LLC', wlan: '802.11', vxlan: 'VXLAN', bgp: 'BGP',
    tacacs: 'TACACS', vrrp: 'VRRP', eigrp: 'EIGRP', stp: 'STP', lldp: 'LLDP', cdp: 'CDP',
    radius: 'RADIUS', ntp: 'NTP', tftp: 'TFTP', ssh: 'SSH', ftp: 'FTP', telnet: 'Telnet',
    smtp: 'SMTP', pop3: 'POP3', imap: 'IMAP', sip: 'SIP', pptp: 'PPTP',
    lacp: 'LACP', eapol: 'EAPOL', eap: 'EAP', hsrp: 'HSRP', bfd: 'BFD',
    ib: 'InfiniBand', slow: 'Slow Protocols', other: 'Other'
  };

  WWL.Stats = {
    protocolLabel: function (proto) {
      return PROTO_LABEL[proto] || (proto ? proto.toUpperCase() : 'Other');
    },

    compute: function (packets) {
      const total = packets.length;
      const protoMap = new Map();
      const srcMap = new Map();
      const dstMap = new Map();
      const tcpPortMap = new Map();
      const udpPortMap = new Map();
      let totalBytes = 0;
      let startT = Infinity, endT = -Infinity;

      for (let i = 0; i < total; i++) {
        const p = packets[i];
        totalBytes += p.len;
        if (p.t < startT) startT = p.t;
        if (p.t > endT) endT = p.t;

        const proto = p.proto || 'other';
        protoMap.set(proto, (protoMap.get(proto) || 0) + 1);

        if (p.src) {
          const s = srcMap.get(p.src) || { count: 0, bytes: 0 };
          s.count++;
          s.bytes += p.len;
          srcMap.set(p.src, s);
        }
        if (p.dst) {
          const d = dstMap.get(p.dst) || { count: 0, bytes: 0 };
          d.count++;
          d.bytes += p.len;
          dstMap.set(p.dst, d);
        }
        if (p.tproto === 'tcp') {
          if (p.sport) tcpPortMap.set(p.sport, (tcpPortMap.get(p.sport) || 0) + 1);
          if (p.dport) tcpPortMap.set(p.dport, (tcpPortMap.get(p.dport) || 0) + 1);
        } else if (p.tproto === 'udp') {
          if (p.sport) udpPortMap.set(p.sport, (udpPortMap.get(p.sport) || 0) + 1);
          if (p.dport) udpPortMap.set(p.dport, (udpPortMap.get(p.dport) || 0) + 1);
        }
      }

      const protocols = [];
      protoMap.forEach(function (count, proto) {
        protocols.push({
          name: WWL.Stats.protocolLabel(proto),
          count: count,
          pct: total ? count / total * 100 : 0
        });
      });
      protocols.sort(function (a, b) { return b.count - a.count; });

      const topSrc = topN(srcMap, 20);
      const topDst = topN(dstMap, 20);
      const topTcp = topPorts(tcpPortMap, 20);
      const topUdp = topPorts(udpPortMap, 20);

      return {
        total: total,
        totalBytes: totalBytes,
        avgSize: total ? totalBytes / total : 0,
        startT: isFinite(startT) ? startT : 0,
        endT: isFinite(endT) ? endT : 0,
        duration: isFinite(startT) && isFinite(endT) && endT >= startT ? endT - startT : 0,
        pps: (isFinite(startT) && endT > startT) ? total / (endT - startT) : 0,
        protocols: protocols,
        topSrc: topSrc,
        topDst: topDst,
        topTcp: topTcp,
        topUdp: topUdp
      };
    }
  };

  function topN(map, n) {
    const arr = [];
    map.forEach(function (v, k) { arr.push({ key: k, count: v.count, bytes: v.bytes }); });
    arr.sort(function (a, b) { return b.count - a.count || b.bytes - a.bytes; });
    return arr.slice(0, n);
  }

  function topPorts(map, n) {
    const arr = [];
    map.forEach(function (count, port) { arr.push({ port: port, count: count, service: WWL.WELL_KNOWN_PORTS[port] || '' }); });
    arr.sort(function (a, b) { return b.count - a.count; });
    return arr.slice(0, n);
  }

  /* 协议分层（Wireshark Protocol Hierarchy 风格） */
  WWL.Stats.hierarchy = function (packets) {
    const root = { name: '所有帧 (All frames)', count: 0, children: new Map() };
    function chainOf(p) {
      const chain = [];
      if (p.l2 === 'wlan') chain.push('IEEE 802.11');
      else if (p.l2 === 'sll') chain.push('Linux cooked');
      else if (p.l2 === 'raw') chain.push('Raw IP');
      else if (p.l2 === 'ppp') chain.push('PPP');
      else if (p.l2 === 'null') chain.push('Loopback');
      else if (p.macSrc || p.macDst) chain.push('Ethernet');
      if (p.tunnel) chain.push(WWL.Stats.protocolLabel(p.tunnel));
      if (p.l3) chain.push(WWL.Stats.protocolLabel(p.l3));
      if (p.tproto) chain.push(WWL.Stats.protocolLabel(p.tproto));
      if (p.proto) {
        const top = WWL.Stats.protocolLabel(p.proto);
        if (p.proto !== p.l3 && p.proto !== p.tproto && p.proto !== 'ipv4' && p.proto !== 'ipv6' && top !== chain[chain.length - 1]) {
          chain.push(top);
        }
      }
      const out = [];
      for (let i = 0; i < chain.length; i++) if (out[out.length - 1] !== chain[i]) out.push(chain[i]);
      return out;
    }
    for (let i = 0; i < packets.length; i++) {
      const p = packets[i];
      root.count++;
      let cur = root;
      const chain = chainOf(p);
      for (let j = 0; j < chain.length; j++) {
        let child = cur.children.get(chain[j]);
        if (!child) {
          child = { name: chain[j], count: 0, children: new Map() };
          cur.children.set(chain[j], child);
        }
        child.count++;
        cur = child;
      }
    }
    function conv(node) {
      const arr = [];
      node.children.forEach(function (child) { arr.push(conv(child)); });
      arr.sort(function (a, b) { return b.count - a.count || a.name.localeCompare(b.name); });
      return {
        name: node.name,
        count: node.count,
        pct: root.count ? node.count / root.count * 100 : 0,
        children: arr
      };
    }
    return conv(root);
  };

  /* 流量分析：吞吐量时间桶、包长分布、TCP 标志位 */
  WWL.Stats.traffic = function (packets) {
    const total = packets.length;
    if (!total) {
      return { labels: [], series: [], lengths: [], tcpFlags: [], startT: 0, endT: 0 };
    }
    let startT = Infinity, endT = -Infinity;
    for (let i = 0; i < total; i++) {
      if (packets[i].t < startT) startT = packets[i].t;
      if (packets[i].t > endT) endT = packets[i].t;
    }
    const dur = Math.max(endT - startT, 1e-9);
    const bucketCount = Math.min(dur < 1 ? 200 : 150, Math.max(30, Math.round(total / 200)));
    const bucketSize = dur / bucketCount;

    const protoTotal = new Map();
    for (let i = 0; i < total; i++) {
      const label = WWL.Stats.protocolLabel(packets[i].proto);
      protoTotal.set(label, (protoTotal.get(label) || 0) + packets[i].len);
    }
    const topNames = Array.from(protoTotal.entries()).sort(function (a, b) { return b[1] - a[1]; }).slice(0, 6).map(function (e) { return e[0]; });
    const series = topNames.map(function (name, i) {
      return { name: name, color: WWL.Charts.colors[i % WWL.Charts.colors.length], values: new Array(bucketCount).fill(0) };
    });
    const other = { name: 'Other', color: '#6b7280', values: new Array(bucketCount).fill(0) };

    const lenBounds = [64, 128, 256, 512, 1024, 1518, Infinity];
    const lenLabels = ['0-63', '64-127', '128-255', '256-511', '512-1023', '1024-1517', '1518+'];
    const lengths = new Array(7).fill(0);
    const tcpFlagCounts = { SYN: 0, ACK: 0, RST: 0, FIN: 0, PSH: 0, URG: 0, ECE: 0, CWR: 0 };

    for (let i = 0; i < total; i++) {
      const p = packets[i];
      const idx = Math.min(bucketCount - 1, Math.floor((p.t - startT) / bucketSize));
      const label = WWL.Stats.protocolLabel(p.proto);
      const si = topNames.indexOf(label);
      (si >= 0 ? series[si] : other).values[idx] += p.len;
      for (let b = 0; b < lenBounds.length; b++) {
        if (p.len <= lenBounds[b]) { lengths[b]++; break; }
      }
      if (p.tcpFlags) {
        if (p.tcpFlags & 0x02) tcpFlagCounts.SYN++;
        if (p.tcpFlags & 0x10) tcpFlagCounts.ACK++;
        if (p.tcpFlags & 0x04) tcpFlagCounts.RST++;
        if (p.tcpFlags & 0x01) tcpFlagCounts.FIN++;
        if (p.tcpFlags & 0x08) tcpFlagCounts.PSH++;
        if (p.tcpFlags & 0x20) tcpFlagCounts.URG++;
        if (p.tcpFlags & 0x40) tcpFlagCounts.ECE++;
        if (p.tcpFlags & 0x80) tcpFlagCounts.CWR++;
      }
    }
    if (other.values.some(function (v) { return v > 0; })) series.push(other);

    const labels = [];
    for (let i = 0; i < bucketCount; i++) {
      const t = startT + i * bucketSize - startT;
      labels.push(t < 1 ? (t * 1000).toFixed(1) + 'ms' : t < 60 ? t.toFixed(2) + 's' : Math.floor(t / 60) + 'm' + Math.round(t % 60) + 's');
    }
    const flagData = Object.keys(tcpFlagCounts).map(function (k) {
      return { label: k, value: tcpFlagCounts[k] };
    });
    const lenData = lengths.map(function (v, i) { return { label: lenLabels[i], value: v }; });
    return { labels: labels, series: series, lengths: lenData, tcpFlags: flagData, startT: startT, endT: endT, bucketSize: bucketSize };
  };
})(typeof window !== 'undefined' ? window : globalThis);
