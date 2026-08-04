/* dissect.js - 数据包协议解析：快速摘要路径（大数据量）与完整详情树路径 */
(function (global) {
  'use strict';
  const WWL = global.WWL = global.WWL || {};

  const IP_PROTO = {
    1: 'ICMP', 2: 'IGMP', 4: 'IPIP', 6: 'TCP', 17: 'UDP', 47: 'GRE',
    50: 'ESP', 51: 'AH', 58: 'ICMPv6', 89: 'OSPF', 103: 'PIM', 132: 'SCTP'
  };

  const ICMP_TYPES = {
    0: 'Echo (ping) reply', 3: 'Destination unreachable', 4: 'Source quench',
    5: 'Redirect', 8: 'Echo (ping) request', 9: 'Router advertisement',
    10: 'Router solicitation', 11: 'Time exceeded', 12: 'Parameter problem',
    13: 'Timestamp request', 14: 'Timestamp reply',
    17: 'Address mask request', 18: 'Address mask reply'
  };
  const ICMP_UNREACH = {
    0: 'Network unreachable', 1: 'Host unreachable', 2: 'Protocol unreachable',
    3: 'Port unreachable', 4: 'Fragmentation needed', 5: 'Source route failed'
  };

  const ICMP6_TYPES = {
    1: 'Destination unreachable', 2: 'Packet too big', 3: 'Time exceeded',
    4: 'Parameter problem', 128: 'Echo (ping) request', 129: 'Echo (ping) reply',
    130: 'Multicast listener query', 131: 'Multicast listener report',
    132: 'Multicast listener done', 133: 'Router solicitation',
    134: 'Router advertisement', 135: 'Neighbor solicitation',
    136: 'Neighbor advertisement', 137: 'Redirect'
  };

  const TLS_VER = {
    0x0300: 'SSLv3', 0x0301: 'TLSv1.0', 0x0302: 'TLSv1.1',
    0x0303: 'TLSv1.2', 0x0304: 'TLSv1.3'
  };
  const TLS_CONTENT = {
    20: 'Change Cipher Spec', 21: 'Alert', 22: 'Handshake',
    23: 'Application Data', 24: 'Heartbeat'
  };
  const TLS_HS = {
    1: 'Client Hello', 2: 'Server Hello', 4: 'New Session Ticket',
    8: 'Encrypted Extensions', 11: 'Certificate', 12: 'Server Key Exchange',
    13: 'Certificate Request', 14: 'Server Hello Done', 15: 'Certificate Verify',
    16: 'Client Key Exchange', 20: 'Finished'
  };

  const DNS_TYPES = {
    1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT',
    28: 'AAAA', 33: 'SRV', 35: 'NAPTR', 41: 'OPT', 43: 'DS', 46: 'RRSIG',
    47: 'NSEC', 48: 'DNSKEY', 99: 'SPF', 251: 'IXFR', 252: 'AXFR', 255: 'ANY'
  };

  const DHCP_MSGS = {
    1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline', 5: 'ACK',
    6: 'NAK', 7: 'Release', 8: 'Inform'
  };
  const DHCP_OPT_NAMES = {
    1: 'Subnet Mask', 3: 'Router', 6: 'Domain Name Server', 12: 'Host Name',
    15: 'Domain Name', 50: 'Requested IP Address', 51: 'IP Address Lease Time',
    53: 'Message Type', 54: 'Server Identifier', 55: 'Parameter Request List',
    57: 'Maximum DHCP Message Size', 58: 'Renewal Time Value',
    59: 'Rebinding Time Value', 61: 'Client Identifier', 82: 'Relay Agent Information'
  };

  const DOT11_TYPE_NAMES = { 0: 'Management', 1: 'Control', 2: 'Data', 3: 'Extension' };
  const DOT11_SUBTYPE_MGMT = [
    'Association Request', 'Association Response', 'Reassociation Request', 'Reassociation Response',
    'Probe Request', 'Probe Response', 'Timing Advertisement', 'Reserved', 'Beacon', 'ATIM',
    'Disassociation', 'Authentication', 'Deauthentication', 'Action', 'Action No Ack', 'Reserved'
  ];
  const DOT11_SUBTYPE_CTRL = [
    'Reserved', 'Reserved', 'Reserved', 'Reserved', 'Reserved', 'Reserved', 'Reserved', 'Reserved',
    'Block Ack Request', 'Block Ack', 'PS-Poll', 'RTS', 'CTS', 'ACK', 'CF-End', 'CF-End+CF-Ack'
  ];
  const DOT11_SUBTYPE_DATA = [
    'Data', 'Data+CF-Ack', 'Data+CF-Poll', 'Data+CF-Ack+CF-Poll', 'Null', 'CF-Ack', 'CF-Poll',
    'CF-Ack+CF-Poll', 'QoS Data', 'QoS Data+CF-Ack', 'QoS Data+CF-Poll', 'Reserved', 'QoS Null',
    'Reserved', 'Reserved', 'Reserved'
  ];
  const PPP_PROTO = {
    0x0021: 'IPv4', 0x0057: 'IPv6', 0xc021: 'Link Control Protocol',
    0xc023: 'Password Authentication Protocol', 0xc223: 'Challenge Handshake Authentication Protocol',
    0x8021: 'IPv4 Control Protocol', 0x8057: 'IPv6 Control Protocol'
  };

  function Reader(u8, little) {
    this.b = u8;
    this.dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    this.p = 0;
    this.le = !!little;
  }
  Reader.prototype.u8 = function () { return this.b[this.p++]; };
  Reader.prototype.u16 = function () { const v = this.dv.getUint16(this.p, this.le); this.p += 2; return v; };
  Reader.prototype.u24 = function () {
    const v = (this.b[this.p] << 16) | (this.b[this.p + 1] << 8) | this.b[this.p + 2];
    this.p += 3;
    return v >>> 0;
  };
  Reader.prototype.u32 = function () { const v = this.dv.getUint32(this.p, this.le); this.p += 4; return v >>> 0; };
  Reader.prototype.bytes = function (n) { const s = this.p; this.p += n; return this.b.subarray(s, this.p); };
  Reader.prototype.skip = function (n) { this.p += n; };
  Reader.prototype.remaining = function () { return this.b.length - this.p; };
  Reader.prototype.seek = function (p) { this.p = p; };

  function node(name, value, range, children) {
    return { name: name || '', value: value !== undefined && value !== null ? String(value) : '', range: range || null, children: children || [] };
  }

  function etherTypeName(t) {
    const n = WWL.ETHER_TYPES[t];
    return n ? n + ' (0x' + WWL.hex4(t) + ')' : 'Unknown (0x' + WWL.hex4(t) + ')';
  }

  function tcpFlagsList(f) {
    const n = [];
    if (f & 0x01) n.push('FIN');
    if (f & 0x02) n.push('SYN');
    if (f & 0x04) n.push('RST');
    if (f & 0x08) n.push('PSH');
    if (f & 0x10) n.push('ACK');
    if (f & 0x20) n.push('URG');
    if (f & 0x40) n.push('ECE');
    if (f & 0x80) n.push('CWR');
    if (f & 0x100) n.push('NS');
    return n.join(', ');
  }

  function flagChildren(f, off) {
    const rows = [
      ['FIN', 0x01], ['SYN', 0x02], ['RST', 0x04], ['PSH', 0x08], ['ACK', 0x10],
      ['URG', 0x20], ['ECE', 0x40], ['CWR', 0x80], ['NS', 0x100]
    ];
    return rows.map(function (r) {
      return node('.... .... .... ...' + r[0] + ' = ' + ((f & r[1]) ? 'Set' : 'Not set'), '', [off, off + 1]);
    });
  }

  function asciiBytes(u8) {
    let s = '';
    for (let i = 0; i < u8.length; i++) {
      const c = u8[i];
      s += (c >= 32 && c <= 126) ? String.fromCharCode(c) : '.';
    }
    return s;
  }
  function hexBytes(u8) {
    let s = '';
    for (let i = 0; i < u8.length; i++) s += WWL.u8hex(u8[i]);
    return s;
  }

  /* ---------------- Layer 2 ---------------- */
  function ethernetDissect(r, m, tree) {
    const start = r.p;
    const macDst = WWL.macToString(r.bytes(6));
    const macSrc = WWL.macToString(r.bytes(6));
    m.macDst = macDst;
    m.macSrc = macSrc;
    let etherType = r.u16();
    const tags = [];
    while ((etherType === 0x8100 || etherType === 0x88a8 || etherType === 0x9100) && r.remaining() >= 4 && tags.length < 4) {
      const tagStart = r.p;
      const tci = r.u16();
      tags.push({
        pri: tci >> 13, dei: (tci >> 12) & 1, vid: tci & 0xfff,
        range: [tagStart, tagStart + 4]
      });
      etherType = r.u16();
    }
    m.ethType = etherType;
    const end = r.p;
    m.l2 = 'eth';
    if (tree) {
      const e = node('Ethernet II, Src: ' + macSrc + ', Dst: ' + macDst, '', [start, end], [
        node('Destination', macDst, [start, start + 6]),
        node('Source', macSrc, [start + 6, start + 12]),
        node('Type', etherTypeName(etherType), [end - 2, end])
      ]);
      tags.forEach(function (t) {
        e.children.push(node(
          '802.1Q Virtual LAN, PRI: ' + t.pri + ', DEI: ' + t.dei + ', ID: ' + t.vid,
          '', t.range
        ));
      });
      tree.push(e);
    }
    let l3Handled = false;
    if (etherType < 0x0600) {
      // 802.3 长度字段 + LLC/SNAP
      if (tree) {
        const e2 = tree[tree.length - 1];
        e2.name = 'IEEE 802.3 Ethernet, Src: ' + macSrc + ', Dst: ' + macDst;
        e2.children[e2.children.length - 1] = node('Length', etherType, [end - 2, end]);
      }
      const llcStart = r.p;
      const llcRes = llcSnap(r, m, tree, llcStart);
      if (llcRes.l3Handled) l3Handled = true;
    }
    return { end: r.p, l3Handled: l3Handled };
  }

  function llcSnap(r, m, tree, start) {
    const dsap = r.u8(), ssap = r.u8(), ctrl = r.u8();
    if (dsap === 0x42 && ssap === 0x42 && ctrl === 0x03 && r.remaining() >= 35) {
      // 802.1D 生成树 BPDU
      stpDissect(r, m, tree, r.p);
      return { proto: 0, l3Handled: true };
    }
    if (dsap === 0x80 && ssap === 0x80 && r.remaining() >= 1) {
      // 802.3 慢协议（LACP / Marker / OAM 等，经 LLC 封装）
      slowProtocolsDissect(r, m, tree, r.p);
      return { proto: 0, l3Handled: true };
    }
    if (tree) {
      tree.push(node('Logical Link Control (LLC) header', '', [start, r.p], [
        node('Destination SAP', dsap + (dsap === 0xaa ? ' (SNAP)' : ''), [start, start + 1]),
        node('Source SAP', ssap + (ssap === 0xaa ? ' (SNAP)' : ''), [start + 1, start + 2]),
        node('Control field', '0x' + WWL.u8hex(ctrl), [start + 2, start + 3])
      ]));
    }
    if (dsap === 0xaa && ssap === 0xaa && r.remaining() >= 5) {
      const ouiB = r.bytes(3);
      const proto = r.u16();
      const oui = WWL.pad(((ouiB[0] << 16) | (ouiB[1] << 8) | ouiB[2]).toString(16), 6);
      m.ethType = proto;
      if (tree) {
        tree.push(node('SNAP header', '', [start + 3, r.p], [
          node('OUI', '0x' + oui, [start + 3, start + 6]),
          node('Protocol ID', etherTypeName(proto), [start + 6, start + 8])
        ]));
      }
      return { proto: proto, l3Handled: false };
    }
    m.ethType = 0;
    m.proto = 'llc';
    m.info = 'IEEE 802.3 LLC (DSAP: ' + dsap + ', SSAP: ' + ssap + ')';
    return { proto: 0, l3Handled: true };
  }

  function dot11SubtypeName(type, subtype) {
    if (type === 0) return DOT11_SUBTYPE_MGMT[subtype] || ('Subtype ' + subtype);
    if (type === 1) return DOT11_SUBTYPE_CTRL[subtype] || ('Subtype ' + subtype);
    if (type === 2) return DOT11_SUBTYPE_DATA[subtype] || ('Subtype ' + subtype);
    return 'Subtype ' + subtype;
  }

  function dot11Dissect(r, m, tree, start) {
    const p0 = r.p;
    // 802.11 头部字段为小端序，与文件字节序无关
    const fc = r.b[r.p] | (r.b[r.p + 1] << 8);
    r.p += 2;
    const version = fc & 0x3;
    const type = (fc >> 2) & 0x3;
    const subtype = (fc >> 4) & 0xf;
    const toDs = !!(fc & 0x0100), fromDs = !!(fc & 0x0200);
    const moreFrag = !!(fc & 0x0400), retry = !!(fc & 0x0800);
    const pwrMgmt = !!(fc & 0x1000), moreData = !!(fc & 0x2000);
    const protectedF = !!(fc & 0x4000), order = !!(fc & 0x8000);
    const duration = r.b[r.p] | (r.b[r.p + 1] << 8);
    r.p += 2;
    const addr1 = WWL.macToString(r.bytes(6));
    let addr2 = '', addr3 = '';
    if (r.remaining() >= 12) addr2 = WWL.macToString(r.bytes(6));
    if (r.remaining() >= 6) addr3 = WWL.macToString(r.bytes(6));
    let seqCtrl = 0;
    if (r.remaining() >= 2) {
      seqCtrl = r.b[r.p] | (r.b[r.p + 1] << 8);
      r.p += 2;
    }
    let addr4 = '';
    if (toDs && fromDs && r.remaining() >= 6) addr4 = WWL.macToString(r.bytes(6));
    const isQos = type === 2 && (subtype & 0x8);
    if (isQos && r.remaining() >= 2) r.skip(2);
    if (order && r.remaining() >= 4) r.skip(4); // HT Control
    const hdrEnd = r.p;
    const typeName = DOT11_TYPE_NAMES[type] || ('Type ' + type);
    const subName = dot11SubtypeName(type, subtype);
    m.l2 = 'wlan';
    m.proto = 'wlan';
    m.macDst = addr1;
    m.macSrc = addr2;
    if (type === 0) { m.src = addr2; m.dst = addr1; }
    else if (type === 2) {
      if (toDs && fromDs) { m.src = addr4; m.dst = addr3; }
      else if (toDs) { m.src = addr2; m.dst = addr3; }
      else if (fromDs) { m.src = addr3; m.dst = addr1; }
      else { m.src = addr2; m.dst = addr1; }
    } else if (type === 1) {
      m.dst = addr1;
      m.src = addr2;
    }
    if (tree) {
      const fcNode = node('Frame Control', '0x' + WWL.hex4(fc), [p0, p0 + 2], [
        node('.... ..00 0000 .... = Protocol version', String(version), [p0, p0 + 2]),
        node('.... ..00 0000 .... = Type', typeName + ' (' + type + ')', [p0, p0 + 2]),
        node('.... ..00 0000 .... = Subtype', subName + ' (' + subtype + ')', [p0, p0 + 2]),
        node('.... .... .0.. .... = To DS', toDs ? 'Set' : 'Not set', [p0, p0 + 2]),
        node('.... .... ..0. .... = From DS', fromDs ? 'Set' : 'Not set', [p0, p0 + 2]),
        node('.... .... ...0 .... = More fragments', moreFrag ? 'Set' : 'Not set', [p0, p0 + 2]),
        node('.... .... .... 0... = Retry', retry ? 'Set' : 'Not set', [p0, p0 + 2]),
        node('.... .... .... .0.. = Power management', pwrMgmt ? 'Set' : 'Not set', [p0, p0 + 2]),
        node('.... .... .... ..0. = More data', moreData ? 'Set' : 'Not set', [p0, p0 + 2]),
        node('.... .... .... ...0 = Protected frame', protectedF ? 'Set' : 'Not set', [p0, p0 + 2])
      ]);
      const w = node('IEEE 802.11 ' + typeName + ', ' + subName, '', [p0, hdrEnd], [
        fcNode,
        node('Duration', duration, [p0 + 2, p0 + 4]),
        node('Destination address', addr1, [p0 + 4, p0 + 10]),
        node('BSS Id', addr3, [p0 + 16, p0 + 22]),
        node('Fragment number', seqCtrl & 0xf, [p0 + 22, p0 + 24]),
        node('Sequence number', seqCtrl >> 4, [p0 + 22, p0 + 24])
      ]);
      if (addr2) w.children.splice(3, 0, node('Source address', addr2, [p0 + 10, p0 + 16]));
      if (addr4) w.children.splice(4, 0, node('Address 4', addr4, [p0 + 24, p0 + 30]));
      tree.push(w);
    }
    m.info = subName + (type === 2 && subtype === 0 ? '' : ' ' + typeName) + ' frame' +
      (m.src ? ', Src: ' + m.src : '') + (m.dst ? ', Dst: ' + m.dst : '');
    if (type === 0 && subtype === 8 && r.remaining() >= 12) {
      // Beacon：Timestamp(8) + Beacon interval(2) + Capability(2)
      const ts = r.u32() + r.u32() * 4294967296;
      const interval = r.u16();
      const caps = r.u16();
      m.info = 'Beacon frame, Beacon Interval: ' + interval + ', Capabilities: 0x' + WWL.hex4(caps);
    }
    // Data 帧负载通常为 LLC/SNAP
    if (type === 2 && r.remaining() >= 8) {
      const llcStart = r.p;
      const llcRes = llcSnap(r, m, tree, llcStart);
      if (!llcRes.l3Handled) {
        if (llcRes.proto === 0x0800) ipv4Dissect(r, m, tree, r.p);
        else if (llcRes.proto === 0x86dd) ipv6Dissect(r, m, tree, r.p);
        else if (llcRes.proto === 0x0806) arpDissect(r, m, tree, r.p);
      }
    }
  }

  function pppDissect(r, m, tree, start, linkType) {
    const p0 = r.p;
    if (linkType === 104) { r.u8(); r.u8(); } // Cisco HDLC: address + control
    else if (linkType === 50 || linkType === 51) {
      const verType = r.u8(), code = r.u8(), session = r.u16(), plen = r.u16();
      if (tree) {
        tree.push(node('PPP over Ethernet', 'Session: ' + session, [start, r.p], [
          node('Version', String(verType >> 4), [start, start + 1]),
          node('Type', String(verType & 0xf), [start, start + 1]),
          node('Code', code, [start + 1, start + 2]),
          node('Session ID', session, [start + 2, start + 4]),
          node('Payload Length', plen, [start + 4, start + 6])
        ]));
      }
    }
    let proto = 0;
    if (r.remaining() >= 2) proto = r.u16();
    const name = PPP_PROTO[proto] || ('0x' + WWL.hex4(proto));
    m.l2 = 'ppp';
    m.ethType = proto === 0x0021 ? 0x0800 : proto === 0x0057 ? 0x86dd : 0;
    if (tree) tree.push(node('PPP Protocol', name, [r.p - 2, r.p]));
    if (proto === 0x0021) { ipv4Dissect(r, m, tree, r.p); return; }
    if (proto === 0x0057) { ipv6Dissect(r, m, tree, r.p); return; }
    m.proto = 'ppp';
    m.info = name + (linkType === 50 || linkType === 51 ? ' (PPPoE)' : '');
  }

  function arpDissect(r, m, tree, start) {
    const htype = r.u16(), ptype = r.u16(), hlen = r.u8(), plen = r.u8(), oper = r.u16();
    m.l3 = 'arp';
    m.proto = 'arp';
    if (tree) {
      tree.push(node('Address Resolution Protocol (' + (oper === 1 ? 'request' : oper === 2 ? 'reply' : 'opcode ' + oper) + ')', '', [start, r.p], [
        node('Hardware type', 'Ethernet (1)', [start, start + 2]),
        node('Protocol type', 'IPv4 (0x0800)', [start + 2, start + 4]),
        node('Hardware size', String(hlen), [start + 4, start + 5]),
        node('Protocol size', String(plen), [start + 5, start + 6]),
        node('Opcode', oper === 1 ? 'request (1)' : oper === 2 ? 'reply (2)' : '(' + oper + ')', [start + 6, start + 8])
      ]));
    }
    if (hlen === 6 && plen === 4 && r.remaining() >= 20) {
      const sha = WWL.macToString(r.bytes(6));
      const spa = WWL.ip4ToString(r.bytes(4));
      const tha = WWL.macToString(r.bytes(6));
      const tpa = WWL.ip4ToString(r.bytes(4));
      m.macSrc = sha;
      m.macDst = tha;
      m.src = spa;
      m.dst = tpa;
      if (tree && tree.length) {
        const a = tree[tree.length - 1];
        a.children.push(
          node('Sender MAC address', sha, [start + 8, start + 14]),
          node('Sender IP address', spa, [start + 14, start + 18]),
          node('Target MAC address', tha, [start + 18, start + 24]),
          node('Target IP address', tpa, [start + 24, start + 28])
        );
        a.range = [start, r.p];
      }
      m.info = oper === 1 ? 'Who has ' + tpa + '? Tell ' + spa
        : oper === 2 ? spa + ' is at ' + sha
        : 'ARP opcode ' + oper;
    } else {
      m.info = 'ARP (malformed)';
    }
  }

  /* ---------------- Layer 3 ---------------- */
  function ipv4Dissect(r, m, tree, start) {
    const p0 = r.p;
    const verIhl = r.u8(), tos = r.u8(), totalLen = r.u16(), id = r.u16(), flagsFrag = r.u16(),
          ttl = r.u8(), protoNum = r.u8(), csum = r.u16();
    const src = WWL.ip4ToString(r.bytes(4));
    const dst = WWL.ip4ToString(r.bytes(4));
    const ihl = (verIhl & 0xf) * 4;
    const df = !!(flagsFrag & 0x4000), mf = !!(flagsFrag & 0x2000), fragOff = flagsFrag & 0x1fff;
    m.l3 = 'ipv4';
    m.src = src;
    m.dst = dst;
    m.proto = 'ipv4';
    const pname = IP_PROTO[protoNum] || ('0x' + protoNum.toString(16));
    const hdrEnd = Math.min(p0 + ihl, r.b.length);
    if (ihl > 20) r.skip(ihl - 20);
    if (tree) {
      tree.push(node('Internet Protocol Version 4, Src: ' + src + ', Dst: ' + dst, '', [p0, hdrEnd], [
        node('0100 .... = Version', '4', [p0, p0 + 1]),
        node('.... 0101 = Header Length', ihl + ' bytes (' + (ihl / 4) + ')', [p0, p0 + 1]),
        node('Differentiated Services Field', '0x' + WWL.u8hex(tos), [p0 + 1, p0 + 2]),
        node('Total Length', totalLen, [p0 + 2, p0 + 4]),
        node('Identification', '0x' + WWL.hex4(id) + ' (' + id + ')', [p0 + 4, p0 + 6]),
        node('Flags', '0x' + ((flagsFrag >> 13) & 0x7).toString(16), [p0 + 6, p0 + 8], [
          node('.... .... .... .... = Reserved bit', 'Not set', [p0 + 6, p0 + 8]),
          node('.... .... .... .... = Don\'t fragment', df ? 'Set' : 'Not set', [p0 + 6, p0 + 8]),
          node('.... .... .... .... = More fragments', mf ? 'Set' : 'Not set', [p0 + 6, p0 + 8])
        ]),
        node('Fragment Offset', fragOff, [p0 + 6, p0 + 8]),
        node('Time to Live', ttl, [p0 + 8, p0 + 9]),
        node('Protocol', pname + ' (' + protoNum + ')', [p0 + 9, p0 + 10]),
        node('Header Checksum', '0x' + WWL.hex4(csum), [p0 + 10, p0 + 12]),
        node('Source Address', src, [p0 + 12, p0 + 16]),
        node('Destination Address', dst, [p0 + 16, p0 + 20])
      ]));
    }
    if (fragOff !== 0) {
      m.info = pname + ' (IPv4 fragment, offset=' + fragOff + ')';
      return;
    }
    l4Dispatch(r, m, tree, protoNum);
  }

  function ipv6Dissect(r, m, tree, start) {
    const p0 = r.p;
    const first = r.u32();
    const payloadLen = r.u16();
    let nextHdr = r.u8();
    const hopLimit = r.u8();
    const src = WWL.ip6ToString(r.bytes(16));
    const dst = WWL.ip6ToString(r.bytes(16));
    const tc = (first >>> 20) & 0xff;
    const flow = first & 0xfffff;
    m.l3 = 'ipv6';
    m.src = src;
    m.dst = dst;
    m.proto = 'ipv6';
    let fragOff = 0;
    const extHdrs = [];
    let guard = 0;
    while ((nextHdr === 0 || nextHdr === 43 || nextHdr === 44 || nextHdr === 51 || nextHdr === 60) && guard++ < 8 && r.remaining() >= 2) {
      const hs = r.p;
      const nh = r.u8();
      if (nextHdr === 44) {
        r.u8();
        const fo = r.u16();
        r.skip(4);
        fragOff = (fo >> 3) & 0x1fff;
        extHdrs.push({ name: 'Fragment Header', range: [hs, r.p] });
        nextHdr = nh;
      } else if (nextHdr === 51) {
        const alen = r.u8();
        r.skip((alen + 2) * 4 - 2);
        extHdrs.push({ name: 'Authentication Header', range: [hs, r.p] });
        nextHdr = nh;
      } else {
        const hlen = (r.u8() + 1) * 8;
        r.skip(Math.max(0, hlen - 2));
        extHdrs.push({ name: nextHdr === 0 ? 'Hop-by-Hop Options' : nextHdr === 43 ? 'Routing Header' : 'Destination Options', range: [hs, r.p] });
        nextHdr = nh;
      }
    }
    const pname = IP_PROTO[nextHdr] || ('0x' + nextHdr.toString(16));
    if (tree) {
      const ipn = node('Internet Protocol Version 6, Src: ' + src + ', Dst: ' + dst, '', [p0, r.p], [
        node('0110 .... = Version', '6', [p0, p0 + 1]),
        node('Traffic Class', '0x' + WWL.u8hex(tc), [p0, p0 + 1]),
        node('Flow Label', '0x' + WWL.pad(flow.toString(16), 5), [p0 + 1, p0 + 4]),
        node('Payload Length', payloadLen, [p0 + 4, p0 + 6]),
        node('Next Header', pname + ' (' + nextHdr + ')', [p0 + 6, p0 + 7]),
        node('Hop Limit', hopLimit, [p0 + 7, p0 + 8]),
        node('Source Address', src, [p0 + 8, p0 + 24]),
        node('Destination Address', dst, [p0 + 24, p0 + 40])
      ]);
      extHdrs.forEach(function (h) { ipn.children.push(node(h.name, '', h.range)); });
      tree.push(ipn);
    }
    if (fragOff !== 0) {
      m.info = pname + ' (IPv6 fragment, offset=' + fragOff + ')';
      return;
    }
    l4Dispatch(r, m, tree, nextHdr);
  }

  function l4Dispatch(r, m, tree, protoNum) {
    const pname = IP_PROTO[protoNum] || ('0x' + protoNum.toString(16));
    if (protoNum === 6) tcpDissect(r, m, tree, r.p);
    else if (protoNum === 17) udpDissect(r, m, tree, r.p);
    else if (protoNum === 1) icmpDissect(r, m, tree, r.p);
    else if (protoNum === 58) icmpv6Dissect(r, m, tree, r.p);
    else if (protoNum === 2) igmpDissect(r, m, tree, r.p);
    else if (protoNum === 4) { m.tunnel = 'ipip'; ipv4Dissect(r, m, tree, r.p); }
    else if (protoNum === 41) { m.tunnel = '6in4'; ipv6Dissect(r, m, tree, r.p); }
    else if (protoNum === 47) greDissect(r, m, tree, r.p);
    else if (protoNum === 50) espDissect(r, m, tree, r.p);
    else if (protoNum === 51) ahDissect(r, m, tree, r.p);
    else if (protoNum === 88) eigrpDissect(r, m, tree, r.p);
    else if (protoNum === 89) ospfDissect(r, m, tree, r.p);
    else if (protoNum === 112) vrrpDissect(r, m, tree, r.p);
    else if (protoNum === 132) sctpDissect(r, m, tree, r.p);
    else {
      m.info = pname + ', Src: ' + m.src + ', Dst: ' + m.dst;
    }
  }

  /* ---------------- Layer 4 ---------------- */
  function tcpDissect(r, m, tree, start) {
    const p0 = r.p;
    const sport = r.u16(), dport = r.u16(), seq = r.u32(), ack = r.u32();
    const offFlags = r.u16(), win = r.u16(), csum = r.u16(), urg = r.u16();
    const dataOff = (offFlags >>> 12) * 4;
    const flags = offFlags & 0x1ff;
    m.tproto = 'tcp';
    m.sport = sport;
    m.dport = dport;
    m.proto = 'tcp';
    m.tcpFlags = flags;
    const hdrEnd = Math.min(p0 + Math.max(dataOff, 20), r.b.length);
    if (dataOff > 20) r.skip(dataOff - 20);
    const payloadLen = r.remaining();
    const fl = tcpFlagsList(flags);
    m.info = '[' + (fl || '---') + '] Seq=' + seq + (flags & 0x10 ? ' Ack=' + ack : '') + ' Win=' + win + ' Len=' + payloadLen;
    if (tree) {
      tree.push(node(
        'Transmission Control Protocol, Src Port: ' + sport + ', Dst Port: ' + dport + ', Seq: ' + seq + ', Len: ' + payloadLen,
        '', [p0, hdrEnd], [
          node('Source Port', sport, [p0, p0 + 2]),
          node('Destination Port', dport, [p0 + 2, p0 + 4]),
          node('Sequence Number', seq, [p0 + 4, p0 + 8]),
          node('Acknowledgment Number', (flags & 0x10) ? ack : 0, [p0 + 8, p0 + 12]),
          node('Header Length', dataOff + ' bytes (' + (dataOff / 4) + ')', [p0 + 12, p0 + 13]),
          node('Flags', '0x' + WWL.pad(flags.toString(16), 3) + (fl ? ' (' + fl + ')' : ''), [p0 + 13, p0 + 14], flagChildren(flags, p0 + 13)),
          node('Window', win, [p0 + 14, p0 + 16]),
          node('Checksum', '0x' + WWL.hex4(csum), [p0 + 16, p0 + 18]),
          node('Urgent Pointer', urg, [p0 + 18, p0 + 20])
        ]));
    }
    if (payloadLen > 0) {
      const parent = tree && tree.length ? tree[tree.length - 1] : null;
      appLayer(r, m, tree, 'tcp', sport, dport, p0 + Math.max(dataOff, 20), parent);
    }
  }

  function udpDissect(r, m, tree, start) {
    const p0 = r.p;
    const sport = r.u16(), dport = r.u16(), len = r.u16(), csum = r.u16();
    m.tproto = 'udp';
    m.sport = sport;
    m.dport = dport;
    m.proto = 'udp';
    const payloadLen = Math.max(0, len - 8);
    if (tree) {
      tree.push(node('User Datagram Protocol, Src Port: ' + sport + ', Dst Port: ' + dport, '', [p0, p0 + 8], [
        node('Source Port', sport, [p0, p0 + 2]),
        node('Destination Port', dport, [p0 + 2, p0 + 4]),
        node('Length', len, [p0 + 4, p0 + 6]),
        node('Checksum', '0x' + WWL.hex4(csum), [p0 + 6, p0 + 8])
      ]));
    }
    if (r.remaining() > 0) {
      const parent = tree && tree.length ? tree[tree.length - 1] : null;
      appLayer(r, m, tree, 'udp', sport, dport, p0 + 8, parent);
    }
    if (!m.app) m.info = 'Len=' + payloadLen;
  }

  function icmpDissect(r, m, tree, start) {
    const p0 = r.p;
    const type = r.u8(), code = r.u8(), csum = r.u16();
    m.proto = 'icmp';
    m.tproto = 'icmp';
    const tn = ICMP_TYPES[type] || ('Type ' + type);
    let extra = '';
    if (type === 0 || type === 8) {
      const id = r.u16(), seq = r.u16();
      extra = ' id=0x' + WWL.hex4(id) + ', seq=' + seq;
      if (tree) {
        tree.push(node('Internet Control Message Protocol', tn, [p0, r.p], [
          node('Type', type + ' (' + tn + ')', [p0, p0 + 1]),
          node('Code', code, [p0 + 1, p0 + 2]),
          node('Checksum', '0x' + WWL.hex4(csum), [p0 + 2, p0 + 4]),
          node('Identifier', '0x' + WWL.hex4(id), [p0 + 4, p0 + 6]),
          node('Sequence Number', seq, [p0 + 6, p0 + 8])
        ]));
      }
    } else if (type === 3) {
      const codeName = ICMP_UNREACH[code] || ('Code ' + code);
      extra = ' (' + codeName + ')';
      if (tree) {
        tree.push(node('Internet Control Message Protocol', tn + ' (' + codeName + ')', [p0, Math.min(p0 + 8, r.b.length)], [
          node('Type', type + ' (' + tn + ')', [p0, p0 + 1]),
          node('Code', code + ' (' + codeName + ')', [p0 + 1, p0 + 2]),
          node('Checksum', '0x' + WWL.hex4(csum), [p0 + 2, p0 + 4])
        ]));
      }
    } else {
      if (tree) {
        tree.push(node('Internet Control Message Protocol', tn, [p0, r.p], [
          node('Type', type + ' (' + tn + ')', [p0, p0 + 1]),
          node('Code', code, [p0 + 1, p0 + 2]),
          node('Checksum', '0x' + WWL.hex4(csum), [p0 + 2, p0 + 4])
        ]));
      }
    }
    m.info = tn + extra;
  }

  function icmpv6Dissect(r, m, tree, start) {
    const p0 = r.p;
    const type = r.u8(), code = r.u8(), csum = r.u16();
    m.proto = 'icmpv6';
    m.tproto = 'icmpv6';
    const tn = ICMP6_TYPES[type] || ('Type ' + type);
    let extra = '';
    if (type === 128 || type === 129) {
      const id = r.u16(), seq = r.u16();
      extra = ' id=0x' + WWL.hex4(id) + ', seq=' + seq;
      if (tree) {
        tree.push(node('Internet Control Message Protocol v6', tn, [p0, r.p], [
          node('Type', type + ' (' + tn + ')', [p0, p0 + 1]),
          node('Code', code, [p0 + 1, p0 + 2]),
          node('Checksum', '0x' + WWL.hex4(csum), [p0 + 2, p0 + 4]),
          node('Identifier', '0x' + WWL.hex4(id), [p0 + 4, p0 + 6]),
          node('Sequence Number', seq, [p0 + 6, p0 + 8])
        ]));
      }
    } else {
      if (tree) {
        tree.push(node('Internet Control Message Protocol v6', tn, [p0, r.p], [
          node('Type', type + ' (' + tn + ')', [p0, p0 + 1]),
          node('Code', code, [p0 + 1, p0 + 2]),
          node('Checksum', '0x' + WWL.hex4(csum), [p0 + 2, p0 + 4])
        ]));
      }
    }
    m.info = tn + extra;
  }

  /* ---------------- Application layer ---------------- */
  function appLayer(r, m, tree, transport, sport, dport, payloadStart, parent) {
    const rem = r.remaining();
    if (rem <= 0) return false;
    const b = r.b;
    // VXLAN（UDP 4789）
    if (transport === 'udp' && (sport === 4789 || dport === 4789) && rem >= 8) {
      vxlanDissect(r, m, tree, parent, r.p);
      return true;
    }
    // RADIUS（UDP 1812/1813）
    if (transport === 'udp' && (sport === 1812 || dport === 1812 || sport === 1813 || dport === 1813)) {
      const s = r.p;
      if (radiusDissect(r, m, tree, parent, s)) return true;
      r.seek(s);
    }
    // NTP（UDP 123）
    if (transport === 'udp' && (sport === 123 || dport === 123)) {
      const s = r.p;
      if (ntpDissect(r, m, tree, parent, s)) return true;
      r.seek(s);
    }
    // TFTP（UDP 69）
    if (transport === 'udp' && (sport === 69 || dport === 69)) {
      const s = r.p;
      if (tftpDissect(r, m, tree, parent, s)) return true;
      r.seek(s);
    }
    // DHCP over UDP (67/68)
    if (transport === 'udp' && (sport === 67 || dport === 67 || sport === 68 || dport === 68) && rem >= 240) {
      const s = r.p;
      if (dhcpDissect(r, m, tree, parent, s)) return true;
      r.seek(s);
    }
    // TACACS+（TCP 49）
    if (transport === 'tcp' && (sport === 49 || dport === 49)) {
      const s = r.p;
      if (tacacsDissect(r, m, tree, parent, s)) return true;
      r.seek(s);
    }
    // BGP（TCP 179）
    if (transport === 'tcp' && (sport === 179 || dport === 179)) {
      const s = r.p;
      if (bgpDissect(r, m, tree, parent, s)) return true;
      r.seek(s);
    }
    // SIP（TCP/UDP 5060/5061）
    if (sport === 5060 || dport === 5060 || sport === 5061 || dport === 5061) {
      const s = r.p;
      if (textProtocol(r, m, tree, parent, s, 'sip',
        /^(INVITE|ACK|BYE|CANCEL|REGISTER|OPTIONS|PRACK|SUBSCRIBE|NOTIFY|REFER|INFO|UPDATE|MESSAGE|PUBLISH)\s|^SIP\/2\.0 \d/,
        'Session Initiation Protocol')) return true;
      r.seek(s);
    }
    // HSRP（UDP 1985/1986）
    if (transport === 'udp' && (sport === 1985 || dport === 1985 || sport === 1986 || dport === 1986)) {
      const s = r.p;
      if (hsrpDissect(r, m, tree, parent, s)) return true;
      r.seek(s);
    }
    // BFD（UDP 3784/3785）
    if (transport === 'udp' && (sport === 3784 || dport === 3784 || sport === 3785 || dport === 3785)) {
      const s = r.p;
      if (bfdDissect(r, m, tree, parent, s)) return true;
      r.seek(s);
    }
    // 其他 TCP 文本协议
    if (transport === 'tcp') {
      if (sport === 22 || dport === 22) {
        const s = r.p;
        if (textProtocol(r, m, tree, parent, s, 'ssh', /^SSH-\d\.\d-/, 'SSH')) return true;
        r.seek(s);
      }
      if (sport === 21 || dport === 21) {
        const s = r.p;
        if (textProtocol(r, m, tree, parent, s, 'ftp',
          /^(220|221|230|331|332|530|USER|PASS|PASV|EPSV|LIST|RETR|STOR|DELE|RNFR|RNTO|CWD|PWD|QUIT|SYST|TYPE|PORT|MKD|RMD|NLST|NOOP|ACCT|REIN|SITE)\s/i,
          'File Transfer Protocol')) return true;
        r.seek(s);
      }
      if (sport === 25 || dport === 25 || sport === 587 || dport === 587) {
        const s = r.p;
        if (textProtocol(r, m, tree, parent, s, 'smtp',
          /^(220|250|221|354|421|450|451|452|550|551|552|553|554|EHLO|HELO|MAIL|RCPT|DATA|QUIT|RSET|NOOP|VRFY|EXPN|HELP|AUTH)\s/i,
          'Simple Mail Transfer Protocol')) return true;
        r.seek(s);
      }
      if (sport === 110 || dport === 110) {
        const s = r.p;
        if (textProtocol(r, m, tree, parent, s, 'pop3',
          /^\+OK|^-ERR|^(USER|PASS|STAT|LIST|RETR|DELE|NOOP|RSET|QUIT|TOP|UIDL|APOP)\s/i,
          'Post Office Protocol')) return true;
        r.seek(s);
      }
      if (sport === 143 || dport === 143) {
        const s = r.p;
        if (textProtocol(r, m, tree, parent, s, 'imap',
          /^\* (OK|NO|BAD|BYE|CAPABILITY|LIST|LSUB|STATUS|SEARCH|FLAGS)|^[A-Z0-9]+ (OK|NO|BAD|BYE|CAPABILITY|LOGIN|LOGOUT|SELECT|EXAMINE|CREATE|DELETE|RENAME|SUBSCRIBE|UNSUBSCRIBE|LIST|LSUB|STATUS|APPEND|CHECK|CLOSE|EXPUNGE|SEARCH|FETCH|STORE|COPY|UID|NOOP)\s/i,
          'Internet Message Access Protocol')) return true;
        r.seek(s);
      }
      if (sport === 23 || dport === 23) {
        const s = r.p;
        if (b[s] === 0xff) {
          m.proto = 'telnet';
          m.app = 'telnet';
          m.info = 'Telnet, IAC negotiation';
          if (tree && parent) parent.children.push(node('Telnet', 'IAC negotiation', [s, Math.min(s + 16, b.length)]));
          return true;
        }
        if (textProtocol(r, m, tree, parent, s, 'telnet', /^[\x20-\x7e]{2,}/, 'Telnet')) return true;
        r.seek(s);
      }
    }
    // TLS over TCP (record layer)
    if (transport === 'tcp' && rem >= 5 &&
        (b[r.p] === 20 || b[r.p] === 21 || b[r.p] === 22 || b[r.p] === 23) &&
        b[r.p + 1] === 3 && b[r.p + 2] <= 4) {
      const s = r.p;
      if (tlsDissect(r, m, tree, parent, s)) return true;
      r.seek(s);
    }
    // HTTP over TCP
    if (transport === 'tcp' && rem >= 4) {
      const s = r.p;
      if (httpDissect(r, m, tree, parent, s)) return true;
      r.seek(s);
    }
    // DNS over UDP/TCP (port 53 / mDNS 5353)
    if ((sport === 53 || dport === 53 || sport === 5353 || dport === 5353) && rem >= 12) {
      const s = r.p;
      if (dnsDissect(r, m, tree, parent, s)) return true;
      r.seek(s);
    }
    return false;
  }

  function httpDissect(r, m, tree, parent, start) {
    const b = r.b;
    const max = Math.min(r.remaining(), 4096);
    let lineEnd = -1;
    for (let i = 0; i < max - 1; i++) {
      if (b[start + i] === 13 && b[start + i + 1] === 10) { lineEnd = start + i; break; }
    }
    const lineLen = lineEnd >= 0 ? lineEnd - start : Math.min(max, 256);
    let first = '';
    for (let i = 0; i < lineLen; i++) first += String.fromCharCode(b[start + i]);
    const isReq = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s/.test(first);
    const isResp = /^HTTP\/\d(\.\d)?\s/.test(first);
    if (!isReq && !isResp) return false;
    m.proto = 'http';
    m.app = 'http';
    m.info = first.length > 220 ? first.slice(0, 220) + '...' : first;
    if (tree && parent) {
      const bodyEnd = lineEnd >= 0 ? Math.min(b.length, lineEnd + 2) : Math.min(b.length, start + lineLen);
      const hn = node(isReq ? 'Hypertext Transfer Protocol' : 'Hypertext Transfer Protocol', '', [start, bodyEnd], [
        node(isReq ? 'Request Line' : 'Status Line', first, [start, start + lineLen])
      ]);
      if (lineEnd >= 0) {
        let p = lineEnd + 2;
        let guard = 0;
        while (p + 1 < b.length && guard++ < 64) {
          let e = p;
          while (e + 1 < b.length && !(b[e] === 13 && b[e + 1] === 10)) e++;
          if (e + 1 >= b.length) break;
          if (e === p) break;
          let line = '';
          for (let i = p; i < e; i++) line += String.fromCharCode(b[i]);
          const ci = line.indexOf(':');
          const name = ci >= 0 ? line.slice(0, ci) : line;
          const value = ci >= 0 ? line.slice(ci + 1).trim() : '';
          hn.children.push(node(name, value, [p, e]));
          p = e + 2;
        }
      }
      parent.children.push(hn);
    }
    return true;
  }

  function dnsReadName(b, base, pos) {
    const parts = [];
    let p = pos;
    let jumped = false;
    let end = null;
    for (let hops = 0; hops < 64; hops++) {
      if (p >= b.length) break;
      const len = b[p];
      if (len === 0) { if (!jumped) end = p + 1; break; }
      if ((len & 0xc0) === 0xc0) {
        if (p + 2 > b.length) break;
        if (!jumped) { end = p + 2; jumped = true; }
        p = base + (((len & 0x3f) << 8) | b[p + 1]);
        continue;
      }
      if (len > 63 || p + 1 + len > b.length) break;
      let s = '';
      for (let i = 0; i < len; i++) s += String.fromCharCode(b[p + 1 + i]);
      parts.push(s);
      p += 1 + len;
    }
    return { name: parts.join('.'), end: end === null ? pos : end };
  }

  function dnsDissect(r, m, tree, parent, start) {
    const b = r.b;
    const base = start;
    const id = r.u16(), flags = r.u16(), qd = r.u16(), an = r.u16(), ns = r.u16(), ar = r.u16();
    const qr = !!(flags & 0x8000);
    const opcode = (flags >> 11) & 0xf;
    const rd = !!(flags & 0x0100);
    const questions = [];
    let qname = '', qtype = 0;
    for (let i = 0; i < qd && r.p + 1 <= b.length; i++) {
      const nm = dnsReadName(b, base, r.p);
      r.seek(nm.end);
      if (r.p + 4 > b.length) break;
      const qt = r.u16(), qc = r.u16();
      questions.push({ name: nm.name, type: qt, cls: qc });
      if (i === 0) { qname = nm.name; qtype = qt; }
    }
    m.proto = 'dns';
    m.app = 'dns';
    const opName = opcode === 0 ? 'Standard query' : opcode === 1 ? 'Inverse query' : opcode === 2 ? 'Server status' : 'Opcode ' + opcode;
    m.info = (qr ? opName + ' response' : opName) +
      ' 0x' + WWL.hex4(id) +
      ' ' + (DNS_TYPES[qtype] || qtype || '') +
      (qname ? ' ' + qname : '') +
      (qr ? ', ' + an + ' answers' : '');
    if (tree && parent) {
      const dn = node('Domain Name System (' + (qr ? 'response' : 'query') + ')', '', [start, r.p], [
        node('Transaction ID', '0x' + WWL.hex4(id), [start, start + 2]),
        node('Flags', '0x' + WWL.hex4(flags), [start + 2, start + 4], [
          node('.... .... .... .... = Response', qr ? 'Message is a response' : 'Message is a query', [start + 2, start + 4]),
          node('.... .... ...1 .... = Recursion desired', rd ? 'Set' : 'Not set', [start + 2, start + 4])
        ]),
        node('Questions', qd, [start + 4, start + 6]),
        node('Answer RRs', an, [start + 6, start + 8]),
        node('Authority RRs', ns, [start + 8, start + 10]),
        node('Additional RRs', ar, [start + 10, start + 12])
      ]);
      if (questions.length) {
        const qn = node('Queries', '', [start, r.p], []);
        questions.forEach(function (q) {
          qn.children.push(node(q.name || '(empty)', '', null, [
            node('Type', DNS_TYPES[q.type] || String(q.type), null),
            node('Class', q.cls === 1 ? 'IN (0x0001)' : '0x' + WWL.hex4(q.cls), null)
          ]));
        });
        dn.children.push(qn);
      }
      const ansNode = node('Answers', '', [start, r.p], []);
      for (let i = 0; i < an && r.p + 10 <= b.length; i++) {
        const nm = dnsReadName(b, base, r.p);
        r.seek(nm.end);
        if (r.p + 10 > b.length) break;
        const at = r.u16(), acls = r.u16(), ttl = r.u32(), rdlen = r.u16();
        if (r.p + rdlen > b.length) break;
        const dataStart = r.p;
        const rd = r.bytes(rdlen);
        let rdstr = '';
        if (at === 1 && rdlen === 4) rdstr = WWL.ip4ToString(rd);
        else if (at === 28 && rdlen === 16) rdstr = WWL.ip6ToString(rd);
        else if ((at === 5 || at === 2 || at === 12) && rdlen > 0) {
          const n2 = dnsReadName(b, base, dataStart);
          rdstr = n2.name;
        } else if (at === 16) {
          rdstr = '"' + asciiBytes(rd).replace(/\.+$/, '') + '"';
        }
        ansNode.children.push(node(
          (nm.name || '(root)') + ': type ' + (DNS_TYPES[at] || at) + ', class ' + (acls === 1 ? 'IN' : '0x' + WWL.hex4(acls)) + ', ttl ' + ttl,
          rdstr, [dataStart, r.p]
        ));
      }
      if (ansNode.children.length) dn.children.push(ansNode);
      parent.children.push(dn);
    }
    return true;
  }

  function dhcpOptionDesc(code, val) {
    const name = DHCP_OPT_NAMES[code] || ('Option ' + code);
    if (code === 53 && val.length >= 1) return name + ': ' + (DHCP_MSGS[val[0]] || val[0]);
    if ((code === 1 || code === 3 || code === 6 || code === 50 || code === 54) && val.length >= 4 && val.length % 4 === 0) {
      let ips = [];
      for (let i = 0; i < val.length; i += 4) ips.push(WWL.ip4ToString(val, i));
      return name + ': ' + ips.join(', ');
    }
    if (code === 51 && val.length >= 4) {
      const v = ((val[0] << 24) | (val[1] << 16) | (val[2] << 8) | val[3]) >>> 0;
      return name + ': ' + v + ' seconds';
    }
    if (code === 55) {
      let ids = [];
      for (let i = 0; i < val.length; i++) ids.push(DHCP_OPT_NAMES[val[i]] || String(val[i]));
      return name + ': ' + ids.join(', ');
    }
    if (code === 12 || code === 15) return name + ': ' + asciiBytes(val);
    if (code === 61) return name + ': 0x' + hexBytes(val);
    return name + ': ' + hexBytes(val);
  }

  function dhcpDissect(r, m, tree, parent, start) {
    const b = r.b;
    if (r.remaining() < 240) return false;
    const op = r.u8(), htype = r.u8(), hlen = r.u8(), hops = r.u8();
    const xid = r.u32(), secs = r.u16(), flags = r.u16();
    const ciaddr = WWL.ip4ToString(r.bytes(4));
    const yiaddr = WWL.ip4ToString(r.bytes(4));
    const siaddr = WWL.ip4ToString(r.bytes(4));
    const giaddr = WWL.ip4ToString(r.bytes(4));
    const chaddrB = r.bytes(16);
    r.bytes(64); // sname
    r.bytes(128); // file
    const magic = r.u32();
    if (magic !== 0x63825363) return false;
    let msgType = 0, reqIp = '', serverId = '';
    const opts = [];
    let guard = 0;
    while (r.remaining() >= 1 && guard++ < 512) {
      const code = r.u8();
      if (code === 0) continue;
      if (code === 255) break;
      if (r.remaining() < 1) break;
      const len = r.u8();
      if (len > r.remaining()) break;
      const valStart = r.p;
      const val = r.bytes(len);
      opts.push({ code: code, range: [valStart, r.p], val: val });
      if (code === 53 && len >= 1) msgType = val[0];
      else if (code === 50 && len >= 4) reqIp = WWL.ip4ToString(val);
      else if (code === 54 && len >= 4) serverId = WWL.ip4ToString(val);
    }
    const msgName = DHCP_MSGS[msgType] || 'Message';
    const clientMac = hlen > 0 && hlen <= 6 ? WWL.macToString(chaddrB) : '';
    m.proto = 'dhcp';
    m.app = 'dhcp';
    m.info = 'DHCP ' + msgName + ' - Transaction ID 0x' + WWL.hex8(xid) +
      (clientMac ? ', Client MAC ' + clientMac : '') +
      (reqIp ? ', Requested IP ' + reqIp : '') +
      (serverId ? ', Server ID ' + serverId : '') +
      (yiaddr !== '0.0.0.0' ? ', Your IP ' + yiaddr : '');
    if (tree && parent) {
      const dn = node('Dynamic Host Configuration Protocol (' + msgName + ')', '', [start, r.p], [
        node('Message type', (op === 1 ? 'Boot Request (1)' : op === 2 ? 'Boot Reply (2)' : String(op)), [start, start + 1]),
        node('Hardware type', htype + ' (Ethernet)', [start + 1, start + 2]),
        node('Hardware address length', hlen, [start + 2, start + 3]),
        node('Transaction ID', '0x' + WWL.hex8(xid), [start + 4, start + 8]),
        node('Client IP address', ciaddr, [start + 12, start + 16]),
        node('Your (client) IP address', yiaddr, [start + 16, start + 20]),
        node('Next server IP address', siaddr, [start + 20, start + 24]),
        node('Relay agent IP address', giaddr, [start + 24, start + 28]),
        node('Client MAC address', clientMac || '-', [start + 28, start + 44]),
        node('Magic cookie', 'DHCP (0x63825363)', [start + 236, start + 240]),
        node('Message Type', msgName + (msgType ? ' (' + msgType + ')' : ''), null)
      ]);
      opts.forEach(function (o) {
        dn.children.push(node('Option (' + o.code + ') ' + (DHCP_OPT_NAMES[o.code] || ''), dhcpOptionDesc(o.code, o.val), o.range));
      });
      parent.children.push(dn);
    }
    return true;
  }

  function tlsDissect(r, m, tree, parent, start) {
    const b = r.b;
    const p0 = r.p;
    const ctype = r.u8();
    const ver = r.u16();
    const recLen = r.u16();
    if (ctype < 20 || ctype > 24) return false;
    if ((ver >> 8) !== 3) return false;
    if (p0 + 5 + recLen > b.length) return false;
    const vname = TLS_VER[ver] || ('0x' + WWL.hex4(ver));
    m.proto = 'tls';
    m.app = 'tls';
    let info;
    if (ctype === 22 && recLen >= 4) {
      const hsType = r.u8();
      const hsLen = r.u24();
      if (hsType === 1 && hsLen >= 34) {
        r.u16();
        r.skip(32);
        const sidLen = r.u8();
        r.skip(sidLen);
        const csLen = r.u16();
        r.bytes(csLen);
        const compLen = r.u8();
        r.skip(compLen);
        let sni = '', tls13 = false;
        if (r.remaining() >= 2) {
          const extLen = r.u16();
          const extEnd = Math.min(r.p + extLen, b.length);
          while (r.p + 4 <= extEnd) {
            const et = r.u16();
            const el = r.u16();
            if (r.p + el > extEnd) break;
            const ev = r.bytes(el);
            if (et === 0 && ev.length >= 5 && ev[2] === 0) {
              const nl = (ev[3] << 8) | ev[4];
              let s = '';
              for (let i = 5; i < 5 + nl && i < ev.length; i++) s += String.fromCharCode(ev[i]);
              sni = s;
            } else if (et === 43 && ev.length >= 3) {
              for (let i = 1; i + 1 < ev.length; i++) {
                if (ev[i] === 0x03 && ev[i + 1] === 0x04) { tls13 = true; break; }
              }
            }
          }
        }
        info = 'Client Hello, ' + (tls13 ? 'TLSv1.3' : vname) + (sni ? ', SNI=' + sni : '');
      } else if (hsType === 2 && hsLen >= 38) {
        r.u16();
        r.skip(32);
        const sidLen = r.u8();
        r.skip(sidLen);
        r.u16(); // cipher
        r.u8(); // compression
        let tls13 = false;
        if (r.remaining() >= 2) {
          const extLen = r.u16();
          const extEnd = Math.min(r.p + extLen, b.length);
          while (r.p + 4 <= extEnd) {
            const et = r.u16(), el = r.u16();
            if (r.p + el > extEnd) break;
            const ev = r.bytes(el);
            if (et === 43 && el === 2 && ev[0] === 0x03 && ev[1] === 0x04) tls13 = true;
          }
        }
        info = 'Server Hello, ' + (tls13 ? 'TLSv1.3' : vname);
      } else {
        info = (TLS_HS[hsType] || ('Handshake (' + hsType + ')')) + ', ' + vname;
      }
    } else {
      info = (TLS_CONTENT[ctype] || ('Content type ' + ctype)) + ', ' + vname;
    }
    m.info = info;
    if (tree && parent) {
      parent.children.push(node('Transport Layer Security', info, [p0, p0 + 5 + recLen], [
        node('TLS Record Layer', '', [p0, p0 + 5 + recLen], [
          node('Content Type', (TLS_CONTENT[ctype] || ctype) + ' (' + ctype + ')', [p0, p0 + 1]),
          node('Version', vname + ' (0x' + WWL.hex4(ver) + ')', [p0 + 1, p0 + 3]),
          node('Length', recLen, [p0 + 3, p0 + 5])
        ])
      ]));
    }
    return true;
  }

  function pppoeDissect(r, m, tree, start) {
    const verType = r.u8(), code = r.u8(), session = r.u16(), plen = r.u16();
    let proto = 0;
    if (r.remaining() >= 2) proto = r.u16();
    if (proto === 0x0021) { ipv4Dissect(r, m, tree, r.p); return; }
    if (proto === 0x0057) { ipv6Dissect(r, m, tree, r.p); return; }
    m.proto = 'ppp';
    m.info = 'PPPoE session ' + session + ', PPP protocol 0x' + WWL.hex4(proto) + ' (code ' + code + ')';
    if (tree) {
      tree.push(node('PPP over Ethernet', '', [start, r.p], [
        node('Version', String(verType >> 4), [start, start + 1]),
        node('Type', String(verType & 0xf), [start, start + 1]),
        node('Code', code, [start + 1, start + 2]),
        node('Session ID', session, [start + 2, start + 4]),
        node('PPP Protocol', '0x' + WWL.hex4(proto), [start + 6, start + 8])
      ]));
    }
  }

  /* ---------------- 更多协议：隧道 / 路由 / 应用 ---------------- */
  const OSPF_MSG_TYPES = { 1: 'Hello', 2: 'Database Description', 3: 'Link State Request', 4: 'Link State Update', 5: 'Link State Acknowledgment' };
  const SCTP_CHUNK_NAMES = {
    0: 'DATA', 1: 'INIT', 2: 'INIT ACK', 3: 'SACK', 4: 'HEARTBEAT', 5: 'HEARTBEAT ACK',
    6: 'ABORT', 7: 'SHUTDOWN', 8: 'SHUTDOWN ACK', 9: 'ERROR', 10: 'COOKIE ECHO',
    11: 'COOKIE ACK', 12: 'ECNE', 13: 'CWR', 14: 'SHUTDOWN COMPLETE', 64: 'I-DATA',
    128: 'AUTH', 132: 'ASCONF', 133: 'ASCONF ACK', 192: 'PAD', 224: 'FORWARD TSN'
  };
  const IGMP_TYPE_NAMES = {
    0x11: 'Membership Query', 0x12: 'Membership Report (v1)', 0x16: 'Membership Report (v2)',
    0x17: 'Leave Group', 0x22: 'Membership Report (v3)'
  };
  const BGP_TYPE_NAMES = { 1: 'OPEN', 2: 'UPDATE', 3: 'NOTIFICATION', 4: 'KEEPALIVE', 5: 'ROUTE-REFRESH' };
  const BGP_ATTR_NAMES = {
    1: 'ORIGIN', 2: 'AS_PATH', 3: 'NEXT_HOP', 4: 'MULTI_EXIT_DISC', 5: 'LOCAL_PREF',
    6: 'ATOMIC_AGGREGATE', 7: 'AGGREGATOR', 8: 'COMMUNITY', 9: 'ORIGINATOR_ID',
    10: 'CLUSTER_LIST', 14: 'MP_REACH_NLRI', 15: 'MP_UNREACH_NLRI'
  };
  const BGP_NOTIF_CODES = {
    1: 'Message Header Error', 2: 'OPEN Message Error', 3: 'UPDATE Message Error',
    4: 'Hold Timer Expired', 5: 'Finite State Machine Error', 6: 'Cease'
  };
  const TACACS_TYPE_NAMES = { 1: 'Authentication', 2: 'Authorization', 3: 'Accounting' };
  const TACACS_ACTION_NAMES = { 1: 'Login', 2: 'Change password' };
  const TACACS_SERVICE_NAMES = { 1: 'Login', 2: 'Enable', 15: 'PPP', 16: 'ARAP', 17: 'PT', 18: 'RCMD', 19: 'X25', 21: 'NASI', 22: 'FTP' };
  const RADIUS_CODE_NAMES = {
    1: 'Access-Request', 2: 'Access-Accept', 3: 'Access-Reject', 4: 'Accounting-Request',
    5: 'Accounting-Response', 11: 'Access-Challenge', 12: 'Status-Server', 13: 'Status-Client'
  };
  const RADIUS_ATTR_NAMES = {
    1: 'User-Name', 2: 'User-Password', 4: 'NAS-IP-Address', 5: 'NAS-Port', 6: 'Service-Type',
    7: 'Framed-Protocol', 8: 'Framed-IP-Address', 25: 'Class', 26: 'Vendor-Specific',
    30: 'Called-Station-Id', 31: 'Calling-Station-Id', 32: 'NAS-Identifier', 40: 'Acct-Status-Type',
    41: 'Acct-Delay-Time', 42: 'Acct-Input-Octets', 43: 'Acct-Output-Octets', 44: 'Acct-Session-Id'
  };
  const ACCT_STATUS_NAMES = { 1: 'Start', 2: 'Stop', 3: 'Interim-Update' };
  const NTP_MODE_NAMES = { 1: 'symmetric active', 2: 'symmetric passive', 3: 'client', 4: 'server', 5: 'broadcast', 6: 'control', 7: 'private' };
  const EAP_CODE_NAMES = { 1: 'Request', 2: 'Response', 3: 'Success', 4: 'Failure' };
  const EAP_TYPE_NAMES = {
    1: 'Identity', 2: 'Notification', 3: 'NAK', 4: 'MD5-Challenge', 5: 'OTP',
    6: 'Generic Token Card', 13: 'EAP-TLS', 21: 'EAP-TTLS', 25: 'PEAP',
    43: 'EAP-pwd', 50: 'EAP-FAST', 55: 'EAP-AKA', 56: 'EAP-AKA\''
  };
  const SLOW_PROTOCOL_NAMES = {
    1: 'LACP', 2: 'Marker', 3: 'Marker Response', 0x0a: 'OAM', 0x20: 'ESMC',
    0x21: 'Link Layer Discovery Protocol', 0x22: 'Performance Diagnostic', 0x23: 'Customer Slow Protocol'
  };
  const HSRP_OPCODES = { 0: 'Hello', 1: 'Coup', 2: 'Resign' };
  const HSRP_STATES = { 0: 'Initial', 1: 'Learn', 2: 'Listen', 4: 'Speak', 6: 'Standby', 8: 'Active' };
  const BFD_STATES = { 0: 'AdminDown', 1: 'Down', 2: 'Init', 3: 'Up' };
  const IB_OPCODES = {
    0x00: 'UD SEND First', 0x01: 'UD SEND Middle', 0x02: 'UD SEND Last', 0x03: 'UD SEND Only',
    0x04: 'RC SEND First', 0x05: 'RC SEND Middle', 0x06: 'RC SEND Last', 0x07: 'RC SEND Only',
    0x08: 'RC RDMA WRITE First', 0x09: 'RC RDMA WRITE Middle', 0x0a: 'RC RDMA WRITE Last',
    0x0b: 'RC RDMA WRITE Only', 0x0c: 'RC RDMA READ Request', 0x0d: 'RC RDMA READ Response',
    0x0e: 'RC ATOMIC', 0x0f: 'RC ATOMIC Acknowledge', 0x10: 'UC SEND First', 0x11: 'UC SEND Middle',
    0x12: 'UC SEND Last', 0x13: 'UC SEND Only', 0x1c: 'UD', 0x20: 'CNP', 0x21: 'MAD'
  };

  /* 按 EtherType 分发（外层以太网 / VXLAN 内层 / GRE 桥接共用） */
  function dispatchL3(r, m, tree, etherType, l3start) {
    if (etherType === 0x0806 || etherType === 0x8035) arpDissect(r, m, tree, l3start);
    else if (etherType === 0x0800) ipv4Dissect(r, m, tree, l3start);
    else if (etherType === 0x86dd) ipv6Dissect(r, m, tree, l3start);
    else if (etherType === 0x8847 || etherType === 0x8848) mplsDissect(r, m, tree, l3start);
    else if (etherType === 0x8864) pppoeDissect(r, m, tree, l3start);
    else if (etherType === 0x88cc) lldpDissect(r, m, tree, l3start);
    else if (etherType === 0x2000) cdpDissect(r, m, tree, l3start);
    else if (etherType === 0x8809) slowProtocolsDissect(r, m, tree, l3start);
    else if (etherType === 0x888e) eapolDissect(r, m, tree, l3start);
    else {
      m.info = 'EtherType 0x' + WWL.hex4(etherType) + ' (' + (WWL.ETHER_TYPES[etherType] || 'Unknown') + ')';
      if (tree) tree.push(node('Unknown EtherType', etherTypeName(etherType), [r.p, r.b.length]));
    }
  }

  function mplsDissect(r, m, tree, start) {
    const p0 = r.p;
    const labels = [];
    let bottom = -1;
    for (let i = 0; i < 16 && r.remaining() >= 4; i++) {
      const v = r.u32();
      const label = v >>> 12;
      const tc = (v >>> 9) & 0x7;
      const s = (v >>> 8) & 0x1;
      const ttl = v & 0xff;
      labels.push({ label: label, tc: tc, s: s, ttl: ttl });
      if (s) { bottom = label; break; }
    }
    m.proto = 'mpls';
    m.l3 = 'mpls';
    m.tunnel = 'mpls';
    m.info = 'MPLS Label Switched Packet, Labels: ' + labels.map(function (l) { return l.label; }).join(', ');
    if (tree) {
      tree.push(node('MultiProtocol Label Switching', '', [p0, r.p], labels.map(function (l, i) {
        return node('MPLS Label ' + (i + 1), 'Label: ' + l.label + ', Traffic Class: ' + l.tc + ', Bottom of stack: ' + l.s + ', TTL: ' + l.ttl, [p0 + i * 4, p0 + (i + 1) * 4]);
      })));
    }
    // 显式空标签：0 = IPv4 显式空，2 = IPv6 显式空
    if (bottom === 0 && r.remaining() >= 20) ipv4Dissect(r, m, tree, r.p);
    else if (bottom === 2 && r.remaining() >= 40) ipv6Dissect(r, m, tree, r.p);
  }

  function stpDissect(r, m, tree, start) {
    const p0 = r.p;
    const protoId = r.u16(), version = r.u8(), type = r.u8(), flags = r.u8();
    const rootPri = r.u16();
    const rootMac = WWL.macToString(r.bytes(6));
    const cost = r.u32();
    const bridgePri = r.u16();
    const bridgeMac = WWL.macToString(r.bytes(6));
    const portId = r.u16();
    const msgAge = r.u16(), maxAge = r.u16(), hello = r.u16(), fwd = r.u16();
    m.proto = 'stp';
    const typeName = type === 0 ? 'Config BPDU' : type === 0x80 ? 'TCN BPDU' : 'BPDU type ' + type;
    m.info = 'Spanning Tree ' + typeName + ', Root: ' + rootPri + '/' + rootMac +
      ', Cost: ' + cost + ', Bridge: ' + bridgePri + '/' + bridgeMac;
    if (tree) {
      tree.push(node('Spanning Tree Protocol (' + typeName + ')', '', [p0, r.p], [
        node('Protocol Identifier', protoId, [p0, p0 + 2]),
        node('Protocol Version', version === 0 ? 'STP (0)' : version === 2 ? 'RSTP (2)' : version === 3 ? 'MSTP (3)' : String(version), [p0 + 2, p0 + 3]),
        node('BPDU Type', type === 0 ? 'Configuration (0)' : type === 0x80 ? 'Topology Change Notification (0x80)' : '0x' + WWL.u8hex(type), [p0 + 3, p0 + 4]),
        node('Root Identifier', rootPri + '/' + rootMac, [p0 + 5, p0 + 13]),
        node('Root Path Cost', cost, [p0 + 13, p0 + 17]),
        node('Bridge Identifier', bridgePri + '/' + bridgeMac, [p0 + 17, p0 + 25]),
        node('Port Identifier', '0x' + WWL.hex4(portId), [p0 + 25, p0 + 27]),
        node('Message Age', msgAge / 256 + 's', [p0 + 27, p0 + 29]),
        node('Max Age', maxAge / 256 + 's', [p0 + 29, p0 + 31]),
        node('Hello Time', hello / 256 + 's', [p0 + 31, p0 + 33]),
        node('Forward Delay', fwd / 256 + 's', [p0 + 33, p0 + 35])
      ]));
    }
  }

  function lldpTlvValue(val) {
    if (!val.length) return '';
    const sub = val[0];
    if (sub === 4 && val.length >= 7) return WWL.macToString(val, 1);
    if (sub === 6 || sub === 7) return asciiBytes(val.subarray(1));
    return hexBytes(val);
  }

  function lldpDissect(r, m, tree, start) {
    const p0 = r.p;
    let chassis = '', port = '', sysName = '', ttl = '';
    const tlvs = [];
    while (r.remaining() >= 2) {
      const h = r.u16();
      const t = h >>> 9, len = h & 0x1ff;
      if (len > r.remaining()) break;
      const valStart = r.p;
      const val = r.bytes(len);
      if (t === 0) { tlvs.push({ t: 0, range: [valStart, r.p], text: 'End of LLDPDU' }); break; }
      let text = '';
      if (t === 1) { chassis = lldpTlvValue(val); text = 'Chassis ID: ' + chassis; }
      else if (t === 2) { port = lldpTlvValue(val); text = 'Port ID: ' + port; }
      else if (t === 3) { ttl = String((val[0] << 8) | val[1]); text = 'Time to Live: ' + ttl + 's'; }
      else if (t === 4) { text = 'Port Description: ' + asciiBytes(val); }
      else if (t === 5) { sysName = asciiBytes(val); text = 'System Name: ' + sysName; }
      else if (t === 6) { text = 'System Description: ' + asciiBytes(val); }
      else text = 'TLV type ' + t + ': ' + hexBytes(val);
      tlvs.push({ t: t, range: [valStart, r.p], text: text });
    }
    m.proto = 'lldp';
    m.info = 'Link Layer Discovery Protocol' + (chassis ? ', Chassis ID: ' + chassis : '') + (port ? ', Port ID: ' + port : '');
    if (tree) {
      tree.push(node('Link Layer Discovery Protocol', '', [p0, r.p], tlvs.map(function (tlv) {
        return node('TLV (' + tlv.t + ')', tlv.text, tlv.range);
      })));
    }
  }

  function cdpDissect(r, m, tree, start) {
    const p0 = r.p;
    const version = r.u8(), ttl = r.u8(), csum = r.u16();
    let devId = '', portId = '', platform = '', vlan = '';
    const tlvs = [];
    while (r.remaining() >= 4) {
      const t = r.u16(), len = r.u16();
      if (len < 4 || len - 4 > r.remaining()) break;
      const valStart = r.p;
      const val = r.bytes(len - 4);
      let text = '';
      if (t === 1) { devId = asciiBytes(val); text = 'Device ID: ' + devId; }
      else if (t === 3) { portId = asciiBytes(val); text = 'Port ID: ' + portId; }
      else if (t === 6) { platform = asciiBytes(val); text = 'Platform: ' + platform; }
      else if (t === 0x11 && val.length >= 2) { vlan = String((val[0] << 8) | val[1]); text = 'Native VLAN: ' + vlan; }
      else if (t === 0x1a && val.length >= 1) { text = 'Duplex: ' + (val[0] === 2 ? 'full' : val[0] === 1 ? 'half' : val[0]); }
      else if (t === 4 && val.length >= 4) { text = 'Capabilities: 0x' + WWL.hex4((val[0] << 8) | val[1]); }
      else if (t === 5) { text = 'Software Version: ' + asciiBytes(val); }
      else text = 'TLV type 0x' + WWL.hex4(t) + ': ' + hexBytes(val);
      tlvs.push({ t: t, range: [valStart, r.p], text: text });
    }
    m.proto = 'cdp';
    m.info = 'Cisco Discovery Protocol' + (devId ? ', Device ID: ' + devId : '') + (portId ? ', Port ID: ' + portId : '') + (platform ? ', Platform: ' + platform : '');
    if (tree) {
      tree.push(node('Cisco Discovery Protocol', 'Version: ' + version + ', TTL: ' + ttl, [p0, r.p], [
        node('Version', version, [p0, p0 + 1]),
        node('Time to Live', ttl + 's', [p0 + 1, p0 + 2]),
        node('Checksum', '0x' + WWL.hex4(csum), [p0 + 2, p0 + 4])
      ].concat(tlvs.map(function (tlv) { return node('TLV type 0x' + WWL.hex4(tlv.t), tlv.text, tlv.range); }))));
    }
  }

  /* 内层以太网负载（VXLAN / GRE 透明桥接） */
  function ethernetPayload(r, m, tree, start) {
    const dst = WWL.macToString(r.bytes(6));
    const src = WWL.macToString(r.bytes(6));
    const et = r.u16();
    m.macDst = dst;
    m.macSrc = src;
    m.ethType = et;
    if (tree) {
      tree.push(node('Ethernet II (inner), Src: ' + src + ', Dst: ' + dst, '', [start, r.p], [
        node('Destination', dst, [start, start + 6]),
        node('Source', src, [start + 6, start + 12]),
        node('Type', etherTypeName(et), [r.p - 2, r.p])
      ]));
    }
    dispatchL3(r, m, tree, et, r.p);
  }

  function greDissect(r, m, tree, start) {
    const p0 = r.p;
    const flagsVer = r.u16();
    const version = flagsVer & 0x7;
    const hasC = !!(flagsVer & 0x8000), hasR = !!(flagsVer & 0x4000), hasK = !!(flagsVer & 0x2000), hasS = !!(flagsVer & 0x1000);
    const proto = r.u16();
    let key = 0, seq = 0;
    if (hasC) { r.u16(); r.u16(); }
    if (hasR) r.skip(4);
    if (hasK) key = r.u32();
    if (hasS) seq = r.u32();
    if (version === 1) {
      m.proto = 'pptp';
      m.tunnel = 'gre';
      m.info = 'PPTP (GRE v1), Call ID: ' + (key & 0xffff) + ', Seq: ' + seq;
      if (tree) tree.push(node('Point-to-Point Tunneling Protocol', 'Call ID: ' + (key & 0xffff), [p0, r.p]));
      return;
    }
    const protoName = proto === 0x0800 ? 'IPv4' : proto === 0x86dd ? 'IPv6' : proto === 0x6558 ? 'Transparent Ethernet Bridging' : proto === 0x88be ? 'ERSPAN' : ('0x' + WWL.hex4(proto));
    m.tunnel = 'gre';
    m.proto = 'gre';
    m.info = 'Generic Routing Encapsulation, Protocol: ' + protoName + (hasK ? ', Key: 0x' + WWL.hex8(key) : '') + (hasS ? ', Seq: ' + seq : '');
    if (tree) {
      tree.push(node('Generic Routing Encapsulation', 'Protocol: ' + protoName, [p0, r.p], [
        node('Flags and Version', '0x' + WWL.hex4(flagsVer), [p0, p0 + 2], [
          node('.... .... .... ...0 = Checksum', hasC ? 'Set' : 'Not set', [p0, p0 + 2]),
          node('.... .... .... ...0 = Routing', hasR ? 'Set' : 'Not set', [p0, p0 + 2]),
          node('.... .... .... ...0 = Key', hasK ? 'Set' : 'Not set', [p0, p0 + 2]),
          node('.... .... .... ...0 = Sequence number', hasS ? 'Set' : 'Not set', [p0, p0 + 2]),
          node('Protocol Type', protoName + ' (0x' + WWL.hex4(proto) + ')', [p0 + 2, p0 + 4])
        ])
      ]));
    }
    if (proto === 0x0800) ipv4Dissect(r, m, tree, r.p);
    else if (proto === 0x86dd) ipv6Dissect(r, m, tree, r.p);
    else if (proto === 0x6558 && r.remaining() >= 14) ethernetPayload(r, m, tree, r.p);
    else if (proto === 0x88be && r.remaining() >= 12) { r.skip(8); ipv4Dissect(r, m, tree, r.p); }
  }

  function vxlanDissect(r, m, tree, parent, start) {
    const p0 = r.p;
    const flags = r.u8();
    r.skip(3); // Reserved (24 bits)
    const vni = r.u24();
    r.u8();
    m.tunnel = 'vxlan';
    m.app = 'vxlan';
    m.info = 'VXLAN, VNI: ' + vni;
    if (tree && parent) {
      parent.children.push(node('Virtual eXtensible Local Area Network', 'VNI: ' + vni, [p0, r.p], [
        node('Flags', '0x' + WWL.u8hex(flags), [p0, p0 + 1]),
        node('VXLAN Network Identifier (VNI)', vni, [p0 + 4, p0 + 7])
      ]));
    }
    if (r.remaining() >= 14) ethernetPayload(r, m, tree, r.p);
  }

  function igmpDissect(r, m, tree, start) {
    const p0 = r.p;
    const type = r.u8(), maxResp = r.u8(), csum = r.u16();
    const group = WWL.ip4ToString(r.bytes(4));
    const name = IGMP_TYPE_NAMES[type] || ('Type 0x' + WWL.u8hex(type));
    m.proto = 'igmp';
    m.info = name + (group !== '0.0.0.0' ? ', Group: ' + group : '');
    if (tree) {
      tree.push(node('Internet Group Management Protocol', name, [p0, r.p], [
        node('Type', '0x' + WWL.u8hex(type) + ' (' + name + ')', [p0, p0 + 1]),
        node('Max Response Time', maxResp + (type === 0x11 ? ' (1/10 s)' : ''), [p0 + 1, p0 + 2]),
        node('Checksum', '0x' + WWL.hex4(csum), [p0 + 2, p0 + 4]),
        node('Group Address', group, [p0 + 4, p0 + 8])
      ]));
    }
  }

  function ospfDissect(r, m, tree, start) {
    const p0 = r.p;
    const version = r.u8(), type = r.u8(), plen = r.u16();
    const routerId = WWL.ip4ToString(r.bytes(4));
    const areaId = WWL.ip4ToString(r.bytes(4));
    const csum = r.u16(), autype = r.u16();
    const auth = r.bytes(8);
    const tn = OSPF_MSG_TYPES[type] || ('Type ' + type);
    m.proto = 'ospf';
    if (type === 1 && r.remaining() >= 20) {
      const mask = WWL.ip4ToString(r.bytes(4));
      const helloInt = r.u16();
      const opts = r.u8(), prio = r.u8();
      const deadInt = r.u32();
      const dr = WWL.ip4ToString(r.bytes(4));
      const bdr = WWL.ip4ToString(r.bytes(4));
      const neighbors = [];
      while (r.remaining() >= 4) neighbors.push(WWL.ip4ToString(r.bytes(4)));
      m.info = 'OSPF Hello, Router: ' + routerId + ', Area: ' + areaId + ', Neighbors: ' + neighbors.length;
      if (tree) {
        tree.push(node('Open Shortest Path First - Hello', '', [p0, r.p], [
          node('Version', version, [p0, p0 + 1]),
          node('Message Type', tn + ' (' + type + ')', [p0 + 1, p0 + 2]),
          node('Router ID', routerId, [p0 + 4, p0 + 8]),
          node('Area ID', areaId, [p0 + 8, p0 + 12]),
          node('Network Mask', mask, [p0 + 24, p0 + 28]),
          node('Hello Interval', helloInt + 's', [p0 + 28, p0 + 30]),
          node('Router Priority', prio, [p0 + 31, p0 + 32]),
          node('Dead Interval', deadInt + 's', [p0 + 32, p0 + 36]),
          node('Designated Router', dr, [p0 + 36, p0 + 40]),
          node('Backup Designated Router', bdr, [p0 + 40, p0 + 44]),
          node('Neighbors', neighbors.length, [p0 + 44, r.p])
        ]));
      }
    } else if (type === 4 && r.remaining() >= 2) {
      const numLsa = r.u16();
      m.info = 'OSPF Link State Update, ' + numLsa + ' LSA(s), Router: ' + routerId;
      if (tree) tree.push(node('Open Shortest Path First - Link State Update', numLsa + ' LSA(s)', [p0, r.p], [
        node('Version', version, [p0, p0 + 1]),
        node('Message Type', tn + ' (' + type + ')', [p0 + 1, p0 + 2]),
        node('Router ID', routerId, [p0 + 4, p0 + 8]),
        node('Area ID', areaId, [p0 + 8, p0 + 12]),
        node('Number of LSAs', numLsa, [p0 + 24, p0 + 26])
      ]));
    } else {
      m.info = 'OSPF ' + tn + ', Router: ' + routerId + ', Area: ' + areaId;
      if (tree) {
        tree.push(node('Open Shortest Path First', tn, [p0, r.p], [
          node('Version', version, [p0, p0 + 1]),
          node('Message Type', tn + ' (' + type + ')', [p0 + 1, p0 + 2]),
          node('Router ID', routerId, [p0 + 4, p0 + 8]),
          node('Area ID', areaId, [p0 + 8, p0 + 12])
        ]));
      }
    }
  }

  function eigrpDissect(r, m, tree, start) {
    const p0 = r.p;
    const version = r.u8(), opcode = r.u8(), csum = r.u16();
    const flags = r.u32(), seq = r.u32(), ack = r.u32(), asn = r.u32();
    const names = { 1: 'Update', 3: 'Request', 5: 'Hello', 6: 'ACK', 7: 'SIA Query', 8: 'SIA Reply' };
    m.proto = 'eigrp';
    m.info = 'EIGRP ' + (names[opcode] || ('Opcode ' + opcode)) + ', AS: ' + asn;
    if (tree) {
      tree.push(node('Enhanced Interior Gateway Routing Protocol', names[opcode] || opcode, [p0, r.p], [
        node('Version', version, [p0, p0 + 1]),
        node('Opcode', opcode + ' (' + (names[opcode] || 'Unknown') + ')', [p0 + 1, p0 + 2]),
        node('Checksum', '0x' + WWL.hex4(csum), [p0 + 2, p0 + 4]),
        node('Flags', '0x' + WWL.hex8(flags), [p0 + 4, p0 + 8]),
        node('Sequence', seq, [p0 + 8, p0 + 12]),
        node('Acknowledgement', ack, [p0 + 12, p0 + 16]),
        node('Autonomous System Number', asn, [p0 + 16, p0 + 20])
      ]));
    }
  }

  function vrrpDissect(r, m, tree, start) {
    const p0 = r.p;
    const verType = r.u8();
    const version = verType >> 4, type = verType & 0xf;
    const vrid = r.u8(), priority = r.u8();
    const count = r.u8(), autype = r.u8(), advInt = r.u8(), csum = r.u16();
    const vips = [];
    for (let i = 0; i < count && r.remaining() >= 4; i++) vips.push(WWL.ip4ToString(r.bytes(4)));
    m.proto = 'vrrp';
    m.info = 'VRRPv' + version + ' Advertisement, VRID: ' + vrid + ', Priority: ' + priority + (vips.length ? ', VIPs: ' + vips.join(', ') : '');
    if (tree) {
      tree.push(node('Virtual Router Redundancy Protocol', 'VRRPv' + version, [p0, r.p], [
        node('Version / Type', 'Version ' + version + ', Type ' + type, [p0, p0 + 1]),
        node('Virtual Rtr ID', vrid, [p0 + 1, p0 + 2]),
        node('Priority', priority, [p0 + 2, p0 + 3]),
        node('Count IP Addrs', count, [p0 + 3, p0 + 4]),
        node('Adver Int', advInt + 's', [p0 + 5, p0 + 6]),
        node('Checksum', '0x' + WWL.hex4(csum), [p0 + 6, p0 + 8])
      ].concat(vips.map(function (ip, i) { return node('Virtual IP ' + (i + 1), ip, [p0 + 8 + i * 4, p0 + 12 + i * 4]); }))));
    }
  }

  function sctpDissect(r, m, tree, start) {
    const p0 = r.p;
    const sport = r.u16(), dport = r.u16(), vtag = r.u32(), csum = r.u32();
    m.tproto = 'sctp';
    m.sport = sport;
    m.dport = dport;
    m.proto = 'sctp';
    const chunks = [];
    let guard = 0;
    while (r.remaining() >= 4 && guard++ < 8) {
      const ct = r.u8(), cflags = r.u8(), clen = r.u16();
      if (clen < 4 || clen - 4 > r.remaining()) break;
      chunks.push({ name: SCTP_CHUNK_NAMES[ct] || ('Chunk ' + ct), len: clen });
      if (clen > 4) r.skip(clen - 4);
    }
    m.info = 'SCTP, Src Port: ' + sport + ', Dst Port: ' + dport +
      (chunks.length ? ', ' + chunks.map(function (c) { return c.name + '(' + c.len + ')'; }).join(', ') : '');
    if (tree) {
      tree.push(node('Stream Control Transmission Protocol', 'Src Port: ' + sport + ', Dst Port: ' + dport, [p0, r.p], [
        node('Source Port', sport, [p0, p0 + 2]),
        node('Destination Port', dport, [p0 + 2, p0 + 4]),
        node('Verification Tag', '0x' + WWL.hex8(vtag), [p0 + 4, p0 + 8]),
        node('Checksum', '0x' + WWL.hex8(csum), [p0 + 8, p0 + 12])
      ].concat(chunks.map(function (c) { return node('Chunk: ' + c.name, 'Length: ' + c.len, null); }))));
    }
  }

  function espDissect(r, m, tree, start) {
    const p0 = r.p;
    const spi = r.u32(), seq = r.u32();
    m.proto = 'esp';
    m.info = 'Encapsulating Security Payload, SPI: 0x' + WWL.hex8(spi) + ', Seq: ' + seq + ' (encrypted payload)';
    if (tree) {
      tree.push(node('Encapsulating Security Payload', '', [p0, r.p], [
        node('Security Parameters Index', '0x' + WWL.hex8(spi), [p0, p0 + 4]),
        node('Sequence Number', seq, [p0 + 4, p0 + 8])
      ]));
    }
  }

  function ahDissect(r, m, tree, start) {
    const p0 = r.p;
    const nextHdr = r.u8(), payloadLen = r.u8(), reserved = r.u16();
    const spi = r.u32(), seq = r.u32();
    const hdrLen = (payloadLen + 2) * 4;
    m.proto = 'ah';
    m.info = 'Authentication Header, Next Header: ' + (IP_PROTO[nextHdr] || nextHdr) + ', SPI: 0x' + WWL.hex8(spi) + ', Seq: ' + seq;
    if (tree) {
      tree.push(node('Authentication Header', '', [p0, Math.min(p0 + hdrLen, r.b.length)], [
        node('Next Header', IP_PROTO[nextHdr] || String(nextHdr), [p0, p0 + 1]),
        node('Payload Length', (payloadLen + 2) + ' (32-bit words)', [p0 + 1, p0 + 2]),
        node('Security Parameters Index', '0x' + WWL.hex8(spi), [p0 + 4, p0 + 8]),
        node('Sequence Number', seq, [p0 + 8, p0 + 12])
      ]));
    }
  }

  function tacacsDissect(r, m, tree, parent, start) {
    const p0 = r.p;
    if (r.remaining() < 12) return false;
    const ver = r.u8();
    if ((ver & 0xf0) !== 0xc0) return false; // TACACS+ 主版本
    const type = r.u8(), seq = r.u8(), flags = r.u8();
    const session = r.u32(), length = r.u32();
    if (length > r.remaining()) return false;
    m.proto = 'tacacs';
    m.app = 'tacacs';
    const typeName = TACACS_TYPE_NAMES[type] || ('Type ' + type);
    let extra = '';
    if (type === 1 && seq === 1 && length >= 5) {
      const action = r.u8(), priv = r.u8(), aType = r.u8(), service = r.u8();
      const userLen = r.u8();
      let user = '';
      if (userLen <= r.remaining()) user = asciiBytes(r.bytes(userLen));
      const portLen = r.u8(); if (portLen <= r.remaining()) r.skip(portLen);
      const remLen = r.u8(); if (remLen <= r.remaining()) r.skip(remLen);
      const dataLen = r.u8(); if (dataLen <= r.remaining()) r.skip(dataLen);
      extra = ', ' + (TACACS_ACTION_NAMES[action] || ('action ' + action)) +
        ', Service: ' + (TACACS_SERVICE_NAMES[service] || service) +
        (user ? ', User: ' + user : '');
    }
    m.info = 'TACACS+ ' + typeName + ' (seq ' + seq + '), Session: 0x' + WWL.hex8(session) + extra;
    if (tree && parent) {
      parent.children.push(node('Terminal Access Controller Access-Control System Plus', typeName, [p0, r.p], [
        node('Version', '0x' + WWL.u8hex(ver), [p0, p0 + 1]),
        node('Type', typeName + ' (' + type + ')', [p0 + 1, p0 + 2]),
        node('Sequence Number', seq, [p0 + 2, p0 + 3]),
        node('Session ID', '0x' + WWL.hex8(session), [p0 + 4, p0 + 8]),
        node('Length', length, [p0 + 8, p0 + 12])
      ]));
    }
    return true;
  }

  function bgpParseAsPath(v) {
    const parts = [];
    let p = 0;
    while (p + 2 <= v.length) {
      const segType = v[p], segCount = v[p + 1];
      p += 2;
      const ases = [];
      for (let i = 0; i < segCount && p + 2 <= v.length; i++) {
        ases.push(String((v[p] << 8) | v[p + 1]));
        p += 2;
      }
      parts.push((segType === 2 ? 'Sequence: ' : 'Set: ') + ases.join(' '));
    }
    return parts.join(', ');
  }

  function bgpDissect(r, m, tree, parent, start) {
    const p0 = r.p;
    if (r.remaining() < 19) return false;
    const marker = r.bytes(16);
    let markerOk = true;
    const first = marker[0];
    for (let i = 0; i < 16; i++) if (marker[i] !== first || (first !== 0xff && first !== 0x00)) { markerOk = false; break; }
    if (!markerOk) return false;
    const length = r.u16();
    if (length < 19 || length - 19 > r.remaining()) return false;
    const type = r.u8();
    const typeName = BGP_TYPE_NAMES[type] || ('Type ' + type);
    m.proto = 'bgp';
    m.app = 'bgp';
    let info = 'Border Gateway Protocol - ' + typeName;
    const bodyStart = r.p;
    if (type === 1 && length >= 29) {
      const version = r.u8(), asn = r.u16(), hold = r.u16();
      const id = WWL.ip4ToString(r.bytes(4));
      const optLen = r.u8();
      if (optLen <= r.remaining()) r.skip(optLen);
      info += ', AS ' + asn + ', Hold ' + hold + 's, BGP ID ' + id;
    } else if (type === 2 && length >= 23) {
      const withdrawnLen = r.u16();
      if (withdrawnLen <= r.remaining()) r.skip(withdrawnLen);
      const attrs = [];
      if (r.remaining() >= 2) {
        const attrLen = r.u16();
        const attrEnd = Math.min(r.p + attrLen, r.b.length);
        while (r.p + 3 <= attrEnd) {
          const flags = r.u8();
          const at = r.u8() & 0x3f;
          let alen = r.u8();
          if (flags & 0x10) alen = (alen << 8) | r.u8();
          if (alen > r.remaining() || r.p + alen > attrEnd) break;
          const av = r.bytes(alen);
          if (at === 3 && alen >= 4) attrs.push('Next-hop ' + WWL.ip4ToString(av));
          else if (at === 2) {
            const seg = bgpParseAsPath(av);
            if (seg) attrs.push('AS_PATH {' + seg + '}');
          } else if (at === 1 && alen >= 1) attrs.push('Origin ' + (av[0] === 0 ? 'IGP' : av[0] === 1 ? 'EGP' : 'Incomplete'));
          else if (at === 4 && alen >= 4) attrs.push('MED ' + ((av[0] << 24) | (av[1] << 16) | (av[2] << 8) | av[3]));
          else if (at === 5 && alen >= 4) attrs.push('LocalPref ' + ((av[0] << 24) | (av[1] << 16) | (av[2] << 8) | av[3]));
          else if (at === 8 && alen >= 4) attrs.push('Community ' + WWL.hex4((av[0] << 8) | av[1]) + ':' + WWL.hex4((av[2] << 8) | av[3]));
          else attrs.push(BGP_ATTR_NAMES[at] || ('Attr ' + at));
          if (flags & 0x20) break;
        }
      }
      info += attrs.length ? ', ' + attrs.join(', ') : ', no attributes';
    } else if (type === 3 && length >= 21) {
      const code = r.u8(), subcode = r.u8();
      info += ', ' + (BGP_NOTIF_CODES[code] || ('Error ' + code)) + (subcode ? ' (' + subcode + ')' : '');
    } else if (type === 4) {
      // KEEPALIVE
    } else if (type === 5 && length >= 23) {
      const afi = r.u16(), res = r.u8(), safi = r.u8();
      info += ', AFI ' + afi + ', SAFI ' + safi;
    }
    m.info = info;
    if (tree && parent) {
      parent.children.push(node('Border Gateway Protocol', typeName, [p0, p0 + length], [
        node('Marker', '0x' + hexBytes(marker), [p0, p0 + 16]),
        node('Length', length, [p0 + 16, p0 + 18]),
        node('Type', typeName + ' (' + type + ')', [p0 + 18, p0 + 19])
      ]));
    }
    return true;
  }

  function radiusDissect(r, m, tree, parent, start) {
    const p0 = r.p;
    if (r.remaining() < 20) return false;
    const code = r.u8(), id = r.u8(), length = r.u16();
    if (length < 20 || length - 20 > r.remaining()) return false;
    const auth = r.bytes(16);
    let user = '', statusType = '';
    const attrs = [];
    while (r.remaining() >= 2) {
      const t = r.u8(), alen = r.u8();
      if (alen < 2 || alen - 2 > r.remaining()) break;
      const valStart = r.p;
      const v = r.bytes(alen - 2);
      let text = '';
      if (t === 1) { user = asciiBytes(v); text = user; }
      else if (t === 4 && v.length >= 4) text = WWL.ip4ToString(v);
      else if (t === 40 && v.length >= 4) {
        statusType = String((v[0] << 24) | (v[1] << 16) | (v[2] << 8) | v[3]);
        text = ACCT_STATUS_NAMES[statusType] || statusType;
      }
      else if (t === 6 && v.length >= 1) text = 'Service-Type ' + v[0];
      else if (t === 8 && v.length >= 4) text = WWL.ip4ToString(v);
      else text = hexBytes(v);
      attrs.push({ t: t, range: [valStart, r.p], text: text });
    }
    m.proto = 'radius';
    m.app = 'radius';
    m.info = 'RADIUS ' + (RADIUS_CODE_NAMES[code] || ('Code ' + code)) + ', Id: ' + id +
      (user ? ', User-Name: ' + user : '') +
      (statusType ? ', Status-Type: ' + (ACCT_STATUS_NAMES[statusType] || statusType) : '');
    if (tree && parent) {
      parent.children.push(node('Remote Authentication Dial In User Service', RADIUS_CODE_NAMES[code] || code, [p0, p0 + length], [
        node('Code', (RADIUS_CODE_NAMES[code] || code) + ' (' + code + ')', [p0, p0 + 1]),
        node('Packet Identifier', id, [p0 + 1, p0 + 2]),
        node('Length', length, [p0 + 2, p0 + 4]),
        node('Authenticator', hexBytes(auth), [p0 + 4, p0 + 20])
      ].concat(attrs.map(function (a) {
        return node(RADIUS_ATTR_NAMES[a.t] || ('Attribute ' + a.t), a.text, a.range);
      }))));
    }
    return true;
  }

  function ntpDissect(r, m, tree, parent, start) {
    const p0 = r.p;
    if (r.remaining() < 48) return false;
    const b0 = r.u8();
    const vn = (b0 >> 3) & 0x7, mode = b0 & 0x7;
    const stratum = r.u8();
    const poll = r.u8(), precision = r.u8();
    r.skip(44);
    m.proto = 'ntp';
    m.app = 'ntp';
    m.info = 'Network Time Protocol v' + vn + ', ' + (NTP_MODE_NAMES[mode] || ('mode ' + mode)) + (stratum ? ', stratum ' + stratum : '');
    if (tree && parent) {
      parent.children.push(node('Network Time Protocol', 'v' + vn, [p0, p0 + 48], [
        node('Flags', '0x' + WWL.u8hex(b0), [p0, p0 + 1]),
        node('Version', vn, [p0, p0 + 1]),
        node('Mode', NTP_MODE_NAMES[mode] || String(mode), [p0, p0 + 1]),
        node('Stratum', stratum, [p0 + 1, p0 + 2]),
        node('Poll Interval', poll + 's', [p0 + 2, p0 + 3]),
        node('Precision', precision, [p0 + 3, p0 + 4])
      ]));
    }
    return true;
  }

  function tftpDissect(r, m, tree, parent, start) {
    const p0 = r.p;
    if (r.remaining() < 2) return false;
    const op = r.u16();
    const names = { 1: 'Read Request', 2: 'Write Request', 3: 'Data', 4: 'Acknowledgment', 5: 'Error' };
    m.proto = 'tftp';
    m.app = 'tftp';
    let extra = '';
    if (op === 1 || op === 2) {
      let fname = '';
      while (r.remaining() > 0) {
        const c = r.u8();
        if (c === 0) break;
        fname += String.fromCharCode(c);
      }
      extra = ', Filename: ' + (fname || '(empty)');
    } else if (op === 4 && r.remaining() >= 2) {
      extra = ', Block: ' + r.u16();
    }
    m.info = 'Trivial File Transfer Protocol, ' + (names[op] || ('Opcode ' + op)) + extra;
    if (tree && parent) {
      parent.children.push(node('Trivial File Transfer Protocol', names[op] || op, [p0, r.p], [
        node('Opcode', (names[op] || op) + ' (' + op + ')', [p0, p0 + 2])
      ]));
    }
    return true;
  }

  /* 通用文本协议（SSH/FTP/SMTP/POP3/IMAP/SIP）：首行 + 头部 */
  function textProtocol(r, m, tree, parent, start, proto, re, label) {
    const b = r.b;
    const max = Math.min(r.remaining(), 4096);
    let lineEnd = -1;
    for (let i = 0; i < max - 1; i++) {
      if (b[start + i] === 13 && b[start + i + 1] === 10) { lineEnd = start + i; break; }
      if (b[start + i] === 10) { lineEnd = start + i; break; }
    }
    const lineLen = lineEnd >= 0 ? lineEnd - start : Math.min(max, 256);
    let first = '';
    for (let i = 0; i < lineLen; i++) first += String.fromCharCode(b[start + i]);
    if (!re.test(first)) return false;
    m.proto = proto;
    m.app = proto;
    m.info = first.length > 200 ? first.slice(0, 200) + '...' : first;
    if (tree && parent) {
      const bodyEnd = lineEnd >= 0 ? Math.min(b.length, lineEnd + 1) : Math.min(b.length, start + lineLen);
      const n = node(label, '', [start, bodyEnd], [node('Line', first, [start, start + lineLen])]);
      if (lineEnd >= 0) {
        let p = lineEnd + 1;
        if (b[lineEnd] === 13) p++;
        let guard = 0;
        while (p + 1 < b.length && guard++ < 64) {
          let e = p;
          while (e + 1 < b.length && !(b[e] === 13 && b[e + 1] === 10) && b[e] !== 10) e++;
          if (e + 1 >= b.length && b[e] !== 10) break;
          if (e === p) break;
          let line = '';
          for (let i = p; i < e; i++) line += String.fromCharCode(b[i]);
          const ci = line.indexOf(':');
          const hname = ci >= 0 ? line.slice(0, ci) : line;
          const hval = ci >= 0 ? line.slice(ci + 1).trim() : '';
          n.children.push(node(hname, hval, [p, e]));
          p = e + 1;
          if (b[e] === 13) p++;
        }
      }
      parent.children.push(n);
    }
    return true;
  }

  /* ---------------- LACP / 802.3 慢协议 ---------------- */
  function lacpDissect(r, m, tree, start) {
    const p0 = r.p; // 此时 r.p 指向 subtype
    const subtype = r.u8(); // 1
    const version = r.u8();
    m.proto = 'lacp';
    const tlvNodes = [];
    let actor = '';
    let guard = 0;
    while (r.remaining() >= 2 && guard++ < 4) {
      const t = r.u8(), len = r.u8();
      if (len === 0) { tlvNodes.push(node('Terminator', 'End of LACPDU', [r.p - 2, r.p])); break; }
      if (len < 20 || len - 20 > r.remaining()) break;
      if (t === 1 || t === 2) {
        const tlvStart = r.p - 2;
        const sysPri = r.u16();
        const sysMac = WWL.macToString(r.bytes(6));
        const key = r.u16();
        const portPri = r.u16();
        const port = r.u16();
        const state = r.u8();
        const reserved = r.bytes(3);
        const role = t === 1 ? 'Actor' : 'Partner';
        const stateBits = [
          [0, 'Activity', state & 0x01 ? 'Active' : 'Passive'],
          [1, 'Timeout', state & 0x02 ? 'Short Timeout' : 'Long Timeout'],
          [2, 'Aggregation', state & 0x04 ? 'Aggregation' : 'Individual'],
          [3, 'Synchronization', state & 0x08 ? 'In Sync' : 'Out of Sync'],
          [4, 'Collecting', state & 0x10 ? 'Collecting' : 'Not Collecting'],
          [5, 'Distributing', state & 0x20 ? 'Distributing' : 'Not Distributing'],
          [6, 'Defaulted', state & 0x40 ? 'Defaulted' : 'Not Defaulted'],
          [7, 'Expired', state & 0x80 ? 'Expired' : 'Not Expired']
        ];
        if (t === 1) {
          actor = 'System ' + sysPri + '/' + sysMac + ', Key ' + key + ', Port ' + port;
        }
        tlvNodes.push(node(role, '', [tlvStart, r.p], [
          node('System Priority', sysPri, [tlvStart + 2, tlvStart + 4]),
          node('System', sysMac, [tlvStart + 4, tlvStart + 10]),
          node('Key', key, [tlvStart + 10, tlvStart + 12]),
          node('Port Priority', portPri, [tlvStart + 12, tlvStart + 14]),
          node('Port', port, [tlvStart + 14, tlvStart + 16]),
          node('State', '0x' + WWL.u8hex(state), [tlvStart + 16, tlvStart + 17],
            stateBits.map(function (b) {
              let bits = '';
              for (let bit = 7; bit >= 0; bit--) bits += (bit === b[0] ? '1' : '.');
              return node(bits + ' = ' + b[1], b[2], [tlvStart + 16, tlvStart + 17]);
            })),
          node('Reserved', hexBytes(reserved), [tlvStart + 17, tlvStart + 20])
        ]));
      } else {
        r.skip(Math.max(0, len - 2));
      }
    }
    m.info = 'Link Aggregation Control Protocol' + (actor ? ', ' + actor : '');
    if (tree) {
      tree.push(node('Link Aggregation Control Protocol', 'Version: ' + version, [p0, r.p], [
        node('Subtype', 'LACP (' + subtype + ')', [p0, p0 + 1]),
        node('Version', version, [p0 + 1, p0 + 2])
      ].concat(tlvNodes)));
    }
  }

  function slowProtocolsDissect(r, m, tree, start) {
    const p0 = r.p;
    const subtype = r.u8();
    const name = SLOW_PROTOCOL_NAMES[subtype] || ('Slow protocol ' + subtype);
    if (subtype === 1) { r.seek(p0); lacpDissect(r, m, tree, p0); return; }
    if (subtype === 2 || subtype === 3) {
      m.proto = 'lacp';
      if (r.remaining() >= 5) {
        const version = r.u8();
        const t = r.u8(), len = r.u8();
        const reqPort = r.u16();
        const reqSys = WWL.macToString(r.bytes(6));
        m.info = 'Link Aggregation Control Protocol, ' + (subtype === 2 ? 'Marker' : 'Marker Response') + ', Requester Port ' + reqPort + ', System ' + reqSys;
        if (tree) tree.push(node('LACP ' + (subtype === 2 ? 'Marker' : 'Marker Response'), '', [p0, r.p], [
          node('Requester Port', reqPort, [p0 + 5, p0 + 7]),
          node('Requester System ID', reqSys, [p0 + 7, p0 + 13])
        ]));
      } else {
        m.info = name;
        if (tree) tree.push(node('Slow Protocols', name, [p0, r.p]));
      }
      return;
    }
    m.proto = 'slow';
    m.info = name;
    if (tree) tree.push(node('Slow Protocols', name, [p0, r.p], [
      node('Subtype', '0x' + WWL.u8hex(subtype) + ' (' + name + ')', [p0, p0 + 1])
    ]));
  }

  /* ---------------- EAPOL / EAP ---------------- */
  function eapDissect(r, m, tree, parent, start) {
    const p0 = r.p;
    if (r.remaining() < 4) return false;
    const code = r.u8(), id = r.u8(), length = r.u16();
    const codeName = EAP_CODE_NAMES[code] || ('Code ' + code);
    m.proto = 'eap';
    let extra = '';
    if (code === 1 || code === 2) {
      if (r.remaining() >= 1) {
        const t = r.u8();
        extra = ', ' + (EAP_TYPE_NAMES[t] || ('Type ' + t));
      }
    }
    m.info = 'Extensible Authentication Protocol, ' + codeName + extra;
    if (tree && parent) {
      parent.children.push(node('Extensible Authentication Protocol', codeName, [p0, Math.min(p0 + length, r.b.length)], [
        node('Code', codeName + ' (' + code + ')', [p0, p0 + 1]),
        node('Identifier', id, [p0 + 1, p0 + 2]),
        node('Length', length, [p0 + 2, p0 + 4])
      ]));
    }
    return true;
  }

  function eapolDissect(r, m, tree, start) {
    const p0 = r.p;
    const version = r.u8(), type = r.u8(), length = r.u16();
    const names = { 0: 'EAP Packet', 1: 'EAPOL Start', 2: 'EAPOL Logoff', 3: 'EAPOL Key', 4: 'EAPOL Encapsulated-ASF-Alert' };
    const name = names[type] || ('EAPOL type ' + type);
    m.proto = 'eapol';
    m.info = name;
    if (tree) {
      const n = node('EAP over LAN', name, [p0, r.p], [
        node('Version', version + ' (IEEE 802.1X-' + (version === 1 ? '2001' : version === 2 ? '2004' : '2010') + ')', [p0, p0 + 1]),
        node('Type', name + ' (' + type + ')', [p0 + 1, p0 + 2]),
        node('Length', length, [p0 + 2, p0 + 4])
      ]);
      tree.push(n);
      if (type === 0) eapDissect(r, m, tree, n, r.p);
    } else if (type === 0) {
      eapDissect(r, m, tree, null, r.p);
    }
  }

  /* ---------------- HSRP / BFD ---------------- */
  function hsrpDissect(r, m, tree, parent, start) {
    const p0 = r.p;
    if (r.remaining() < 20) return false;
    const version = r.u8(), opcode = r.u8(), state = r.u8(), hellotime = r.u8();
    const holdtime = r.u8(), priority = r.u8(), group = r.u8(), reserved = r.u8();
    const auth = r.bytes(8);
    const vip = WWL.ip4ToString(r.bytes(4));
    m.proto = 'hsrp';
    m.app = 'hsrp';
    m.info = 'HSRPv' + version + ' ' + (HSRP_OPCODES[opcode] || ('Opcode ' + opcode)) +
      ', Group ' + group + ', State ' + (HSRP_STATES[state] || state) +
      ', Priority ' + priority + ', Virtual IP ' + vip;
    if (tree && parent) {
      parent.children.push(node('Hot Standby Router Protocol', 'HSRPv' + version, [p0, p0 + 20], [
        node('Opcode', (HSRP_OPCODES[opcode] || opcode) + ' (' + opcode + ')', [p0 + 1, p0 + 2]),
        node('State', HSRP_STATES[state] || String(state), [p0 + 2, p0 + 3]),
        node('Hello Time', hellotime + 's', [p0 + 3, p0 + 4]),
        node('Hold Time', holdtime + 's', [p0 + 4, p0 + 5]),
        node('Priority', priority, [p0 + 5, p0 + 6]),
        node('Group', group, [p0 + 6, p0 + 7]),
        node('Authentication Data', asciiBytes(auth) || hexBytes(auth), [p0 + 8, p0 + 16]),
        node('Virtual IP Address', vip, [p0 + 16, p0 + 20])
      ]));
    }
    return true;
  }

  function bfdDissect(r, m, tree, parent, start) {
    const p0 = r.p;
    if (r.remaining() < 24) return false;
    const b0 = r.u8();
    const version = b0 >> 5;
    const diag = b0 & 0x1f;
    const b1 = r.u8();
    const state = (b1 >> 6) & 0x3;
    const poll = !!(b1 & 0x20), fin = !!(b1 & 0x10), cplane = !!(b1 & 0x08);
    const auth = !!(b1 & 0x04), demand = !!(b1 & 0x02), multipoint = !!(b1 & 0x01);
    const detectMult = r.u8();
    const length = r.u8();
    const myDisc = r.u32(), yourDisc = r.u32();
    const txInt = r.u32(), rxInt = r.u32(), echoInt = r.u32();
    m.proto = 'bfd';
    m.app = 'bfd';
    m.info = 'Bidirectional Forwarding Detection (Control), State ' + (BFD_STATES[state] || state) +
      ', My Discriminator: ' + myDisc + ', Your Discriminator: ' + yourDisc;
    if (tree && parent) {
      parent.children.push(node('Bidirectional Forwarding Detection', 'Control, State ' + (BFD_STATES[state] || state), [p0, p0 + 24], [
        node('Version', version, [p0, p0 + 1]),
        node('Diagnostic', diag, [p0, p0 + 1]),
        node('State', BFD_STATES[state] || String(state), [p0 + 1, p0 + 2]),
        node('Poll / Final', 'P: ' + (poll ? 1 : 0) + ', F: ' + (fin ? 1 : 0), [p0 + 1, p0 + 2]),
        node('Detect Multiplier', detectMult, [p0 + 2, p0 + 3]),
        node('My Discriminator', myDisc, [p0 + 4, p0 + 8]),
        node('Your Discriminator', yourDisc, [p0 + 8, p0 + 12]),
        node('Desired Min TX Interval', txInt + ' us', [p0 + 12, p0 + 16]),
        node('Required Min RX Interval', rxInt + ' us', [p0 + 16, p0 + 20]),
        node('Required Min Echo Interval', echoInt + ' us', [p0 + 20, p0 + 24])
      ]));
    }
    return true;
  }

  /* ---------------- InfiniBand（链路类型 169） ---------------- */
  function ibDissect(r, m, tree, start) {
    const p0 = r.p;
    if (r.remaining() < 8) {
      m.proto = 'ib';
      m.info = 'InfiniBand (truncated)';
      return;
    }
    const b0 = r.u8();
    const vl = b0 >> 4, lver = b0 & 0xf;
    const b1 = r.u8();
    const sl = b1 >> 4, lnh = (b1 >> 2) & 0x3;
    const dlid = r.u16(), slid = r.u16();
    const b4 = r.u16();
    const pkLen = b4 & 0x1f;
    m.l2 = 'ib';
    m.proto = 'ib';
    m.info = 'InfiniBand, Src LID: ' + slid + ', Dst LID: ' + dlid + ', SL: ' + sl + ', Packet length: ' + (pkLen * 4) + ' bytes';
    if (tree) {
      tree.push(node('InfiniBand Local Route Header', '', [p0, p0 + 8], [
        node('Virtual Lane', vl, [p0, p0 + 1]),
        node('Link Version', lver, [p0, p0 + 1]),
        node('Service Level', sl, [p0 + 1, p0 + 2]),
        node('Link Next Header', lnh === 0 ? 'Immediate Data (0)' : lnh === 1 ? 'BTH (1)' : String(lnh), [p0 + 1, p0 + 2]),
        node('Destination LID', dlid, [p0 + 2, p0 + 4]),
        node('Source LID', slid, [p0 + 4, p0 + 6]),
        node('Packet Length', (pkLen * 4) + ' bytes', [p0 + 6, p0 + 8])
      ]));
    }
    if (r.remaining() >= 12) {
      const opcode = r.u8();
      const tver = r.u8();
      const pkey = r.u16();
      const destQp = r.u32();
      r.skip(4);
      const opName = IB_OPCODES[opcode] || ('Opcode 0x' + WWL.u8hex(opcode));
      m.info += ', ' + opName + ', Dest QP: ' + (destQp & 0xffffff);
      if (tree) {
        tree.push(node('InfiniBand Base Transport Header', '', [r.p - 12, r.p], [
          node('Opcode', opName + ' (0x' + WWL.u8hex(opcode) + ')', [r.p - 12, r.p - 11]),
          node('Partition Key', '0x' + WWL.hex4(pkey), [r.p - 10, r.p - 8]),
          node('Destination Queue Pair', destQp & 0xffffff, [r.p - 8, r.p - 4])
        ]));
      }
    }
  }

  WWL.linkTypeName = function (id) {
    const map = {
      0: 'Null/Loopback', 1: 'Ethernet', 6: 'IEEE 802.3 Ethernet', 9: 'PPP',
      12: 'Raw IP', 50: 'PPPoE', 51: 'PPPoE', 101: 'Raw IP', 104: 'Cisco HDLC',
      105: 'Cisco HDLC', 108: 'Loopback', 113: 'Linux SLL', 127: 'Radiotap',
      228: 'IEEE 802.11', 276: 'Linux SLL2'
    };
    return map[id] || ('Link Type ' + id);
  };

  function dissect(data, opts, brief) {
    const linkType = opts.linkType;
    const endian = opts.endian || 'le';
    // 报文负载字段均为网络字节序（大端），与 pcap 文件字节序无关
    const r = new Reader(data, false);
    const m = {
      src: '', dst: '', macSrc: '', macDst: '', ethType: 0,
      l2: '', l3: '', tunnel: '', tcpFlags: 0, proto: 'other', tproto: '', sport: 0, dport: 0, info: '', app: ''
    };
    const tree = brief ? null : [];
    let etherType = 0;
    let l3start = r.p;
    let l3Handled = false;

    switch (linkType) {
      case 1: case 6: {
        const er = ethernetDissect(r, m, tree);
        etherType = m.ethType;
        l3Handled = er.l3Handled;
        break;
      }
      case 127: {
        // Radiotap 头（固定小端）
        if (r.remaining() >= 8) {
          const rtLen = r.b[r.p + 2] | (r.b[r.p + 3] << 8);
          if (rtLen >= 8 && rtLen <= r.remaining()) {
            if (tree) tree.push(node('Radiotap Header', 'Version: ' + r.b[r.p] + ', Header length: ' + rtLen, [r.p, r.p + rtLen]));
            r.skip(rtLen);
          }
        }
        dot11Dissect(r, m, tree, r.p);
        l3Handled = true;
        break;
      }
      case 228:
        dot11Dissect(r, m, tree, r.p);
        l3Handled = true;
        break;
      case 169:
        ibDissect(r, m, tree, r.p);
        l3Handled = true;
        break;
      case 9: case 50: case 51: case 104: case 105:
        pppDissect(r, m, tree, r.p, linkType);
        l3Handled = true;
        break;
      case 0: case 108: {
        const famRaw = r.u32();
        if (famRaw === 2 || famRaw === 0x02000000) etherType = 0x0800;
        else if (famRaw === 24 || famRaw === 0x18000000 || famRaw === 28 || famRaw === 0x1c000000 || famRaw === 30 || famRaw === 0x1e000000) etherType = 0x86dd;
        else {
          m.info = 'Unknown address family ' + famRaw;
          if (tree) tree.push(node('Loopback encapsulation', 'Family ' + famRaw, [0, 4]));
          return { meta: m, tree: tree };
        }
        m.l2 = 'null';
        break;
      }
      case 12: case 101: {
        if (data.length === 0) { m.info = 'Empty frame'; return { meta: m, tree: tree }; }
        const ver = data[0] >> 4;
        etherType = ver === 4 ? 0x0800 : ver === 6 ? 0x86dd : 0;
        if (!etherType) {
          m.info = 'Unknown raw IP version ' + ver;
          return { meta: m, tree: tree };
        }
        m.l2 = 'raw';
        break;
      }
      case 113: {
        r.u16(); r.u16(); r.u16(); r.skip(8);
        etherType = r.u16();
        m.ethType = etherType;
        m.l2 = 'sll';
        break;
      }
      case 276: {
        etherType = r.u16();
        r.u16(); r.u32(); r.u16(); r.u8(); r.u8();
        r.skip(8);
        m.ethType = etherType;
        m.l2 = 'sll';
        break;
      }
      default: {
        m.info = 'Unsupported link type ' + linkType + ' (' + WWL.linkTypeName(linkType) + ')';
        if (tree) tree.push(node('Unsupported encapsulation', WWL.linkTypeName(linkType), [0, data.length]));
        return { meta: m, tree: tree };
      }
    }

    if (!l3Handled) dispatchL3(r, m, tree, etherType, l3start);

    if (!m.info) m.info = '(no payload)';
    return { meta: m, tree: tree };
  }

  WWL.dissectSummary = function (data, opts) {
    return dissect(data, opts, true).meta;
  };
  WWL.dissectFull = function (data, opts) {
    return dissect(data, opts, false);
  };
})(typeof window !== 'undefined' ? window : globalThis);
