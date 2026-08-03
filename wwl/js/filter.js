/* filter.js - Wireshark 风格显示过滤器：词法分析 + 递归下降解析 + 编译为匹配函数 */
(function (global) {
  'use strict';
  const WWL = global.WWL = global.WWL || {};

  function tokenize(src) {
    const tokens = [];
    let i = 0;
    while (i < src.length) {
      const c = src[i];
      if (c === ' ' || c === '\t' || c === '\n' || c === '\r') { i++; continue; }
      if (c === '(' || c === ')') { tokens.push({ type: 'paren', v: c }); i++; continue; }
      if (c === '=' && src[i + 1] === '=') { tokens.push({ type: 'op', v: '==' }); i += 2; continue; }
      if (c === '!' && src[i + 1] === '=') { tokens.push({ type: 'op', v: '!=' }); i += 2; continue; }
      if (c === '"' || c === "'") {
        let j = i + 1, s = '';
        while (j < src.length && src[j] !== c) { s += src[j]; j++; }
        tokens.push({ type: 'value', v: s });
        i = j + 1;
        continue;
      }
      if (/[0-9]/.test(c)) {
        let j = i;
        while (j < src.length && /[0-9a-fA-F.:]/.test(src[j])) j++;
        tokens.push({ type: 'value', v: src.slice(i, j) });
        i = j;
        continue;
      }
      if (/[a-zA-Z]/.test(c)) {
        let j = i;
        while (j < src.length && /[a-zA-Z0-9._:]/.test(src[j])) j++;
        const w = src.slice(i, j);
        const lw = w.toLowerCase();
        if (lw === 'and' || lw === 'or' || lw === 'not') tokens.push({ type: 'kw', v: lw });
        else tokens.push({ type: 'word', v: w, lv: lw });
        i = j;
        continue;
      }
      i++;
    }
    return tokens;
  }

  function Parser(tokens) {
    this.t = tokens;
    this.i = 0;
  }
  Parser.prototype.peek = function () { return this.t[this.i]; };
  Parser.prototype.next = function () { return this.t[this.i++]; };
  Parser.prototype.atEnd = function () { return this.i >= this.t.length; };
  Parser.prototype.expectParen = function (open) {
    const p = this.peek();
    if (!p || p.type !== 'paren' || p.v !== open) {
      throw new Error('缺少 ' + (open === '(' ? '左括号' : '右括号'));
    }
    this.i++;
  };
  Parser.prototype.parse = function () {
    const ast = this.parseOr();
    if (!this.atEnd()) throw new Error('多余的表达式片段: "' + this.peek().v + '"');
    return ast;
  };
  Parser.prototype.parseOr = function () {
    let left = this.parseAnd();
    while (this.peek() && this.peek().type === 'kw' && this.peek().v === 'or') {
      this.next();
      const right = this.parseAnd();
      left = { op: 'or', l: left, r: right };
    }
    return left;
  };
  Parser.prototype.parseAnd = function () {
    let left = this.parseUnary();
    while (this.peek() && this.peek().type === 'kw' && this.peek().v === 'and') {
      this.next();
      const right = this.parseUnary();
      left = { op: 'and', l: left, r: right };
    }
    return left;
  };
  Parser.prototype.parseUnary = function () {
    const p = this.peek();
    if (p && p.type === 'kw' && p.v === 'not') {
      this.next();
      return { op: 'not', e: this.parseUnary() };
    }
    return this.parsePrimary();
  };
  Parser.prototype.parsePrimary = function () {
    const p = this.peek();
    if (!p) throw new Error('过滤器表达式为空');
    if (p.type === 'paren' && p.v === '(') {
      this.next();
      const e = this.parseOr();
      this.expectParen(')');
      return e;
    }
    if (p.type === 'word') {
      this.next();
      const opTok = this.peek();
      if (opTok && opTok.type === 'op') {
        this.next();
        const v = this.peek();
        if (!v || (v.type !== 'value' && v.type !== 'word')) {
          throw new Error('比较运算符 "' + opTok.v + '" 后缺少值');
        }
        this.next();
        return { op: 'cmp', field: p.lv, cmp: opTok.v, value: v.v };
      }
      return { op: 'proto', name: p.lv };
    }
    if (p.type === 'value') {
      this.next();
      throw new Error('意外的值 "' + p.v + '"');
    }
    throw new Error('无法识别的符号 "' + p.v + '"');
  };

  const PROTO_PREDICATES = {
    tcp: function (p) { return p.tproto === 'tcp'; },
    udp: function (p) { return p.tproto === 'udp'; },
    icmp: function (p) { return p.proto === 'icmp'; },
    icmpv6: function (p) { return p.proto === 'icmpv6'; },
    dns: function (p) { return p.proto === 'dns'; },
    http: function (p) { return p.proto === 'http'; },
    dhcp: function (p) { return p.proto === 'dhcp'; },
    tls: function (p) { return p.proto === 'tls'; },
    ssl: function (p) { return p.proto === 'tls'; },
    arp: function (p) { return p.proto === 'arp'; },
    bgp: function (p) { return p.proto === 'bgp'; },
    ospf: function (p) { return p.proto === 'ospf'; },
    tacacs: function (p) { return p.proto === 'tacacs'; },
    igmp: function (p) { return p.proto === 'igmp'; },
    sctp: function (p) { return p.tproto === 'sctp'; },
    esp: function (p) { return p.proto === 'esp'; },
    ah: function (p) { return p.proto === 'ah'; },
    vrrp: function (p) { return p.proto === 'vrrp'; },
    eigrp: function (p) { return p.proto === 'eigrp'; },
    gre: function (p) { return p.tunnel === 'gre'; },
    vxlan: function (p) { return p.tunnel === 'vxlan'; },
    pptp: function (p) { return p.proto === 'pptp'; },
    stp: function (p) { return p.proto === 'stp'; },
    lldp: function (p) { return p.proto === 'lldp'; },
    cdp: function (p) { return p.proto === 'cdp'; },
    radius: function (p) { return p.proto === 'radius'; },
    ntp: function (p) { return p.proto === 'ntp'; },
    tftp: function (p) { return p.proto === 'tftp'; },
    ssh: function (p) { return p.proto === 'ssh'; },
    ftp: function (p) { return p.proto === 'ftp'; },
    telnet: function (p) { return p.proto === 'telnet'; },
    smtp: function (p) { return p.proto === 'smtp'; },
    pop3: function (p) { return p.proto === 'pop3'; },
    imap: function (p) { return p.proto === 'imap'; },
    sip: function (p) { return p.proto === 'sip'; },
    lacp: function (p) { return p.proto === 'lacp'; },
    eapol: function (p) { return p.proto === 'eapol'; },
    eap: function (p) { return p.proto === 'eap'; },
    hsrp: function (p) { return p.proto === 'hsrp'; },
    bfd: function (p) { return p.proto === 'bfd'; },
    ib: function (p) { return p.proto === 'ib'; },
    'infini-band': function (p) { return p.proto === 'ib'; },
    wlan: function (p) { return p.l2 === 'wlan'; },
    '802.11': function (p) { return p.l2 === 'wlan'; },
    llc: function (p) { return p.proto === 'llc'; },
    ppp: function (p) { return p.l2 === 'ppp'; },
    mpls: function (p) { return p.tunnel === 'mpls' || p.proto === 'mpls'; },
    ip: function (p) { return p.l3 === 'ipv4' || p.l3 === 'ipv6'; },
    ipv4: function (p) { return p.l3 === 'ipv4'; },
    ipv6: function (p) { return p.l3 === 'ipv6'; },
    frame: function () { return true; },
    eth: function (p) { return !!p.macSrc; },
    ethernet: function (p) { return !!p.macSrc; }
  };

  function numValue(v, field) {
    const n = parseInt(v, 10);
    if (isNaN(n)) throw new Error('字段 ' + field + ' 需要数值，收到 "' + v + '"');
    return n;
  }

  function buildCmp(ast) {
    const field = ast.field;
    const value = ast.value;
    const eq = ast.cmp === '==';
    const val = value;
    let fn;
    if (field === 'ip.addr' || field === 'ip.src' || field === 'ip.dst' ||
        field === 'ipv6.addr' || field === 'ipv6.src' || field === 'ipv6.dst' ||
        field === 'eth.addr' || field === 'eth.src' || field === 'eth.dst') {
      const wantSrc = field.indexOf('.src') >= 0;
      const wantDst = field.indexOf('.dst') >= 0;
      const isMac = field.indexOf('eth.') === 0;
      if (isMac) {
        fn = function (p) {
          if (wantSrc) return p.macSrc === val;
          if (wantDst) return p.macDst === val;
          return p.macSrc === val || p.macDst === val;
        };
      } else {
        fn = function (p) {
          if (wantSrc) return p.src === val;
          if (wantDst) return p.dst === val;
          return p.src === val || p.dst === val;
        };
      }
    } else if (field === 'tcp.port' || field === 'udp.port') {
      const wantTcp = field === 'tcp.port';
      const n = numValue(val, field);
      fn = function (p) {
        if (wantTcp ? p.tproto !== 'tcp' : p.tproto !== 'udp') return false;
        return p.sport === n || p.dport === n;
      };
    } else if (field === 'tcp.srcport' || field === 'tcp.dstport' || field === 'udp.srcport' || field === 'udp.dstport') {
      const wantTcp = field.indexOf('tcp.') === 0;
      const wantSrc = field.indexOf('.srcport') >= 0;
      const n = numValue(val, field);
      fn = function (p) {
        if (wantTcp ? p.tproto !== 'tcp' : p.tproto !== 'udp') return false;
        return wantSrc ? p.sport === n : p.dport === n;
      };
    } else if (field === 'frame.number' || field === 'frame.len' || field === 'frame.cap_len') {
      const n = numValue(val, field);
      fn = function (p) {
        const actual = field === 'frame.number' ? p.num : field === 'frame.len' ? p.len : p.capLen;
        return actual === n;
      };
    } else {
      throw new Error('不支持的过滤器字段: "' + field + '"');
    }
    if (eq) return fn;
    return function (p) { return !fn(p); };
  }

  function compileAST(ast) {
    switch (ast.op) {
      case 'and': {
        const l = compileAST(ast.l), r = compileAST(ast.r);
        return function (p) { return l(p) && r(p); };
      }
      case 'or': {
        const l = compileAST(ast.l), r = compileAST(ast.r);
        return function (p) { return l(p) || r(p); };
      }
      case 'not': {
        const e = compileAST(ast.e);
        return function (p) { return !e(p); };
      }
      case 'cmp': return buildCmp(ast);
      case 'proto': {
        const pred = PROTO_PREDICATES[ast.name];
        if (!pred) throw new Error('不支持的协议名: "' + ast.name + '"');
        return pred;
      }
      default: throw new Error('未知过滤器节点');
    }
  }

  WWL.Filter = {
    parse: function (text) {
      const trimmed = String(text || '').trim();
      if (!trimmed) return null;
      const tokens = tokenize(trimmed);
      if (!tokens.length) return null;
      const parser = new Parser(tokens);
      return parser.parse();
    },
    compile: function (text) {
      const ast = WWL.Filter.parse(text);
      if (!ast) return null;
      return {
        ast: ast,
        match: compileAST(ast)
      };
    }
  };
})(typeof window !== 'undefined' ? window : globalThis);
