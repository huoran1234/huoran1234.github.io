/* charts.js - 纯 Canvas 图表（柱状图 / 堆叠面积图）与力导向通信拓扑 */
(function (global) {
  'use strict';
  const WWL = global.WWL = global.WWL || {};

  const PALETTE = ['#1465c0', '#137a3c', '#9a5b00', '#6d28d9', '#0f766e', '#c2255c', '#495057', '#e8590c', '#2b8a3e', '#4263eb'];

  function setupCanvas(canvas) {
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    const w = Math.max(80, rect.width || 600);
    const h = Math.max(80, rect.height || 220);
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    return { ctx: ctx, w: w, h: h };
  }

  function niceMax(v) {
    if (v <= 0) return 1;
    const exp = Math.floor(Math.log10(v));
    const base = Math.pow(10, exp);
    const frac = v / base;
    let nice = 1;
    if (frac <= 1) nice = 1;
    else if (frac <= 2) nice = 2;
    else if (frac <= 5) nice = 5;
    else nice = 10;
    return nice * base;
  }

  function fmtShort(v) {
    if (v >= 1e9) return (v / 1e9).toFixed(1) + 'G';
    if (v >= 1e6) return (v / 1e6).toFixed(1) + 'M';
    if (v >= 1e3) return (v / 1e3).toFixed(1) + 'k';
    return String(Math.round(v));
  }

  function drawGrid(ctx, w, h, m, maxV, fmtY) {
    const iw = w - m.left - m.right, ih = h - m.top - m.bottom;
    ctx.strokeStyle = '#e5e9ee';
    ctx.fillStyle = '#5f6b7a';
    ctx.font = '10px sans-serif';
    for (let i = 0; i <= 4; i++) {
      const v = maxV * i / 4;
      const y = m.top + ih - ih * i / 4;
      ctx.beginPath();
      ctx.moveTo(m.left, y);
      ctx.lineTo(m.left + iw, y);
      ctx.stroke();
      ctx.textAlign = 'right';
      ctx.fillText(fmtY ? fmtY(v) : fmtShort(v), m.left - 4, y + 3);
    }
  }

  function tooltip(container, html, x, y) {
    let el = container.querySelector('.chart-tip');
    if (!el) {
      el = document.createElement('div');
      el.className = 'chart-tip';
      container.appendChild(el);
    }
    el.innerHTML = html;
    el.style.left = Math.min(x + 10, container.clientWidth - 140) + 'px';
    el.style.top = (y - 10) + 'px';
    el.style.display = 'block';
  }
  function hideTooltip(container) {
    const el = container.querySelector('.chart-tip');
    if (el) el.style.display = 'none';
  }

  WWL.Charts = {
    colors: PALETTE,

    /* 柱状图 */
    bar: function (canvas, data, opts) {
      opts = opts || {};
      const { ctx, w, h } = setupCanvas(canvas);
      const m = { top: 12, right: 12, bottom: 26, left: 50 };
      const iw = w - m.left - m.right, ih = h - m.top - m.bottom;
      ctx.clearRect(0, 0, w, h);
      const maxV = niceMax(Math.max(1, data.reduce(function (s, d) { return Math.max(s, d.value); }, 0)));
      drawGrid(ctx, w, h, m, maxV);
      const bw = iw / Math.max(1, data.length);
      data.forEach(function (d, i) {
        const bh = Math.max(1, ih * d.value / maxV);
        const x = m.left + i * bw + bw * 0.18;
        ctx.fillStyle = d.color || PALETTE[i % PALETTE.length];
        ctx.fillRect(x, m.top + ih - bh, bw * 0.64, bh);
        ctx.fillStyle = '#20262e';
        ctx.font = '9px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(String(d.label), m.left + i * bw + bw / 2, h - 8);
      });
      if (opts.seriesName && data.length) {
        ctx.fillStyle = '#5f6b7a';
        ctx.font = '10px sans-serif';
        ctx.textAlign = 'left';
        ctx.fillText(opts.seriesName, m.left, m.top - 2);
      }
    },

    /* 按协议堆叠的面积图（吞吐量） */
    stacked: function (canvas, series, labels, opts) {
      opts = opts || {};
      const { ctx, w, h } = setupCanvas(canvas);
      const m = { top: 16, right: 12, bottom: 26, left: 54 };
      const iw = w - m.left - m.right, ih = h - m.top - m.bottom;
      const n = labels.length;
      if (!n) return;
      ctx.clearRect(0, 0, w, h);
      const totals = [];
      for (let i = 0; i < n; i++) {
        let s = 0;
        for (let si = 0; si < series.length; si++) s += series[si].values[i] || 0;
        totals.push(s);
      }
      const maxV = niceMax(Math.max(1, totals.reduce(function (a, b) { return Math.max(a, b); }, 0)));
      drawGrid(ctx, w, h, m, maxV, function (v) { return WWL.formatBytes(v); });
      const step = n > 1 ? iw / (n - 1) : 0;
      const tops = [];
      series.forEach(function (se) {
        const arr = [];
        let acc = 0;
        for (let i = 0; i < n; i++) { acc += se.values[i] || 0; arr.push(acc); }
        tops.push(arr);
      });
      const zeros = new Array(n).fill(0);
      for (let si = series.length - 1; si >= 0; si--) {
        const prev = si > 0 ? tops[si - 1] : zeros;
        ctx.beginPath();
        for (let i = 0; i < n; i++) {
          const x = m.left + i * step;
          const y = m.top + ih - ih * tops[si][i] / maxV;
          if (i === 0) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        }
        for (let i = n - 1; i >= 0; i--) {
          const x = m.left + i * step;
          const y = m.top + ih - ih * prev[i] / maxV;
          ctx.lineTo(x, y);
        }
        ctx.closePath();
        ctx.fillStyle = series[si].color;
        ctx.globalAlpha = 0.85;
        ctx.fill();
        ctx.globalAlpha = 1;
      }
      // x 轴时间标签（取若干刻度）
      ctx.fillStyle = '#5f6b7a';
      ctx.font = '9px sans-serif';
      ctx.textAlign = 'center';
      const tickCount = Math.min(8, n);
      for (let i = 0; i < tickCount; i++) {
        const idx = Math.round(i * (n - 1) / (tickCount - 1));
        ctx.fillText(labels[idx], m.left + idx * step, h - 8);
      }
      // hover 提示
      const container = canvas.parentElement;
      if (!container) return;
      canvas.onmousemove = function (e) {
        const rect = canvas.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const idx = Math.round((x - m.left) / (step || 1));
        if (idx < 0 || idx >= n) { hideTooltip(container); return; }
        const rows = series.map(function (se, si) {
          return '<span style="color:' + se.color + '">■</span> ' + se.name + ': ' + WWL.formatBytes(se.values[idx] || 0);
        }).join('<br>');
        tooltip(container, '<b>' + labels[idx] + '</b><br>' + rows + '<br>合计: ' + WWL.formatBytes(totals[idx]), e.clientX - rect.left, e.clientY - rect.top);
      };
      canvas.onmouseleave = function () { hideTooltip(container); };
    }
  };

  /* ---------------- 通信拓扑（力导向） ---------------- */
  function isPrivate(ip) {
    if (WWL.isIPv6Str(ip)) {
      const l = ip.toLowerCase();
      return l.indexOf('fe80:') === 0 || l.indexOf('fc') === 0 || l.indexOf('fd') === 0 || l.indexOf('::1') === 0;
    }
    const p = ip.split('.');
    if (p.length !== 4) return false;
    const a = parseInt(p[0], 10), b = parseInt(p[1], 10);
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || a === 0;
  }

  function isNoise(ip) {
    if (!ip) return true;
    if (WWL.isIPv6Str(ip)) {
      const l = ip.toLowerCase();
      return l === '::' || l.indexOf('ff0') === 0;
    }
    if (ip === '0.0.0.0' || ip === '255.255.255.255') return true;
    const a = parseInt(ip.split('.')[0], 10);
    return a >= 224; // 组播/保留
  }
  WWL.Topo = function (canvas, callbacks) {
    this.canvas = canvas;
    this.cb = callbacks || {};
    this.nodes = [];
    this.edges = [];
    this.running = false;
    this.tick = 0;
    this.drag = null;
    this.dragMoved = false;
    this.lastClick = 0;
    this.labelMode = 'all';

    const self = this;
    canvas.addEventListener('mousedown', function (e) {
      const pos = self.mousePos(e);
      const node = self.hitTest(pos.x, pos.y);
      self.dragMoved = false;
      if (node) {
        self.drag = { node: node, ox: pos.x - node.x, oy: pos.y - node.y };
        node.pinned = true;
        self.start();
      } else {
        self.drag = { empty: true, x0: pos.x, y0: pos.y };
      }
    });
    canvas.addEventListener('mousemove', function (e) {
      if (!self.drag) return;
      const pos = self.mousePos(e);
      if (self.drag.node) {
        self.drag.node.x = pos.x - self.drag.ox;
        self.drag.node.y = pos.y - self.drag.oy;
        self.dragMoved = true;
      } else {
        const dx = pos.x - self.drag.x0, dy = pos.y - self.drag.y0;
        if (Math.abs(dx) + Math.abs(dy) > 4) self.dragMoved = true;
      }
    });
    window.addEventListener('mouseup', function (e) {
      if (!self.drag) return;
      const wasDrag = self.dragMoved;
      const node = self.drag.node;
      const empty = self.drag.empty;
      self.drag = null;
      if (node && !wasDrag) {
        const now = Date.now();
        if (now - self.lastClick < 350) {
          node.pinned = false; // 双击节点：取消固定
          self.lastClick = 0;
        } else {
          self.lastClick = now;
          if (self.cb.onNodeClick) self.cb.onNodeClick(node);
        }
      }
      if (empty && !wasDrag) {
        self.seed(); // 双击空白：重新布局
        self.start();
      }
      self.start();
    });
  };

  /* 从数据包聚合拓扑数据（按流量字节数取前 maxNodes 个主机） */
  WWL.Topo.compute = function (packets, maxNodes) {
    const limit = maxNodes || 80;
    const nodeMap = new Map();
    const edgeMap = new Map();
    for (let i = 0; i < packets.length; i++) {
      const p = packets[i];
      if (!p.src || !p.dst || (p.l3 !== 'ipv4' && p.l3 !== 'ipv6')) continue;
      const a = p.src, b = p.dst;
      if (isNoise(a) || isNoise(b)) continue;
      let na = nodeMap.get(a), nb = nodeMap.get(b);
      if (!na) { na = { id: a, bytes: 0, count: 0 }; nodeMap.set(a, na); }
      if (!nb) { nb = { id: b, bytes: 0, count: 0 }; nodeMap.set(b, nb); }
      na.bytes += p.len; na.count++;
      nb.bytes += p.len; nb.count++;
      const key = a <= b ? a + '|' + b : b + '|' + a;
      let e = edgeMap.get(key);
      if (!e) { e = { a: a <= b ? a : b, b: a <= b ? b : a, bytes: 0, packets: 0 }; edgeMap.set(key, e); }
      e.bytes += p.len;
      e.packets++;
    }
    const nodes = Array.from(nodeMap.values()).sort(function (x, y) { return y.bytes - x.bytes; }).slice(0, limit);
    const ids = new Set(nodes.map(function (n) { return n.id; }));
    const edges = Array.from(edgeMap.values()).filter(function (e) { return ids.has(e.a) && ids.has(e.b); });
    if (nodes.length >= 2) return { nodes: nodes, edges: edges, mode: 'ip' };

    // IP 会话不足时，回退到按二层 MAC 地址聚合（覆盖 DHCP/广播类抓包）
    const macNoise = function (mac) {
      if (!mac || mac === '00:00:00:00:00:00') return true;
      return (parseInt(mac.split(':')[0], 16) & 0x01) === 1; // 组播/广播
    };
    const macNodes = new Map();
    const macEdges = new Map();
    for (let i = 0; i < packets.length; i++) {
      const p = packets[i];
      const a = p.macSrc, b = p.macDst;
      if (macNoise(a) || macNoise(b)) continue;
      let na = macNodes.get(a), nb = macNodes.get(b);
      if (!na) { na = { id: a, bytes: 0, count: 0 }; macNodes.set(a, na); }
      if (!nb) { nb = { id: b, bytes: 0, count: 0 }; macNodes.set(b, nb); }
      na.bytes += p.len; na.count++;
      nb.bytes += p.len; nb.count++;
      const key = a <= b ? a + '|' + b : b + '|' + a;
      let e = macEdges.get(key);
      if (!e) { e = { a: a <= b ? a : b, b: a <= b ? b : a, bytes: 0, packets: 0 }; macEdges.set(key, e); }
      e.bytes += p.len;
      e.packets++;
    }
    const mNodes = Array.from(macNodes.values()).sort(function (x, y) { return y.bytes - x.bytes; }).slice(0, limit);
    const mIds = new Set(mNodes.map(function (n) { return n.id; }));
    const mEdges = Array.from(macEdges.values()).filter(function (e) { return mIds.has(e.a) && mIds.has(e.b); });
    if (mNodes.length >= 2) return { nodes: mNodes, edges: mEdges, mode: 'mac' };
    return { nodes: [], edges: [], mode: 'none' };
  };

  WWL.Topo.prototype.mousePos = function (e) {
    const r = this.canvas.getBoundingClientRect();
    return { x: e.clientX - r.left, y: e.clientY - r.top };
  };

  WWL.Topo.prototype.hitTest = function (x, y) {
    for (let i = this.nodes.length - 1; i >= 0; i--) {
      const n = this.nodes[i];
      if ((x - n.x) * (x - n.x) + (y - n.y) * (y - n.y) <= (n.r + 3) * (n.r + 3)) return n;
    }
    return null;
  };

  WWL.Topo.prototype.setData = function (nodes, edges) {
    this.nodes = nodes.map(function (n) {
      return {
        id: n.id, name: n.name, bytes: n.bytes, count: n.count,
        internal: isPrivate(n.name),
        x: 0, y: 0, vx: 0, vy: 0,
        r: Math.max(5, Math.min(28, 4 + Math.log10(n.bytes + 1) * 4)),
        pinned: false
      };
    });
    this.edges = edges.map(function (e) {
      return {
        a: e.a, b: e.b, bytes: e.bytes,
        w: Math.max(1, Math.min(10, 1 + Math.log10(e.bytes + 1)))
      };
    });
    this.seed();
  };

  WWL.Topo.prototype.seed = function () {
    const n = this.nodes.length;
    const cx = this.width() / 2, cy = this.height() / 2;
    const R = Math.min(this.width(), this.height()) * 0.36;
    this.nodes.forEach(function (node, i) {
      if (node.pinned) return;
      const ang = (i / Math.max(1, n)) * Math.PI * 2 + Math.random() * 0.4;
      node.x = cx + Math.cos(ang) * R * (0.6 + Math.random() * 0.5);
      node.y = cy + Math.sin(ang) * R * (0.6 + Math.random() * 0.5);
      node.vx = 0; node.vy = 0;
    });
  };

  WWL.Topo.prototype.width = function () { return this.canvas.clientWidth || 800; };
  WWL.Topo.prototype.height = function () { return this.canvas.clientHeight || 560; };

  WWL.Topo.prototype.step = function () {
    const nodes = this.nodes, edges = this.edges;
    const n = nodes.length;
    const k = Math.max(40, Math.sqrt((this.width() * this.height()) / Math.max(1, n)) * 1.2);
    for (let i = 0; i < n; i++) {
      const a = nodes[i];
      for (let j = i + 1; j < n; j++) {
        const b = nodes[j];
        let dx = a.x - b.x, dy = a.y - b.y;
        let d2 = dx * dx + dy * dy;
        if (d2 < 0.01) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 0.01; }
        const d = Math.sqrt(d2);
        const f = k * k / d2;
        const fx = dx / d * f, fy = dy / d * f;
        a.vx += fx; a.vy += fy;
        b.vx -= fx; b.vy -= fy;
      }
    }
    const cx = this.width() / 2, cy = this.height() / 2;
    for (const a of nodes) {
      if (a.pinned) continue;
      a.vx += (cx - a.x) * 0.008;
      a.vy += (cy - a.y) * 0.008;
      a.vx *= 0.86; a.vy *= 0.86;
      a.x += a.vx; a.y += a.vy;
      a.x = Math.max(16, Math.min(this.width() - 16, a.x));
      a.y = Math.max(16, Math.min(this.height() - 16, a.y));
    }
    for (const e of edges) {
      const na = this.byId(e.a), nb = this.byId(e.b);
      if (!na || !nb) continue;
      const dx = nb.x - na.x, dy = nb.y - na.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 1;
      const f = d * 0.012;
      const fx = dx / d * f, fy = dy / d * f;
      if (!na.pinned) { na.vx += fx; na.vy += fy; }
      if (!nb.pinned) { nb.vx -= fx; nb.vy -= fy; }
    }
  };

  WWL.Topo.prototype.byId = function (id) {
    for (let i = 0; i < this.nodes.length; i++) if (this.nodes[i].id === id) return this.nodes[i];
    return null;
  };

  WWL.Topo.prototype.draw = function () {
    const { ctx, w, h } = setupCanvas(this.canvas);
    ctx.clearRect(0, 0, w, h);
    // 边
    for (const e of this.edges) {
      const a = this.byId(e.a), b = this.byId(e.b);
      if (!a || !b) continue;
      ctx.strokeStyle = 'rgba(70, 110, 160, 0.45)';
      ctx.lineWidth = e.w;
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      ctx.stroke();
    }
    // 节点
    const major = this.nodes.slice().sort(function (x, y) { return y.bytes - x.bytes; }).slice(0, 20);
    for (const node of this.nodes) {
      ctx.beginPath();
      ctx.arc(node.x, node.y, node.r, 0, Math.PI * 2);
      ctx.fillStyle = node.internal ? '#1465c0' : '#e8590c';
      ctx.globalAlpha = 0.25;
      ctx.fill();
      ctx.globalAlpha = 1;
      ctx.strokeStyle = node.internal ? '#1465c0' : '#e8590c';
      ctx.lineWidth = 1.5;
      ctx.stroke();
      if (node.pinned) {
        ctx.strokeStyle = '#2f9e44';
        ctx.lineWidth = 2;
        ctx.stroke();
      }
      const show = this.labelMode === 'all' || (this.labelMode === 'major' && major.indexOf(node) >= 0);
      if (show) {
        ctx.fillStyle = '#20262e';
        ctx.font = '10px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(node.name, node.x, node.y - node.r - 4);
      }
    }
    ctx.fillStyle = '#8a94a0';
    ctx.font = '10px sans-serif';
    ctx.textAlign = 'left';
    ctx.fillText('节点大小 = 流量，连线粗细 = 字节数', 8, this.height() - 8);
  };

  WWL.Topo.prototype.start = function () {
    if (this.running) return;
    this.running = true;
    this.tick = 0;
    const self = this;
    const loop = function () {
      if (!self.running) return;
      for (let i = 0; i < 3; i++) self.step();
      self.draw();
      self.tick++;
      if (self.tick < 500 || self.drag) requestAnimationFrame(loop);
      else self.running = false;
    };
    requestAnimationFrame(loop);
  };

  WWL.Topo.prototype.relayout = function () {
    this.nodes.forEach(function (node) { node.pinned = false; });
    this.seed();
    this.start();
  };

  WWL.Topo.isPrivate = isPrivate;
})(typeof window !== 'undefined' ? window : globalThis);
