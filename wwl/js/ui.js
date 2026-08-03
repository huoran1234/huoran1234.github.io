/* ui.js - DOM 渲染：详情树、Hex 视图、统计、会话、状态栏 */
(function (global) {
  'use strict';
  const WWL = global.WWL = global.WWL || {};

  const ui = {
    els: {},
    state: {
      hexByteEls: [],
      hexRowEls: [],
      hexBytesLen: 0,
      hexBase: 0,
      detailRowEls: [],
      onRangeSelect: null
    }
  };

  ui.init = function () {
    const ids = [
      'btn-open', 'file-input', 'btn-sample', 'btn-stop', 'file-info',
      'progress-wrap', 'progress-fill', 'progress-text',
      'filter-input', 'filter-count', 'filter-error', 'search-input',
      'pkt-header', 'pkt-body', 'empty-hint', 'pager',
      'page-size', 'btn-prev', 'btn-next', 'page-info',
      'details', 'hexdump', 'stats-content', 'streams-content',
      'traffic-content', 'hierarchy-content', 'topo-content',
      'status-packets', 'status-parse', 'status-file', 'drop-overlay'
    ];
    ids.forEach(function (id) { ui.els[id] = document.getElementById(id); });

    // 详情树点击 -> 高亮字节
    ui.els.details.addEventListener('click', function (e) {
      const row = e.target.closest('.drow');
      if (!row) return;
      ui.state.detailRowEls.forEach(function (el) { if (el) el.classList.remove('selected'); });
      row.classList.add('selected');
      if (row.dataset.range && ui.state.onRangeSelect) {
        ui.state.onRangeSelect(parseInt(row.dataset.start, 10), parseInt(row.dataset.end, 10));
      }
    });

    // Tab 切换
    document.querySelectorAll('.tab').forEach(function (btn) {
      btn.addEventListener('click', function () {
        document.querySelectorAll('.tab').forEach(function (b) { b.classList.remove('active'); });
        document.querySelectorAll('.tab-panel').forEach(function (p) { p.classList.remove('active'); });
        btn.classList.add('active');
        document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
        if (ui.onTab) ui.onTab(btn.dataset.tab);
      });
    });

    // 列宽拖拽
    setupColResize();
  };

  function setupColResize() {
    const wrap = document.querySelector('.packet-list-wrap');
    if (!wrap) return;
    const varMap = {
      num: '--cw-no', time: '--cw-time', src: '--cw-src', sport: '--cw-sport',
      dst: '--cw-dst', dport: '--cw-dport', proto: '--cw-proto', len: '--cw-len'
    };
    const widths = { num: 60, time: 104, src: 128, sport: 60, dst: 128, dport: 60, proto: 78, len: 56 };
    Object.keys(varMap).forEach(function (key) {
      wrap.style.setProperty(varMap[key], widths[key] + 'px');
    });
    ui.els['pkt-header'].querySelectorAll('.col').forEach(function (col) {
      const key = col.dataset.sort;
      if (!varMap[key]) return;
      const handle = document.createElement('span');
      handle.className = 'col-resize';
      handle.title = '拖动调整列宽';
      col.appendChild(handle);
      handle.addEventListener('mousedown', function (e) {
        e.preventDefault();
        e.stopPropagation();
        const startX = e.clientX;
        const startW = widths[key];
        const move = function (ev) {
          const w = Math.max(32, Math.min(700, startW + ev.clientX - startX));
          widths[key] = w;
          wrap.style.setProperty(varMap[key], w + 'px');
        };
        const up = function () {
          document.removeEventListener('mousemove', move);
          document.removeEventListener('mouseup', up);
          document.body.classList.remove('col-resizing');
        };
        document.body.classList.add('col-resizing');
        document.addEventListener('mousemove', move);
        document.addEventListener('mouseup', up);
      });
    });
  }

  ui.setRangeHandler = function (fn) { ui.state.onRangeSelect = fn; };

  ui.setFileInfo = function (text) { ui.els['file-info'].textContent = text; };

  ui.showProgress = function (show) {
    ui.els['progress-wrap'].hidden = !show;
  };
  ui.setProgress = function (pct, text) {
    ui.els['progress-fill'].style.width = Math.max(0, Math.min(100, pct)) + '%';
    ui.els['progress-text'].textContent = text || '';
  };

  ui.setFilterCount = function (text) { ui.els['filter-count'].textContent = text || ''; };
  ui.setFilterError = function (err) {
    const el = ui.els['filter-error'];
    const input = ui.els['filter-input'];
    if (err) {
      el.textContent = '过滤器错误: ' + err;
      el.hidden = false;
      input.classList.add('invalid');
    } else {
      el.textContent = '';
      el.hidden = true;
      input.classList.remove('invalid');
    }
  };

  ui.setStatus = function (packetsText, parseText, fileText) {
    if (packetsText !== undefined) ui.els['status-packets'].textContent = packetsText;
    if (parseText !== undefined) ui.els['status-parse'].textContent = parseText;
    if (fileText !== undefined) ui.els['status-file'].textContent = fileText;
  };

  ui.showEmptyHint = function (text) {
    const el = ui.els['empty-hint'];
    if (text === null) el.hidden = true;
    else { el.textContent = text; el.hidden = false; }
  };

  ui.updatePager = function (info) {
    ui.els['pager'].hidden = info.hidden;
    ui.els['page-info'].textContent = info.text || '';
    ui.els['btn-prev'].disabled = info.page <= 1;
    ui.els['btn-next'].disabled = info.page >= info.pages;
  };

  /* ---------------- 详情树 ---------------- */
  function buildNode(n, depth) {
    const d = document.createElement('div');
    const hasKids = !!(n.children && n.children.length);
    const collapsed = hasKids && depth >= 2;
    d.className = 'dnode' + (collapsed ? ' collapsed' : '');
    const row = document.createElement('div');
    row.className = 'drow';
    const tg = document.createElement('span');
    tg.className = 'dtoggle';
    tg.textContent = hasKids ? (collapsed ? '▸' : '▾') : ' ';
    row.appendChild(tg);
    const name = document.createElement('span');
    name.className = 'dname';
    name.textContent = n.name;
    row.appendChild(name);
    if (n.value) {
      const sep = document.createElement('span');
      sep.className = 'dsep';
      sep.textContent = ':';
      const val = document.createElement('span');
      val.className = 'dval';
      val.textContent = n.value;
      row.appendChild(sep);
      row.appendChild(val);
    }
    d.appendChild(row);
    if (n.range) {
      row.dataset.range = '1';
      row.dataset.start = n.range[0];
      row.dataset.end = n.range[1];
    }
    if (hasKids) {
      const kids = document.createElement('div');
      kids.className = 'dchildren';
      for (let i = 0; i < n.children.length; i++) kids.appendChild(buildNode(n.children[i], depth + 1));
      d.appendChild(kids);
      row.addEventListener('click', function () {
        d.classList.toggle('collapsed');
        tg.textContent = d.classList.contains('collapsed') ? '▸' : '▾';
      });
    }
    return d;
  }

  ui.renderDetails = function (nodes) {
    const c = ui.els.details;
    c.innerHTML = '';
    ui.state.detailRowEls = [];
    const frag = document.createDocumentFragment();
    const walk = function (el, rows) {
      const row = el.querySelector(':scope > .drow');
      if (row) { rows.push(row); ui.state.detailRowEls.push(row); }
      const kids = el.querySelector(':scope > .dchildren');
      if (kids) {
        for (let i = 0; i < kids.children.length; i++) walk(kids.children[i], rows);
      }
    };
    for (let i = 0; i < nodes.length; i++) {
      const el = buildNode(nodes[i], 0);
      frag.appendChild(el);
      walk(el, []);
    }
    c.appendChild(frag);
    c.scrollTop = 0; // 切换数据包时回到开头
  };

  /* ---------------- Hex 视图 ---------------- */
  ui.renderHex = function (bytes, baseOffset) {
    const c = ui.els.hexdump;
    c.innerHTML = '';
    ui.state.hexByteEls = [];
    ui.state.hexRowEls = [];
    ui.state.hexBytesLen = bytes.length;
    ui.state.hexBase = baseOffset || 0;
    const frag = document.createDocumentFragment();
    const n = bytes.length;
    for (let rowOff = 0; rowOff < n; rowOff += 16) {
      const row = document.createElement('div');
      row.className = 'hex-row';
      const off = document.createElement('span');
      off.className = 'hex-off';
      off.textContent = WWL.pad((ui.state.hexBase + rowOff).toString(16).toUpperCase(), 4);
      const hex = document.createElement('span');
      hex.className = 'hex-bytes';
      const ascii = document.createElement('span');
      ascii.className = 'hex-ascii';
      for (let j = 0; j < 16 && rowOff + j < n; j++) {
        const b = bytes[rowOff + j];
        const hb = document.createElement('b');
        hb.textContent = WWL.u8hex(b);
        const ab = document.createElement('b');
        ab.textContent = (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
        ui.state.hexByteEls[rowOff + j] = { hex: hb, ascii: ab };
        hex.appendChild(hb);
        hex.appendChild(document.createTextNode(' '));
        ascii.appendChild(ab);
        if ((j + 1) % 8 === 0 && j < 15) hex.appendChild(document.createTextNode(' '));
      }
      row.appendChild(off);
      row.appendChild(hex);
      row.appendChild(ascii);
      ui.state.hexRowEls.push(row);
      frag.appendChild(row);
    }
    c.appendChild(frag);
  };

  ui.highlightRange = function (start, end) {
    // 清除旧的
    for (let i = 0; i < ui.state.hexByteEls.length; i++) {
      const e = ui.state.hexByteEls[i];
      if (e) { e.hex.classList.remove('hl'); e.ascii.classList.remove('hl'); }
    }
    if (!isFinite(start) || !isFinite(end)) return;
    const s = Math.max(0, start | 0);
    const e2 = Math.min(ui.state.hexBytesLen, end | 0);
    for (let i = s; i < e2; i++) {
      const el = ui.state.hexByteEls[i];
      if (el) { el.hex.classList.add('hl'); el.ascii.classList.add('hl'); }
    }
    const rowIdx = Math.floor(s / 16);
    const row = ui.state.hexRowEls[rowIdx];
    if (row) {
      const container = ui.els.hexdump;
      // 用 getBoundingClientRect 计算滚动位置，避免 offsetParent 不一致导致定位错误
      const rowTop = row.getBoundingClientRect().top - container.getBoundingClientRect().top + container.scrollTop;
      container.scrollTop = Math.max(0, rowTop - container.clientHeight / 2);
    }
  };

  ui.showDetailsHint = function (text) {
    ui.els.details.innerHTML = '<div class="empty-hint">' + WWL.escapeHtml(text || '选择一个数据包查看协议树') + '</div>';
    ui.state.detailRowEls = [];
  };

  ui.showHexHint = function () {
    ui.els.hexdump.textContent = '';
    ui.state.hexByteEls = [];
    ui.state.hexRowEls = [];
  };

  /* ---------------- 统计 ---------------- */
  function barCell(ratio, maxWidthPct) {
    const wrap = document.createElement('div');
    wrap.className = 'bar-cell';
    const bar = document.createElement('div');
    bar.className = 'bar';
    const fill = document.createElement('div');
    fill.style.width = Math.max(1, Math.min(100, ratio * 100)) + '%';
    bar.appendChild(fill);
    wrap.appendChild(bar);
    return wrap;
  }

  function card(title) {
    const el = document.createElement('div');
    el.className = 'stat-card';
    const h = document.createElement('h3');
    h.textContent = title;
    el.appendChild(h);
    return el;
  }

  function kvRow(k, v) {
    const kk = document.createElement('span');
    kk.className = 'k';
    kk.textContent = k;
    const vv = document.createElement('span');
    vv.className = 'v';
    vv.textContent = v;
    return [kk, vv];
  }

  ui.renderStats = function (s) {
    const c = ui.els['stats-content'];
    c.innerHTML = '';
    const grid = document.createElement('div');
    grid.className = 'stats-grid';

    // 流量统计
    const traffic = card('流量统计');
    const kv = document.createElement('div');
    kv.className = 'kv-grid';
    [['Total Packets', String(s.total)],
     ['Total Bytes', WWL.formatBytes(s.totalBytes) + ' (' + s.totalBytes + ')'],
     ['Average Packet Size', s.avgSize.toFixed(1) + ' bytes'],
     ['Start Time', WWL.formatTime(s.startT)],
     ['End Time', WWL.formatTime(s.endT)],
     ['Duration', WWL.formatDuration(s.duration)],
     ['Packets / Second', s.pps.toFixed(1)]].forEach(function (r) {
      const [k, v] = kvRow(r[0], r[1]);
      kv.appendChild(k);
      kv.appendChild(v);
    });
    traffic.appendChild(kv);
    grid.appendChild(traffic);

    // 协议统计
    const proto = card('协议统计 (Protocol | Count | Percentage)');
    const pt = document.createElement('table');
    pt.innerHTML = '<thead><tr><th>Protocol</th><th style="text-align:right">Count</th><th style="text-align:right">Percentage</th><th></th></tr></thead>';
    const pb = document.createElement('tbody');
    const maxCount = s.protocols.length ? s.protocols[0].count : 1;
    s.protocols.forEach(function (p) {
      const tr = document.createElement('tr');
      const td1 = document.createElement('td');
      td1.textContent = p.name;
      const td2 = document.createElement('td');
      td2.className = 'num';
      td2.textContent = p.count;
      const td3 = document.createElement('td');
      td3.className = 'num';
      td3.textContent = p.pct.toFixed(1) + '%';
      const td4 = document.createElement('td');
      td4.appendChild(barCell(p.count / maxCount));
      tr.appendChild(td1); tr.appendChild(td2); tr.appendChild(td3); tr.appendChild(td4);
      pb.appendChild(tr);
    });
    pt.appendChild(pb);
    proto.appendChild(pt);
    grid.appendChild(proto);

    // Top Talkers
    const talkers = document.createElement('div');
    talkers.className = 'two-col';
    talkers.appendChild(talkerCard('Top Talkers - Source IP', s.topSrc));
    talkers.appendChild(talkerCard('Top Talkers - Destination IP', s.topDst));
    grid.appendChild(talkers);

    // Top Ports
    const ports = document.createElement('div');
    ports.className = 'two-col';
    ports.appendChild(portCard('Top TCP Ports', s.topTcp));
    ports.appendChild(portCard('Top UDP Ports', s.topUdp));
    grid.appendChild(ports);

    c.appendChild(grid);
  };

  function talkerCard(title, list) {
    const el = card(title);
    const t = document.createElement('table');
    t.innerHTML = '<thead><tr><th>Address</th><th style="text-align:right">Packets</th><th style="text-align:right">Bytes</th><th></th></tr></thead>';
    const tb = document.createElement('tbody');
    const max = list.length ? list[0].count : 1;
    list.forEach(function (x) {
      const tr = document.createElement('tr');
      const td1 = document.createElement('td');
      td1.textContent = x.key;
      const td2 = document.createElement('td');
      td2.className = 'num';
      td2.textContent = x.count;
      const td3 = document.createElement('td');
      td3.className = 'num';
      td3.textContent = x.bytes;
      const td4 = document.createElement('td');
      td4.appendChild(barCell(x.count / max));
      tr.appendChild(td1); tr.appendChild(td2); tr.appendChild(td3); tr.appendChild(td4);
      tb.appendChild(tr);
    });
    t.appendChild(tb);
    el.appendChild(t);
    return el;
  }

  function portCard(title, list) {
    const el = card(title);
    const t = document.createElement('table');
    t.innerHTML = '<thead><tr><th>Port</th><th style="text-align:right">Count</th><th>Service</th><th></th></tr></thead>';
    const tb = document.createElement('tbody');
    const max = list.length ? list[0].count : 1;
    list.forEach(function (x) {
      const tr = document.createElement('tr');
      const td1 = document.createElement('td');
      td1.textContent = x.port;
      const td2 = document.createElement('td');
      td2.className = 'num';
      td2.textContent = x.count;
      const td3 = document.createElement('td');
      td3.textContent = x.service || '';
      const td4 = document.createElement('td');
      td4.appendChild(barCell(x.count / max));
      tr.appendChild(td1); tr.appendChild(td2); tr.appendChild(td3); tr.appendChild(td4);
      tb.appendChild(tr);
    });
    t.appendChild(tb);
    el.appendChild(t);
    return el;
  }

  /* ---------------- TCP 会话 ---------------- */
  ui.renderStreams = function (list, onFilter) {
    const c = ui.els['streams-content'];
    c.innerHTML = '';
    const wrap = document.createElement('div');
    wrap.className = 'streams-table-wrap';
    const h = document.createElement('h3');
    h.textContent = 'TCP 会话 (共 ' + list.length + ' 个，仅显示前 500)';
    wrap.appendChild(h);
    const t = document.createElement('table');
    t.className = 'streams-table';
    t.innerHTML = '<thead><tr>' +
      '<th>#</th><th>Endpoint A</th><th>Endpoint B</th>' +
      '<th style="text-align:right">Packets</th>' +
      '<th style="text-align:right">Bytes A→B</th><th style="text-align:right">Bytes B→A</th>' +
      '<th>First</th><th>Last</th><th></th></tr></thead>';
    const tb = document.createElement('tbody');
    list.slice(0, 500).forEach(function (s) {
      const tr = document.createElement('tr');
      const td1 = document.createElement('td'); td1.textContent = s.id;
      const td2 = document.createElement('td'); td2.textContent = s.a;
      const td3 = document.createElement('td'); td3.textContent = s.b;
      const td4 = document.createElement('td'); td4.style.textAlign = 'right'; td4.textContent = s.packets;
      const td5 = document.createElement('td'); td5.style.textAlign = 'right'; td5.textContent = s.bytesAB;
      const td6 = document.createElement('td'); td6.style.textAlign = 'right'; td6.textContent = s.bytesBA;
      const td7 = document.createElement('td'); td7.textContent = (s.first).toFixed(6);
      const td8 = document.createElement('td'); td8.textContent = (s.last).toFixed(6);
      const td9 = document.createElement('td');
      const btn = document.createElement('button');
      btn.className = 'btn-filter';
      btn.textContent = '过滤';
      btn.addEventListener('click', function () { onFilter(s); });
      td9.appendChild(btn);
      tr.appendChild(td1); tr.appendChild(td2); tr.appendChild(td3);
      tr.appendChild(td4); tr.appendChild(td5); tr.appendChild(td6);
      tr.appendChild(td7); tr.appendChild(td8); tr.appendChild(td9);
      tb.appendChild(tr);
    });
    t.appendChild(tb);
    wrap.appendChild(t);
    c.appendChild(wrap);
  };

  /* ---------------- 协议分层 ---------------- */
  ui.renderHierarchy = function (root) {
    const c = ui.els['hierarchy-content'];
    c.innerHTML = '';
    const wrap = document.createElement('div');
    wrap.className = 'hierarchy-card';
    const head = document.createElement('div');
    head.className = 'hierarchy-head';
    [['Protocol', ''], ['Packets', 'num'], ['Percent', 'num'], ['', '']].forEach(function (h) {
      const s = document.createElement('span');
      s.className = 'hier-cell ' + h[1];
      s.textContent = h[0];
      head.appendChild(s);
    });
    wrap.appendChild(head);
    const body = document.createElement('div');
    body.className = 'hierarchy-body';
    const maxCount = root.count || 1;
    (function addNode(node, depth) {
      const row = document.createElement('div');
      row.className = 'hier-row' + (node.children.length ? ' has-children' : '');
      const nameCell = document.createElement('span');
      nameCell.className = 'hier-cell';
      nameCell.style.paddingLeft = (depth * 18 + 6) + 'px';
      const tg = document.createElement('span');
      tg.className = 'hier-toggle';
      tg.textContent = node.children.length ? '▾' : '';
      nameCell.appendChild(tg);
      nameCell.appendChild(document.createTextNode(node.name));
      const countCell = document.createElement('span');
      countCell.className = 'hier-cell num';
      countCell.textContent = node.count;
      const pctCell = document.createElement('span');
      pctCell.className = 'hier-cell num';
      pctCell.textContent = node.pct.toFixed(1) + '%';
      const barCellEl = document.createElement('span');
      barCellEl.className = 'hier-cell';
      barCellEl.appendChild(barCell(node.count / maxCount));
      row.appendChild(nameCell);
      row.appendChild(countCell);
      row.appendChild(pctCell);
      row.appendChild(barCellEl);
      body.appendChild(row);
      const kids = document.createElement('div');
      kids.className = 'hier-children';
      node.children.forEach(function (child) { addNode(child, depth + 1); });
      if (node.children.length) {
        body.appendChild(kids);
        row.addEventListener('click', function () {
          kids.classList.toggle('hidden');
          tg.textContent = kids.classList.contains('hidden') ? '▸' : '▾';
        });
      }
    })(root, 0);
    wrap.appendChild(body);
    c.appendChild(wrap);
  };

  /* ---------------- 流量分析 ---------------- */
  function chartCard(title) {
    const el = card(title);
    const canvas = document.createElement('canvas');
    canvas.className = 'chart-canvas';
    el.appendChild(canvas);
    return { el: el, canvas: canvas };
  }

  ui.renderTraffic = function (data) {
    const c = ui.els['traffic-content'];
    c.innerHTML = '';
    const grid = document.createElement('div');
    grid.className = 'stats-grid';
    const interval = data.bucketSize
      ? (data.bucketSize < 1 ? (data.bucketSize * 1000).toFixed(1) + ' ms' : data.bucketSize.toFixed(2) + ' s')
      : '-';
    const t = chartCard('流量吞吐量（按协议堆叠，悬停查看数值 · 每桶 ' + interval + '）');
    const l = chartCard('包长分布 (Packet Length Distribution)');
    const f = chartCard('TCP 标志位 (TCP Flags)');
    grid.appendChild(t.el);
    grid.appendChild(l.el);
    grid.appendChild(f.el);
    c.appendChild(grid);
    requestAnimationFrame(function () {
      WWL.Charts.stacked(t.canvas, data.series, data.labels, {});
      WWL.Charts.bar(l.canvas, data.lengths, {});
      WWL.Charts.bar(f.canvas, data.tcpFlags, {});
    });
  };

  /* ---------------- 通信拓扑 ---------------- */
  ui.renderTopo = function (data, callbacks) {
    const c = ui.els['topo-content'];
    c.innerHTML = '';
    const controls = document.createElement('div');
    controls.className = 'topo-controls';
    controls.innerHTML =
      '<label>最大节点数<select id="topo-maxnodes">' +
      '<option value="40">40</option><option value="80" selected>80</option>' +
      '<option value="150">150</option><option value="300">300</option></select></label>' +
      '<label>标签<select id="topo-labels">' +
      '<option value="all">全部</option><option value="major" selected>仅主要</option>' +
      '<option value="none">关闭</option></select></label>' +
      '<label class="chk"><input type="checkbox" id="topo-internal"> 仅内网主机</label>' +
      '<button id="topo-relayout" class="btn btn-small">重新布局</button>';
    c.appendChild(controls);
    if (!data.nodes || data.nodes.length < 2) {
      const empty = document.createElement('div');
      empty.className = 'topo-empty';
      empty.textContent = data.nodes && data.nodes.length === 1
        ? '仅检测到 1 个通信节点，无法绘制拓扑'
        : '没有可绘制的通信关系（流量可能全部为广播/组播或仅含未知地址）；已尝试按 MAC 地址聚合。';
      c.appendChild(empty);
      return;
    }
    const hint = document.createElement('div');
    hint.className = 'topo-hint';
    hint.textContent = (data.mode === 'mac' ? '当前按 MAC 地址聚合 · ' : '') +
      '拖动节点=调整布局 · 单击节点=按 IP 过滤 · 双击节点=取消固定 · 双击空白=重新布局（节点大小=流量，连线粗细=字节数）';
    const canvasWrap = document.createElement('div');
    canvasWrap.className = 'topo-wrap';
    const canvas = document.createElement('canvas');
    canvas.className = 'topo-canvas';
    canvasWrap.appendChild(canvas);
    c.appendChild(hint);
    c.appendChild(canvasWrap);

    const topo = new WWL.Topo(canvas, {
      onNodeClick: function (node) { if (callbacks.onNodeClick) callbacks.onNodeClick(node); }
    });
    topo.labelMode = 'major';
    topo.setData(data.nodes, data.edges);
    topo.start();

    controls.querySelector('#topo-labels').addEventListener('change', function (e) {
      topo.labelMode = e.target.value;
      topo.draw();
    });
    controls.querySelector('#topo-relayout').addEventListener('click', function () {
      topo.relayout();
    });
    controls.querySelector('#topo-internal').addEventListener('change', function (e) {
      if (!callbacks.onFilterInternal) return;
      const filtered = callbacks.onFilterInternal(e.target.checked);
      topo.setData(filtered.nodes, filtered.edges);
      topo.start();
    });
    controls.querySelector('#topo-maxnodes').addEventListener('change', function (e) {
      if (callbacks.onMaxNodes) callbacks.onMaxNodes(parseInt(e.target.value, 10) || 80);
    });
  };

  ui.showDropOverlay = function (show) {
    ui.els['drop-overlay'].hidden = !show;
  };

  WWL.ui = ui;
})(typeof window !== 'undefined' ? window : globalThis);
