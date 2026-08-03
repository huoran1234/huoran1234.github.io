/* app.js - 应用控制器：状态管理、文件解析调度、过滤/排序/分页、数据包详情 */
(function (global) {
  'use strict';
  const WWL = global.WWL;
  const ui = WWL.ui;

  const app = {
    packets: [],
    file: null,
    fileName: '',
    fileSize: 0,
    linkTypeName: '',
    parsing: false,
    cancelled: false,
    parseToken: 0,
    parseStartMs: 0,
    parseElapsed: 0,
    firstT: 0,
    filterCompiled: null,
    filterText: '',
    filterError: null,
    searchText: '',
    sortKey: 'num',
    sortDir: 1,
    pageSize: 0,
    pageIndex: 1,
    simpleView: true,     // true 时 view 为恒等映射（row i = packet i），避免为百万包物化数组
    view: [],
    viewAll: null,
    selectedIdx: -1,
    statsCache: null,
    streamsCache: null,
    trafficCache: null,
    hierarchyCache: null,
    topoCache: null,
    topoMaxNodes: 80,
    topoInternal: false,
    vlist: null,
    listPending: false
  };

  function fmtInt(n) { return n.toLocaleString('en-US'); }
  function debounce(fn, ms) {
    let t = null;
    return function () {
      const self = this, args = arguments;
      clearTimeout(t);
      t = setTimeout(function () { fn.apply(self, args); }, ms);
    };
  }
  function strCmp(a, b) {
    a = a || '';
    b = b || '';
    return a < b ? -1 : a > b ? 1 : 0;
  }
  function tn(name, value, range, children) {
    return { name: name, value: value, range: range || null, children: children || [] };
  }

  function viewIndex(i) { return app.simpleView ? i : app.view[i]; }
  function viewCount() { return app.simpleView ? app.packets.length : app.view.length; }
  function totalPages() {
    const total = app.simpleView ? app.packets.length : (app.viewAll ? app.viewAll.length : 0);
    return app.pageSize > 0 ? Math.max(1, Math.ceil(total / app.pageSize)) : 1;
  }

  /* ---------------- 过滤 / 搜索 / 排序 ---------------- */
  function matchesSearch(p) {
    const q = app.searchText;
    if (!q) return true;
    return String(p.num).indexOf(q) >= 0 ||
      (p.src && p.src.toLowerCase().indexOf(q) >= 0) ||
      (p.dst && p.dst.toLowerCase().indexOf(q) >= 0) ||
      (p.proto && p.proto.indexOf(q) >= 0) ||
      (p.info && p.info.toLowerCase().indexOf(q) >= 0) ||
      (p.macSrc && p.macSrc.indexOf(q) >= 0) ||
      (p.macDst && p.macDst.indexOf(q) >= 0) ||
      (p.sport && String(p.sport) === q) ||
      (p.dport && String(p.dport) === q);
  }

  function sortIndexes(arr) {
    const key = app.sortKey;
    const dir = app.sortDir;
    const packets = app.packets;
    let cmp;
    if (key === 'num') cmp = function (a, b) { return packets[a].num - packets[b].num; };
    else if (key === 'time') cmp = function (a, b) { return packets[a].t - packets[b].t; };
    else if (key === 'len') cmp = function (a, b) { return packets[a].len - packets[b].len; };
    else if (key === 'src') cmp = function (a, b) { return strCmp(packets[a].src, packets[b].src); };
    else if (key === 'sport') cmp = function (a, b) { return packets[a].sport - packets[b].sport; };
    else if (key === 'dst') cmp = function (a, b) { return strCmp(packets[a].dst, packets[b].dst); };
    else if (key === 'dport') cmp = function (a, b) { return packets[a].dport - packets[b].dport; };
    else if (key === 'proto') cmp = function (a, b) { return strCmp(packets[a].proto, packets[b].proto); };
    else cmp = function (a, b) { return strCmp(packets[a].info, packets[b].info); };
    arr.sort(function (a, b) { return cmp(a, b) * dir; });
  }

  function rebuildView() {
    const packets = app.packets;
    const n = packets.length;
    const fm = app.filterCompiled ? app.filterCompiled.match : null;
    const simple = !fm && !app.searchText && app.sortKey === 'num' && app.pageSize === 0;
    let out = null;
    if (simple) {
      app.simpleView = true;
      app.viewAll = null;
    } else {
      app.simpleView = false;
      out = [];
      for (let i = 0; i < n; i++) {
        const p = packets[i];
        if (fm && !fm(p)) continue;
        if (!matchesSearch(p)) continue;
        out.push(i);
      }
      sortIndexes(out);
      app.viewAll = out;
    }
    const total = simple ? n : out.length;
    let pages = 1, from = 0, to = total;
    if (app.pageSize > 0) {
      pages = Math.max(1, Math.ceil(total / app.pageSize));
      if (app.pageIndex > pages) app.pageIndex = 1;
      from = (app.pageIndex - 1) * app.pageSize;
      to = Math.min(total, from + app.pageSize);
      app.view = out.slice(from, to);
    } else {
      app.view = out;
    }
    updateListUI(total, pages, from, to);
  }

  function updateListUI(total, pages, from, to) {
    const count = viewCount();
    app.vlist.setCount(count);
    ui.setFilterCount('匹配 ' + fmtInt(total) + ' / ' + fmtInt(app.packets.length) + ' 包');
    if (total === 0) {
      ui.updatePager({ hidden: true, page: 1, pages: 1, text: '' });
      ui.showEmptyHint(app.packets.length
        ? '没有匹配的数据包，调整过滤器或搜索词'
        : '尚未加载数据：点击「打开 PCAP」或将文件拖入窗口，也可点「加载示例」快速体验');
      return;
    }
    if (app.pageSize > 0) {
      ui.updatePager({
        hidden: false,
        page: app.pageIndex,
        pages: pages,
        text: '第 ' + app.pageIndex + ' / ' + pages + ' 页 · 显示 ' + fmtInt(from + 1) + ' - ' + fmtInt(to) + ' / ' + fmtInt(total)
      });
    } else {
      ui.updatePager({
        hidden: false,
        page: 1,
        pages: 1,
        text: '显示 ' + fmtInt(total) + ' / ' + fmtInt(total) + ' 包（虚拟滚动）'
      });
    }
    ui.showEmptyHint(null);
  }

  function renderRow(i, el) {
    const idx = viewIndex(i);
    if (idx === undefined) return;
    const p = app.packets[idx];
    const rel = app.firstT ? (p.t - app.firstT) : p.t;
    const protoCls = 'proto-' + (p.proto || 'other');
    el.classList.toggle('selected', idx === app.selectedIdx);
    el.innerHTML =
      '<span class="cell mono">' + p.num + '</span>' +
      '<span class="cell mono">' + rel.toFixed(6) + '</span>' +
      '<span class="cell mono src">' + WWL.escapeHtml(p.src || '') + '</span>' +
      '<span class="cell mono">' + (p.sport || '') + '</span>' +
      '<span class="cell mono dst">' + WWL.escapeHtml(p.dst || '') + '</span>' +
      '<span class="cell mono">' + (p.dport || '') + '</span>' +
      '<span class="cell proto ' + protoCls + '">' + WWL.escapeHtml((p.proto || '').toUpperCase()) + '</span>' +
      '<span class="cell mono">' + p.len + '</span>' +
      '<span class="cell info">' + WWL.escapeHtml(p.info || '') + '</span>';
  }

  function applyFilterText() {
    const text = app.filterText;
    try {
      const compiled = WWL.Filter.compile(text);
      app.filterCompiled = compiled;
      app.filterError = null;
      ui.setFilterError(null);
      app.pageIndex = 1;
      rebuildView();
    } catch (err) {
      app.filterError = err.message;
      ui.setFilterError(err.message);
    }
  }

  function setSort(key) {
    if (app.sortKey === key) app.sortDir = -app.sortDir;
    else { app.sortKey = key; app.sortDir = 1; }
    updateSortHeader();
    app.pageIndex = 1;
    rebuildView();
  }

  function updateSortHeader() {
    ui.els['pkt-header'].querySelectorAll('.sortable').forEach(function (el) {
      el.classList.remove('sorted');
      delete el.dataset.arrow;
      if (el.dataset.sort === app.sortKey) {
        el.classList.add('sorted');
        el.dataset.arrow = app.sortDir === 1 ? '▲' : '▼';
      }
    });
  }

  /* ---------------- 文件解析 ---------------- */
  function resetState() {
    app.packets = [];
    app.firstT = 0;
    app.selectedIdx = -1;
    app.simpleView = true;
    app.view = [];
    app.viewAll = null;
    app.statsCache = null;
    app.streamsCache = null;
    app.trafficCache = null;
    app.hierarchyCache = null;
    app.topoCache = null;
    app.filterText = '';
    app.searchText = '';
    app.filterCompiled = null;
    app.filterError = null;
    app.linkTypeName = '';
    ui.els['filter-input'].value = '';
    ui.els['search-input'].value = '';
    ui.setFilterError(null);
    ui.setFilterCount('');
    ui.showDetailsHint('选择一个数据包查看协议树');
    ui.showHexHint();
  }

  async function openFile(file) {
    if (!file) return;
    app.cancelled = true;              // 让旧的解析循环尽快退出
    const token = ++app.parseToken;
    resetState();
    app.file = file;
    app.fileName = file.name || 'capture';
    app.fileSize = file.size || 0;
    app.parsing = true;
    app.cancelled = false;
    app.parseStartMs = performance.now();
    ui.showProgress(true);
    ui.setProgress(0, '检测文件格式...');
    ui.setFileInfo('正在读取: ' + app.fileName + ' (' + WWL.formatBytes(app.fileSize) + ')');
    ui.showEmptyHint('正在解析 ' + app.fileName + ' ...');
    ui.setStatus('0 packets', '解析中...', app.fileName);
    try {
      const source = await prepareSource(file);
      if (token !== app.parseToken) return;
      if (source !== file) {
        app.file = source;
        app.fileSize = source.size || 0;
      }
      const result = await WWL.Pcap.load(source, {
        onPacket: function (m) {
          if (token !== app.parseToken) return;
          app.packets.push(m);
          if (app.packets.length === 1) app.firstT = m.t;
          scheduleListUpdate();
        },
        onProgress: function (pr) {
          if (token !== app.parseToken) return;
          const pct = pr.totalBytes ? pr.readBytes / pr.totalBytes * 100 : 0;
          const elapsed = (performance.now() - app.parseStartMs) / 1000;
          ui.setProgress(pct, fmtInt(pr.packets) + ' packets · ' +
            WWL.formatBytes(pr.readBytes) + ' / ' + WWL.formatBytes(pr.totalBytes) +
            ' · ' + elapsed.toFixed(1) + 's');
        },
        isCancelled: function () {
          return app.cancelled || token !== app.parseToken;
        }
      });
      if (token !== app.parseToken) return;
      app.linkTypeName = result.linkTypeName;
      finishParse(result);
    } catch (err) {
      if (token !== app.parseToken) return;
      app.parsing = false;
      ui.showProgress(false);
      ui.setFilterCount('');
      ui.setStatus(fmtInt(app.packets.length) + ' packets', '', app.fileName);
      ui.showEmptyHint('解析失败: ' + (err.message || err));
      ui.setFileInfo('解析失败: ' + (err.message || err));
    }
  }

  function finishParse(result) {
    app.parsing = false;
    app.parseElapsed = (performance.now() - app.parseStartMs) / 1000;
    ui.showProgress(false);
    ui.setFileInfo(app.fileName + ' (' + WWL.formatBytes(app.fileSize) + ') · ' +
      (app.linkTypeName || '') + (result.cancelled ? ' · 解析已停止' : ' · 解析完成'));
    app.statsCache = null;
    app.streamsCache = null;
    app.trafficCache = null;
    app.hierarchyCache = null;
    app.topoCache = null;
    rebuildView();
    ui.setStatus(
      fmtInt(app.packets.length) + ' packets',
      '解析用时 ' + app.parseElapsed.toFixed(1) + 's' + (result.cancelled ? '（已停止）' : ''),
      app.fileName
    );
    if (app.packets.length) {
      if (app.selectedIdx < 0) selectRow(0);
    } else {
      ui.showEmptyHint('未解析到数据包（文件格式或链路类型可能不受支持）');
      ui.showDetailsHint('未解析到数据包');
    }
  }

  function scheduleListUpdate() {
    if (app.listPending) return;
    app.listPending = true;
    setTimeout(function () {
      app.listPending = false;
      if (!app.parsing) return;
      // 解析期间仅做廉价更新：无过滤/搜索/排序/分页时直接刷新虚拟列表
      if (!app.filterText && !app.searchText && app.sortKey === 'num' && app.pageSize === 0) {
        app.simpleView = true;
        updateListUI(app.packets.length, 1, 0, app.packets.length);
      } else {
        ui.setFilterCount('已解析 ' + fmtInt(app.packets.length) + ' 包...');
      }
    }, 140);
  }

  /* ---------------- 数据包详情 ---------------- */
  function chainOf(meta) {
    const parts = [];
    if (meta.macSrc) parts.push('eth');
    if (meta.ethType) parts.push('ethertype');
    if (meta.l3) parts.push(meta.l3);
    if (meta.tproto) parts.push(meta.tproto);
    if (meta.app) parts.push(meta.app);
    return parts.join(':');
  }

  function buildFrameNodes(p, capLen, opts, meta) {
    const wireBits = p.len * 8;
    const rel = p.t - opts.firstT;
    const kids = [
      tn('Interface id', '0', null),
      tn('Encapsulation type', opts.linkTypeName + ' (' + p.linkType + ')', null),
      tn('Arrival Time', WWL.formatTime(p.t), null),
      tn('[Time since first frame]', rel.toFixed(6) + ' seconds', null),
      tn('Frame Number', p.num, null),
      tn('Frame Length', p.len + ' bytes (' + wireBits + ' bits)', [0, p.len]),
      tn('Capture Length', capLen + ' bytes', [0, capLen]),
      tn('[Destination MAC]', meta.macDst || '-', [0, 6]),
      tn('[Source MAC]', meta.macSrc || '-', [6, 12]),
      tn('[Protocols in frame]', chainOf(meta), null)
    ];
    return [tn(
      'Frame ' + p.num + ': ' + p.len + ' bytes on wire (' + wireBits + ' bits), ' + capLen + ' bytes captured',
      '', [0, capLen], kids
    )];
  }

  async function selectRow(i) {
    if (app.parsing) return;
    const idx = viewIndex(i);
    if (idx === undefined || idx < 0 || !app.file) return;
    app.selectedIdx = idx;
    app.vlist.render();
    const p = app.packets[idx];
    ui.showDetailsHint('正在读取数据包 ' + p.num + ' ...');
    try {
      const end = Math.min(p.offset + p.capLen, app.fileSize);
      const ab = await app.file.slice(p.offset, end).arrayBuffer();
      const bytes = new Uint8Array(ab);
      const opts = {
        linkType: p.linkType,
        endian: p.endian,
        t: p.t,
        frameNum: p.num,
        origLen: p.len,
        capLen: bytes.length,
        linkTypeName: WWL.linkTypeName(p.linkType),
        firstT: app.firstT
      };
      const res = WWL.dissectFull(bytes, opts);
      const nodes = buildFrameNodes(p, bytes.length, opts, res.meta);
      nodes.push.apply(nodes, res.tree);
      ui.renderDetails(nodes);
      ui.renderHex(bytes, p.offset);
      ui.highlightRange(0, Math.min(14, bytes.length));
    } catch (err) {
      ui.showDetailsHint('读取失败: ' + (err.message || err));
    }
  }

  /* ---------------- 统计 / 会话 ---------------- */
  function onTab(tab) {
    if (tab === 'stats') {
      if (!app.statsCache) app.statsCache = WWL.Stats.compute(app.packets);
      ui.renderStats(app.statsCache);
    } else if (tab === 'streams') {
      if (!app.streamsCache) app.streamsCache = WWL.Streams.compute(app.packets);
      ui.renderStreams(app.streamsCache, function (s) {
        const ciA = s.a.lastIndexOf(':');
        const ciB = s.b.lastIndexOf(':');
        const ipA = s.a.slice(0, ciA), portA = s.a.slice(ciA + 1);
        const ipB = s.b.slice(0, ciB), portB = s.b.slice(ciB + 1);
        const expr = 'ip.addr == ' + ipA + ' and ip.addr == ' + ipB +
          ' and tcp and (tcp.port == ' + portA + ' or tcp.port == ' + portB + ')';
        setFilterText(expr);
        switchTab('packets');
      });
    } else if (tab === 'traffic') {
      if (!app.trafficCache) app.trafficCache = WWL.Stats.traffic(app.packets);
      ui.renderTraffic(app.trafficCache);
    } else if (tab === 'hierarchy') {
      if (!app.hierarchyCache) app.hierarchyCache = WWL.Stats.hierarchy(app.packets);
      ui.renderHierarchy(app.hierarchyCache);
    } else if (tab === 'topo') {
      if (!app.topoCache) app.topoCache = computeTopo(app.topoMaxNodes, app.topoInternal);
      ui.renderTopo(app.topoCache, topoCallbacks());
    }
  }

  function computeTopo(maxNodes, internalOnly) {
    const full = WWL.Topo.compute(app.packets, maxNodes || app.topoMaxNodes);
    if (!internalOnly) return full;
    const internalIds = new Set();
    full.nodes.forEach(function (n) {
      if (WWL.Topo.isPrivate(n.name)) internalIds.add(n.id);
    });
    const nodes = full.nodes.filter(function (n) {
      return internalIds.has(n.id) ||
        full.edges.some(function (e) {
          return (e.a === n.id || e.b === n.id) && (internalIds.has(e.a) || internalIds.has(e.b));
        });
    });
    const ids = new Set(nodes.map(function (n) { return n.id; }));
    return { nodes: nodes, edges: full.edges.filter(function (e) { return ids.has(e.a) && ids.has(e.b); }) };
  }

  function topoCallbacks() {
    return {
      onNodeClick: function (node) {
        setFilterText('ip.addr == ' + node.name);
        switchTab('packets');
      },
      onMaxNodes: function (max) {
        app.topoMaxNodes = max;
        app.topoCache = computeTopo(max, app.topoInternal);
        ui.renderTopo(app.topoCache, topoCallbacks());
      },
      onFilterInternal: function (checked) {
        app.topoInternal = checked;
        app.topoCache = computeTopo(app.topoMaxNodes, checked);
        return app.topoCache;
      }
    };
  }

  function setFilterText(text) {
    app.filterText = text;
    ui.els['filter-input'].value = text;
    applyFilterText();
  }

  function switchTab(tab) {
    const btn = document.querySelector('.tab[data-tab="' + tab + '"]');
    if (btn) btn.click();
  }

  /* ---------------- 事件 ---------------- */
  function bindEvents() {
    ui.els['btn-open'].addEventListener('click', function () {
      ui.els['file-input'].click();
    });
    ui.els['file-input'].addEventListener('change', function () {
      if (this.files && this.files[0]) openFile(this.files[0]);
      this.value = '';
    });
    ui.els['btn-sample'].addEventListener('click', loadSample);
    ui.els['btn-stop'].addEventListener('click', function () {
      app.cancelled = true;
      ui.setFileInfo('正在停止解析...');
    });

    const filterInput = ui.els['filter-input'];
    filterInput.addEventListener('input', debounce(function () {
      app.filterText = filterInput.value.trim();
      applyFilterText();
    }, 250));
    filterInput.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') {
        app.filterText = filterInput.value.trim();
        applyFilterText();
      }
    });

    const searchInput = ui.els['search-input'];
    searchInput.addEventListener('input', debounce(function () {
      app.searchText = searchInput.value.trim().toLowerCase();
      app.pageIndex = 1;
      rebuildView();
    }, 180));

    ui.els['pkt-header'].addEventListener('click', function (e) {
      const col = e.target.closest('.sortable');
      if (col) setSort(col.dataset.sort);
    });

    ui.els['page-size'].addEventListener('change', function () {
      app.pageSize = parseInt(this.value, 10) || 0;
      app.pageIndex = 1;
      rebuildView();
    });
    ui.els['btn-prev'].addEventListener('click', function () {
      if (app.pageIndex > 1) { app.pageIndex--; rebuildView(); }
    });
    ui.els['btn-next'].addEventListener('click', function () {
      if (app.pageIndex < totalPages()) { app.pageIndex++; rebuildView(); }
    });

    let dragDepth = 0;
    window.addEventListener('dragenter', function (e) {
      e.preventDefault();
      dragDepth++;
      ui.showDropOverlay(true);
    });
    window.addEventListener('dragover', function (e) { e.preventDefault(); });
    window.addEventListener('dragleave', function (e) {
      e.preventDefault();
      if (e.relatedTarget === null) {
        // 拖拽完全离开窗口：直接复位，避免计数错乱导致遮罩卡住
        dragDepth = 0;
        ui.showDropOverlay(false);
      } else {
        dragDepth--;
        if (dragDepth <= 0) { dragDepth = 0; ui.showDropOverlay(false); }
      }
    });
    window.addEventListener('drop', function (e) {
      e.preventDefault();
      dragDepth = 0;
      ui.showDropOverlay(false);
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) {
        openFile(e.dataTransfer.files[0]);
      }
    });
  }

  function loadSample() {
    const b64 = WWL.SAMPLE_B64;
    if (!b64) { ui.setFileInfo('内置示例缺失'); return; }
    try {
      const bin = atob(b64);
      const u8 = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
      const file = new File([u8], 'sample.pcap', { type: 'application/vnd.tcpdump.pcap' });
      openFile(file);
    } catch (e) {
      ui.setFileInfo('示例加载失败: ' + (e.message || e));
    }
  }

  function isGzName(name) {
    return /\.gz$/i.test(name || '');
  }

  async function prepareSource(file) {
    if (!isGzName(file.name)) return file;
    try {
      return await WWL.Pcap.gunzip(file);
    } catch (e) {
      throw new Error('gzip decompression failed (' + (e.message || e) + '), please decompress manually');
    }
  }

  function init() {
    ui.init();
    ui.setRangeHandler(function (start, end) {
      ui.highlightRange(start, end);
    });
    app.vlist = new WWL.VirtualList(ui.els['pkt-body'], 24);
    app.vlist.setRenderRow(renderRow);
    app.vlist.onClick = function (i) { selectRow(i); };
    ui.onTab = onTab;
    bindEvents();
    updateSortHeader();
    updateListUI(0, 1, 0, 0);
    ui.setStatus('0 packets', '', '未加载文件');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  WWL.app = app;
})(typeof window !== 'undefined' ? window : globalThis);
