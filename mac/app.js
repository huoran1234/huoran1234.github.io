(function () {
  "use strict";

  const CSV_SOURCES = [
    { name: "MA-S / OUI-36", path: "data/oui36.csv", bits: 36 },
    { name: "MA-M / OUI-28", path: "data/mam.csv", bits: 28 },
    { name: "MA-L / OUI", path: "data/oui.csv", bits: 24 },
  ];

  const state = {
    entries: [],
    loadedSources: [],
  };

  const form = document.querySelector("#lookupForm");
  const input = document.querySelector("#macInput");
  const result = document.querySelector("#result");
  const sourceStatus = document.querySelector("#sourceStatus");
  const sourceTitle = document.querySelector("#sourceTitle");
  const sourceDetail = document.querySelector("#sourceDetail");

  function normalizeMac(value) {
    const compact = String(value || "")
      .trim()
      .replace(/[^0-9a-f]/gi, "")
      .toUpperCase();

    if (!compact) {
      return { error: "请输入 MAC 地址。" };
    }

    if (compact.length !== 12) {
      return { error: "MAC 地址需要包含 12 个十六进制字符。" };
    }

    if (!/^[0-9A-F]{12}$/.test(compact)) {
      return { error: "MAC 地址只能包含 0-9 与 A-F。" };
    }

    const octets = compact.match(/../g);
    return {
      compact,
      octets,
      colon: octets.join(":"),
      hyphen: octets.join("-"),
      dotted: `${compact.slice(0, 4)}.${compact.slice(4, 8)}.${compact.slice(8, 12)}`,
    };
  }

  async function loadOfflineCsv() {
    if (window.location.protocol === "file:") {
      setStatus(
        "error",
        "请通过 HTTP 打开页面",
        "浏览器会阻止 file:// 页面读取本地 CSV。请使用 GitHub Pages，或在本目录运行本地静态服务器后访问 http://localhost:8099/。"
      );
      return;
    }

    setStatus("pending", "正在加载离线 CSV", "页面会读取 data 目录中的 oui36.csv、mam.csv、oui.csv。");

    const results = await Promise.allSettled(
      CSV_SOURCES.map(async (source) => {
        const response = await fetch(source.path, { cache: "default" });
        if (!response.ok) {
          throw new Error(`${source.path} 返回 HTTP ${response.status}`);
        }

        const text = await response.text();
        const entries = parseCsv(text, source.bits, source.name);
        if (!entries.length) {
          throw new Error(`${source.path} 没有可用记录`);
        }

        return { source, entries };
      })
    );

    const loaded = results.filter((item) => item.status === "fulfilled").map((item) => item.value);
    const failures = results.filter((item) => item.status === "rejected").map((item) => item.reason.message);

    state.entries = loaded.flatMap((item) => item.entries).sort((a, b) => b.bits - a.bits);
    state.loadedSources = loaded.map((item) => item.source.path);

    if (state.entries.length) {
      const detail = `已加载 ${state.loadedSources.join("、")}，共 ${state.entries.length.toLocaleString("zh-CN")} 条记录。`;
      setStatus("ready", failures.length ? "部分 CSV 已加载" : "离线 CSV 已就绪", failures.length ? `${detail} 未加载：${failures.join("；")}` : detail);
      renderCurrentQuery();
    } else {
      setStatus("error", "离线 CSV 加载失败", `请确认 data 目录中存在 mam.csv、oui.csv、oui36.csv。${failures.join("；")}`);
    }
  }

  function parseCsv(text, fallbackBits, sourceName) {
    const rows = parseCsvRows(text);
    if (!rows.length) return [];

    const header = rows[0].map((cell) => cell.trim().toLowerCase());
    const assignmentIndex = findHeader(header, ["assignment", "registry"]);
    const organizationIndex = findHeader(header, ["organization name", "organization"]);
    const addressIndex = findHeader(header, ["organization address", "address"]);

    const entries = [];
    for (const row of rows.slice(1)) {
      const assignment = String(row[assignmentIndex] || row[0] || "")
        .replace(/[^0-9a-f]/gi, "")
        .toUpperCase();
      if (!assignment) continue;

      entries.push({
        prefix: assignment,
        bits: assignment.length * 4 || fallbackBits,
        sourceName,
        organization: String(row[organizationIndex] || "").trim() || "未提供厂商名称",
        address: String(row[addressIndex] || "").trim(),
      });
    }

    return entries;
  }

  function parseCsvRows(text) {
    const rows = [];
    let row = [];
    let cell = "";
    let quoted = false;

    for (let index = 0; index < text.length; index += 1) {
      const char = text[index];
      const next = text[index + 1];

      if (char === '"' && quoted && next === '"') {
        cell += '"';
        index += 1;
      } else if (char === '"') {
        quoted = !quoted;
      } else if (char === "," && !quoted) {
        row.push(cell);
        cell = "";
      } else if ((char === "\n" || char === "\r") && !quoted) {
        if (char === "\r" && next === "\n") index += 1;
        row.push(cell);
        if (row.some((part) => part.trim())) rows.push(row);
        row = [];
        cell = "";
      } else {
        cell += char;
      }
    }

    row.push(cell);
    if (row.some((part) => part.trim())) rows.push(row);
    return rows;
  }

  function findHeader(header, candidates) {
    for (const candidate of candidates) {
      const found = header.findIndex((item) => item === candidate);
      if (found >= 0) return found;
    }
    return 0;
  }

  function findVendor(compact) {
    return state.entries.find((entry) => compact.startsWith(entry.prefix));
  }

  function inspectSpecial(mac) {
    const firstOctet = parseInt(mac.octets[0], 16);
    const flags = [];
    const notes = [];
    const compact = mac.compact;

    if (compact === "FFFFFFFFFFFF") {
      flags.push({ text: "广播地址", level: "bad" });
      notes.push("这是以太网广播地址，不代表某个单独设备。");
    }

    if ((firstOctet & 1) === 1) {
      flags.push({ text: "组播 / 群组地址", level: "warn" });
      notes.push("首字节最低位为 1，表示 I/G 位已置位，属于组播或群组地址。");
    } else {
      flags.push({ text: "单播地址", level: "good" });
    }

    if ((firstOctet & 2) === 2) {
      flags.push({ text: "本地管理", level: "warn" });
      notes.push("首字节第二低位为 1，表示 U/L 位为本地管理，通常不会有 IEEE 厂商注册记录。");
    } else {
      flags.push({ text: "全球唯一", level: "good" });
    }

    if (compact === "000000000000") {
      flags.push({ text: "全零地址", level: "warn" });
      notes.push("全零地址常作为占位、未知或初始化值使用，不应当表示正常网卡。");
    }

    if (compact.startsWith("01005E")) {
      notes.push("01:00:5E 是 IPv4 组播常见映射前缀。");
    }

    if (compact.startsWith("3333")) {
      notes.push("33:33 是 IPv6 组播常见映射前缀。");
    }

    if (compact.startsWith("0180C2")) {
      notes.push("01:80:C2 常用于桥接、生成树、LLDP 等链路层控制协议。");
    }

    if (compact === "01000CCCCCCC") {
      notes.push("01:00:0C:CC:CC:CC 常用于 Cisco Discovery Protocol 等协议。");
    }

    return { flags, notes };
  }

  function renderCurrentQuery() {
    if (input.value.trim()) renderResult(input.value);
  }

  function renderResult(value) {
    const mac = normalizeMac(value);
    if (mac.error) {
      result.className = "result empty";
      result.innerHTML = `<p>${escapeHtml(mac.error)}</p>`;
      return;
    }

    const special = inspectSpecial(mac);
    const vendor = findVendor(mac.compact);
    const vendorName = vendor ? vendor.organization : "未匹配到 IEEE 注册厂商";
    const source = vendor ? `${vendor.sourceName} / ${vendor.prefix}` : "无匹配记录";
    const address = vendor && vendor.address ? vendor.address : "无地址信息";

    result.className = "result";
    result.innerHTML = `
      <div class="result-header">
        <div class="mac-normalized">${escapeHtml(mac.colon)}</div>
        <div class="badge-row">
          ${special.flags.map((flag) => `<span class="badge ${flag.level}">${escapeHtml(flag.text)}</span>`).join("")}
        </div>
      </div>
      <div class="result-grid">
        <div class="fact"><span>厂商 / 组织</span><strong>${escapeHtml(vendorName)}</strong></div>
        <div class="fact"><span>IEEE 匹配</span><strong>${escapeHtml(source)}</strong></div>
        <div class="fact"><span>注册地址</span><strong>${escapeHtml(address)}</strong></div>
        <div class="fact"><span>冒号格式</span><strong>${escapeHtml(mac.colon)}</strong></div>
        <div class="fact"><span>短横线格式</span><strong>${escapeHtml(mac.hyphen)}</strong></div>
        <div class="fact"><span>点分格式</span><strong>${escapeHtml(mac.dotted)}</strong></div>
      </div>
      ${
        special.notes.length
          ? `<ul class="special-list">${special.notes.map((note) => `<li>${escapeHtml(note)}</li>`).join("")}</ul>`
          : ""
      }
    `;
  }

  function setStatus(level, title, detail) {
    sourceStatus.className = `status-dot ${level}`;
    sourceTitle.textContent = title;
    sourceDetail.textContent = detail;
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    renderResult(input.value);
  });

  input.addEventListener("input", () => {
    if (input.value.trim()) renderResult(input.value);
  });

  document.querySelectorAll("[data-example]").forEach((button) => {
    button.addEventListener("click", () => {
      input.value = button.dataset.example;
      renderResult(input.value);
      input.focus();
    });
  });

  loadOfflineCsv();
})();
