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
      return { error: "Input MAC address." };
    }

    if (compact.length !== 12) {
      return { error: "The MAC address must consist of 12 hexadecimal characters." };
    }

    if (!/^[0-9A-F]{12}$/.test(compact)) {
      return { error: "MAC can only consist of 0-9 and A-F." };
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
        "Please open the web by HTTP",
      );
      return;
    }

    setStatus("pending", "Loading offline CSV", "Loading oui36.csv, mam.csv, oui.csv.");

    const results = await Promise.allSettled(
      CSV_SOURCES.map(async (source) => {
        const response = await fetch(source.path, { cache: "default" });
        if (!response.ok) {
          throw new Error(`${source.path} Return HTTP ${response.status}`);
        }

        const text = await response.text();
        const entries = parseCsv(text, source.bits, source.name);
        if (!entries.length) {
          throw new Error(`${source.path} No record`);
        }

        return { source, entries };
      })
    );

    const loaded = results.filter((item) => item.status === "fulfilled").map((item) => item.value);
    const failures = results.filter((item) => item.status === "rejected").map((item) => item.reason.message);

    state.entries = loaded.flatMap((item) => item.entries).sort((a, b) => b.bits - a.bits);
    state.loadedSources = loaded.map((item) => item.source.path);

    if (state.entries.length) {
      const detail = `Loaded ${state.loadedSources.join(", ")},totally ${state.entries.length.toLocaleString("en-US")} records`;
      setStatus("ready", failures.length ? "Part of CSV loaded" : "Offline CSV ready", failures.length ? `${detail} not loaded：${failures.join("；")}` : detail);
      renderCurrentQuery();
    } else {
      setStatus("error", "Offline CSV loading failed", `Please check the data folder contained mam.csv, oui.csv, oui36.csv.${failures.join("；")}`);
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
        organization: String(row[organizationIndex] || "").trim() || "No manufacturer name provided",
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
      flags.push({ text: "Broadcast", level: "bad" });
      notes.push("This is ethernet broadcast.");
    }

    if ((firstOctet & 1) === 1) {
      flags.push({ text: "Multicast", level: "warn" });
      notes.push("I/G marked.");
    } else {
      flags.push({ text: "Unicast", level: "good" });
    }

    if ((firstOctet & 2) === 2) {
      flags.push({ text: "Locally Administered", level: "warn" });
      notes.push("U/L marked.");
    } else {
      flags.push({ text: "Globally Unique", level: "good" });
    }

    if (compact === "000000000000") {
      flags.push({ text: "All zero", level: "warn" });
      notes.push("Unknows value or initialization value.");
    }

    if (compact.startsWith("01005E")) {
      notes.push("01:00:5E IPv4 multicast prefix.");
    }

    if (compact.startsWith("3333")) {
      notes.push("33:33 is IPv6 multicast prefix.");
    }

    if (compact.startsWith("0180C2")) {
      notes.push("01:80:C2 STP,LLDP etc.");
    }

    if (compact === "01000CCCCCCC") {
      notes.push("01:00:0C:CC:CC:CC Cisco CDP etc.");
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
    const vendorName = vendor ? vendor.organization : "No organization name";
    const source = vendor ? `${vendor.sourceName} / ${vendor.prefix}` : "No record";
    const address = vendor && vendor.address ? vendor.address : "No organization address";

    result.className = "result";
    result.innerHTML = `
      <div class="result-header">
        <div class="mac-normalized">${escapeHtml(mac.colon)}</div>
        <div class="badge-row">
          ${special.flags.map((flag) => `<span class="badge ${flag.level}">${escapeHtml(flag.text)}</span>`).join("")}
        </div>
      </div>
      <div class="result-grid">
        <div class="fact"><span>Org Name</span><strong>${escapeHtml(vendorName)}</strong></div>
        <div class="fact"><span>IEEE Match</span><strong>${escapeHtml(source)}</strong></div>
        <div class="fact"><span>Org Addr</span><strong>${escapeHtml(address)}</strong></div>
        <div class="fact"><span>Colon</span><strong>${escapeHtml(mac.colon)}</strong></div>
        <div class="fact"><span>Hyphen</span><strong>${escapeHtml(mac.hyphen)}</strong></div>
        <div class="fact"><span>Dotted</span><strong>${escapeHtml(mac.dotted)}</strong></div>
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
