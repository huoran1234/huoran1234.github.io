/* pcap.js - 分块流式读取 .pcap / .pcapng，避免一次性载入整个文件 */
(function (global) {
  'use strict';
  const WWL = global.WWL = global.WWL || {};

  const CHUNK = 4 * 1024 * 1024; // 4MB 读取块

  function u32le(b, o) {
    return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
  }
  function u32be(b, o) {
    return ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
  }

  function StreamBuffer(file, chunkSize) {
    this.file = file;
    this.chunk = chunkSize || CHUNK;
    this.pos = 0;          // 已从文件读取的字节数
    this.buf = new Uint8Array(0);
    this.eof = false;
  }
  StreamBuffer.prototype.absPos = function () {
    return this.pos - this.buf.length;
  };
  StreamBuffer.prototype.ensure = async function (n) {
    while (this.buf.length < n && !this.eof) {
      const end = Math.min(this.pos + this.chunk, this.file.size);
      if (end <= this.pos) { this.eof = true; break; }
      let ab;
      try {
        ab = await this.file.slice(this.pos, end).arrayBuffer();
      } catch (e) {
        this.eof = true;
        throw e;
      }
      const chunk = new Uint8Array(ab);
      if (chunk.length === 0) { this.eof = true; break; }
      if (this.buf.length === 0) {
        this.buf = chunk;
      } else {
        const merged = new Uint8Array(this.buf.length + chunk.length);
        merged.set(this.buf, 0);
        merged.set(chunk, this.buf.length);
        this.buf = merged;
      }
      this.pos = end;
    }
    return this.buf.length >= n;
  };
  StreamBuffer.prototype.peek = function (n) {
    return this.buf.subarray(0, n);
  };
  StreamBuffer.prototype.take = function (n) {
    const out = this.buf.subarray(0, n);
    this.buf = this.buf.subarray(n);
    return out;
  };

  function nextTick() {
    return new Promise(function (resolve) {
      setTimeout(resolve, 0);
    });
  }

  WWL.Pcap = {};

  /* gzip 解压（浏览器内置 DecompressionStream） */
  WWL.Pcap.gunzip = async function (blob) {
    if (typeof DecompressionStream === 'undefined' || !blob.stream) {
      throw new Error('当前浏览器不支持 gzip 解压');
    }
    const stream = blob.stream().pipeThrough(new DecompressionStream('gzip'));
    const buf = await new Response(stream).arrayBuffer();
    return new Blob([buf]);
  };

  /* 读取文件头，判断格式 */
  WWL.Pcap.detect = async function (file) {
    if (!file || file.size < 4) return { type: 'unknown', reason: '文件过小' };
    const head = new Uint8Array(await file.slice(0, Math.min(24, file.size)).arrayBuffer());
    if (head.length < 4) return { type: 'unknown', reason: '文件过小' };
    const v = u32be(head, 0);
    if (v === 0x0a0d0d0a) return { type: 'pcapng' };
    const le = u32le(head, 0);
    if (le === 0xa1b2c3d4 || le === 0xa1b23c4d) return { type: 'pcap', nano: le === 0xa1b23c4d };
    const be = u32be(head, 0);
    if (be === 0xa1b2c3d4 || be === 0xa1b23c4d) return { type: 'pcap', nano: be === 0xa1b23c4d, bigEndian: true };
    return { type: 'unknown', reason: '无法识别的文件格式（不是 pcap / pcapng）' };
  };

  function internStrings(interner) {
    return function (m) {
      m.src = interner.src(m.src);
      m.dst = interner.dst(m.dst);
      m.macSrc = interner.mac(m.macSrc);
      m.macDst = interner.mac(m.macDst);
      m.proto = interner.proto(m.proto);
      m.info = interner.info(m.info);
      return m;
    };
  }

  function makePacketMeta(num, t, offset, capLen, origLen, linkType, endian, raw) {
    const meta = WWL.dissectSummary(raw, { linkType: linkType, endian: endian });
    meta.num = num;
    meta.t = t;
    meta.offset = offset;
    meta.capLen = capLen;
    meta.len = origLen > 0 ? origLen : capLen;
    meta.linkType = linkType;
    meta.endian = endian;
    return meta;
  }

  /* ---------------- pcap (classic) ---------------- */
  async function loadClassic(file, info, callbacks) {
    const endian = info.bigEndian ? 'be' : 'le';
    const unit = info.nano ? 1e-9 : 1e-6;
    const sb = new StreamBuffer(file);
    if (!(await sb.ensure(24))) throw new Error('pcap 全局头不完整');
    const h = sb.peek(24);
    const dv = new DataView(h.buffer, h.byteOffset, h.byteLength);
    const isLE = endian === 'le';
    const linkType = dv.getUint32(20, isLE);
    const result = {
      type: 'pcap',
      endian: endian,
      linkType: linkType,
      linkTypeName: WWL.linkTypeName(linkType),
      nano: !!info.nano,
      cancelled: false,
      packets: 0
    };
    sb.take(24);
    callbacks.onProgress({ phase: 'parsing', readBytes: 24, totalBytes: file.size, packets: 0 });
    let num = 0;
    let sinceYield = 0;
    while (true) {
      if (callbacks.isCancelled && callbacks.isCancelled()) { result.cancelled = true; break; }
      if (!(await sb.ensure(16))) break;
      const recStart = sb.absPos();
      const rec = sb.peek(16);
      const rdv = new DataView(rec.buffer, rec.byteOffset, rec.byteLength);
      const tsSec = rdv.getUint32(0, isLE);
      const tsFrac = rdv.getUint32(4, isLE);
      const inclLen = rdv.getUint32(8, isLE);
      const origLen = rdv.getUint32(12, isLE);
      if (inclLen > 64 * 1024 * 1024) break; // 防御异常长度
      if (!(await sb.ensure(16 + inclLen))) break;
      const data = sb.take(16 + inclLen).subarray(16);
      num++;
      const t = tsSec + tsFrac * unit;
      const m = makePacketMeta(num, t, recStart + 16, inclLen, origLen, linkType, endian, data);
      callbacks.onPacket(m);
      result.packets = num;
      if (++sinceYield >= 4096) {
        sinceYield = 0;
        callbacks.onProgress({ phase: 'parsing', readBytes: sb.pos, totalBytes: file.size, packets: num });
        await nextTick();
      }
    }
    if (callbacks.isCancelled && callbacks.isCancelled()) result.cancelled = true;
    return result;
  }

  /* ---------------- pcapng ---------------- */
  async function loadNG(file, callbacks) {
    const sb = new StreamBuffer(file);
    let endian = 'le';
    const ifaces = [];   // {linkType, tsresol, tsoffset}
    const result = {
      type: 'pcapng',
      endian: endian,
      linkType: 1,
      linkTypeName: WWL.linkTypeName(1),
      cancelled: false,
      packets: 0
    };
    let num = 0;
    let sinceYield = 0;
    while (true) {
      if (callbacks.isCancelled && callbacks.isCancelled()) { result.cancelled = true; break; }
      if (!(await sb.ensure(8))) break;
      const blockStart = sb.absPos();
      const head = sb.peek(8);
      const tLE = u32le(head, 0);
      const tBE = u32be(head, 0);
      let type;
      if (tLE === 0x0a0d0d0a || tBE === 0x0a0d0d0a) {
        type = 0x0a0d0d0a;
        if (!(await sb.ensure(12))) break;
        const bom = sb.peek(12).subarray(8, 12);
        endian = u32be(bom, 0) === 0x1a2b3c4d ? 'be' : 'le';
      } else {
        type = endian === 'le' ? tLE : tBE;
      }
      const blockLen = endian === 'le' ? u32le(head, 4) : u32be(head, 4);
      if (blockLen < 12 || blockLen > file.size) break;
      if (!(await sb.ensure(blockLen))) break;
      const block = sb.take(blockLen);
      const body = block.subarray(8, blockLen - 4);
      const dv = new DataView(block.buffer, block.byteOffset, block.byteLength);
      const isLE = endian === 'le';

      if (type === 0x0a0d0d0a) {
        // Section Header Block: byte order magic at body[0..4]
        result.endian = endian;
        ifaces.length = 0;
      } else if (type === 0x00000001) {
        // Interface Description Block
        const linkType = dv.getUint16(8, isLE);
        const snaplen = dv.getUint32(12, isLE);
        const iface = { linkType: linkType, snaplen: snaplen, tsresol: 1e-6, tsoffset: 0, name: '' };
        parseOptions(body, 8, isLE, function (code, val) {
          if (code === 9 && val.length >= 1) {
            const b = val[0];
            iface.tsresol = (b & 0x80) ? Math.pow(2, -(b & 0x7f)) : Math.pow(10, -b);
          } else if (code === 14 && val.length >= 8) {
            const v = new DataView(val.buffer, val.byteOffset, val.byteLength);
            const hi = v.getUint32(0, isLE), lo = v.getUint32(4, isLE);
            iface.tsoffset = hi * 4294967296 + lo;
          } else if (code === 2) {
            iface.name = asciiOf(val);
          }
        });
        ifaces.push(iface);
        if (ifaces.length === 1) {
          result.linkType = linkType;
          result.linkTypeName = WWL.linkTypeName(linkType);
        }
      } else if (type === 0x00000002 || type === 0x00000006) {
        // Enhanced Packet Block (EPB，规范块类型 0x00000006) 与旧版草案 Packet Block (0x00000002)，
        // 两者的固定头部布局一致：interface_id + ts_high + ts_low + caplen + origlen + data
        // 注意：0x00000004 是 Name Resolution Block（名称解析），不含数据包，直接跳过
        const ifId = dv.getUint32(8, isLE);
        const tsHigh = dv.getUint32(12, isLE);
        const tsLow = dv.getUint32(16, isLE);
        const capLen = dv.getUint32(20, isLE);
        const origLen = dv.getUint32(24, isLE);
        const iface = ifaces[ifId] || ifaces[0] || { linkType: 1, tsresol: 1e-6, tsoffset: 0 };
        const data = body.subarray(20, 20 + Math.min(capLen, body.length - 20));
        num++;
        const tsVal = tsHigh * 4294967296 + tsLow;
        const t = tsVal * iface.tsresol + iface.tsoffset;
        const m = makePacketMeta(num, t, blockStart + 8 + 20, data.length, origLen, iface.linkType, endian, data);
        callbacks.onPacket(m);
        result.packets = num;
      } else if (type === 0x00000003) {
        // Simple Packet Block
        const origLen = dv.getUint32(8, isLE);
        const iface = ifaces[0] || { linkType: 1, tsresol: 1e-6, tsoffset: 0 };
        const data = body.subarray(4);
        num++;
        const t = 0;
        const m = makePacketMeta(num, t, blockStart + 8 + 4, data.length, origLen, iface.linkType, endian, data);
        callbacks.onPacket(m);
        result.packets = num;
      }
      if (++sinceYield >= 2048) {
        sinceYield = 0;
        callbacks.onProgress({ phase: 'parsing', readBytes: sb.pos, totalBytes: file.size, packets: num });
        await nextTick();
      }
    }
    if (callbacks.isCancelled && callbacks.isCancelled()) result.cancelled = true;
    return result;
  }

  function parseOptions(body, offset, isLE, onOption) {
    let p = offset;
    while (p + 4 <= body.length) {
      const code = isLE ? (body[p] | (body[p + 1] << 8)) : ((body[p] << 8) | body[p + 1]);
      const len = isLE ? (body[p + 2] | (body[p + 3] << 8)) : ((body[p + 2] << 8) | body[p + 3]);
      if (code === 0) { p += 4; continue; }
      p += 4;
      if (p + len > body.length) break;
      onOption(code, body.subarray(p, p + len));
      p += len;
      if (p % 4 !== 0) p += 4 - (p % 4);
    }
  }

  function asciiOf(u8) {
    let s = '';
    for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return s;
  }

  /* 统一入口 */
  WWL.Pcap.load = async function (file, callbacks) {
    const detected = await WWL.Pcap.detect(file);
    const cbs = callbacks || {};
    const onProgress = cbs.onProgress || function () {};
    const onPacket = cbs.onPacket || function () {};
    const isCancelled = cbs.isCancelled || function () { return false; };
    const interner = WWL.makeInterner();
    const internerMap = {
      src: interner, dst: interner, mac: interner, proto: interner, info: interner
    };
    const wrapped = function (m) {
      onPacket(internStrings(internerMap)(m));
    };
    if (detected.type === 'pcap') {
      return await loadClassic(file, detected, {
        onPacket: wrapped,
        onProgress: onProgress,
        isCancelled: isCancelled
      });
    }
    if (detected.type === 'pcapng') {
      return await loadNG(file, {
        onPacket: wrapped,
        onProgress: onProgress,
        isCancelled: isCancelled
      });
    }
    throw new Error(detected.reason || '未知文件格式');
  };
})(typeof window !== 'undefined' ? window : globalThis);
