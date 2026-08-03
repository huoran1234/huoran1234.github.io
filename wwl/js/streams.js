/* streams.js - TCP 会话聚合（按 4 元组） */
(function (global) {
  'use strict';
  const WWL = global.WWL = global.WWL || {};

  WWL.Streams = {
    compute: function (packets) {
      const map = new Map();
      for (let i = 0; i < packets.length; i++) {
        const p = packets[i];
        if (p.tproto !== 'tcp' || !p.sport || !p.dport || !p.src || !p.dst) continue;
        const a = p.src + ':' + p.sport;
        const b = p.dst + ':' + p.dport;
        let key, forward; // forward: a->b
        if (a <= b) { key = a + '|' + b; forward = true; }
        else { key = b + '|' + a; forward = false; }
        let s = map.get(key);
        if (!s) {
          s = {
            id: map.size + 1,
            a: a <= b ? a : b,
            b: a <= b ? b : a,
            packets: 0,
            bytesAB: 0,
            bytesBA: 0,
            first: p.t,
            last: p.t
          };
          map.set(key, s);
        }
        s.packets++;
        if (forward) s.bytesAB += p.len;
        else s.bytesBA += p.len;
        if (p.t < s.first) s.first = p.t;
        if (p.t > s.last) s.last = p.t;
      }
      const list = [];
      map.forEach(function (s) { list.push(s); });
      list.sort(function (x, y) { return x.first - y.first || x.id - y.id; });
      return list;
    }
  };
})(typeof window !== 'undefined' ? window : globalThis);
