/* vlist.js - 虚拟滚动列表：只渲染可视区域内的行，支持百万级数据包 */
(function (global) {
  'use strict';
  const WWL = global.WWL = global.WWL || {};

  WWL.VirtualList = function (container, rowHeight) {
    this.container = container;
    this.rowH = rowHeight || 24;
    this.count = 0;
    this.renderRow = null;
    this.onClick = null;
    this.pool = [];

    this.spacer = document.createElement('div');
    this.spacer.className = 'vlist-spacer';
    this.container.appendChild(this.spacer);

    const self = this;
    this.container.addEventListener('scroll', function () {
      self.render();
    });
    this.spacer.addEventListener('click', function (e) {
      const el = e.target.closest('.pkt-row');
      if (el && self.onClick) {
        self.onClick(parseInt(el.dataset.index, 10), e);
      }
    });
  };

  WWL.VirtualList.prototype.setCount = function (n) {
    this.count = Math.max(0, n | 0);
    this.spacer.style.height = (this.count * this.rowH) + 'px';
    if (!this.count) {
      for (let i = this.pool.length - 1; i >= 0; i--) {
        this.pool[i].remove();
      }
      this.pool.length = 0;
    }
    this.render();
  };

  WWL.VirtualList.prototype.setRenderRow = function (fn) {
    this.renderRow = fn;
  };

  WWL.VirtualList.prototype.render = function () {
    const n = this.count;
    if (!n) {
      for (let i = 0; i < this.pool.length; i++) this.pool[i].remove();
      this.pool.length = 0;
      return;
    }
    const vh = this.container.clientHeight || 300;
    const scrollTop = this.container.scrollTop;
    const start = Math.max(0, Math.floor(scrollTop / this.rowH) - 6);
    const end = Math.min(n, Math.ceil((scrollTop + vh) / this.rowH) + 6);
    // 卸载当前所有行；池中元素全部处于游离状态，可安全复用
    while (this.spacer.firstChild) this.spacer.removeChild(this.spacer.firstChild);
    const free = this.pool;
    this.pool = [];
    for (let i = start; i < end; i++) {
      let el = free.pop();
      if (!el) {
        el = document.createElement('div');
      }
      el.className = 'pkt-row';
      el.dataset.index = i;
      el.style.top = (i * this.rowH) + 'px';
      if (this.renderRow) this.renderRow(i, el);
      this.spacer.appendChild(el);
      this.pool.push(el);
    }
  };
})(typeof window !== 'undefined' ? window : globalThis);
