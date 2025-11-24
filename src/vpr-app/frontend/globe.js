class GlobeRenderer {
  constructor(element, width = 50, height = 25) {
    this.element = element;
    this.width = width;
    this.height = height;
    this.timer = null;
    this.frame = 0;
    this.frames = [
      this._frame('─', '│', '┼'),
      this._frame('·', '•', '+'),
      this._frame('∙', '°', '•'),
      this._frame('•', '·', '·'),
    ];
  }

  _frame(h, v, c) {
    // Very lightweight ASCII globe placeholder
    const top = `   ${h.repeat(this.width - 6)}`;
    const middle = `${v} ${' '.repeat(this.width - 4)} ${v}`;
    const center = `${v} ${c.repeat(this.width - 4)} ${v}`;
    const lines = [top];
    for (let i = 0; i < this.height - 4; i++) {
      lines.push(i === Math.floor((this.height - 4) / 2) ? center : middle);
    }
    lines.push(top);
    return lines.join('\n');
  }

  start() {
    if (this.timer) return;
    this.timer = setInterval(() => {
      this.element.textContent = this.frames[this.frame];
      this.frame = (this.frame + 1) % this.frames.length;
    }, 200);
  }

  stop() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }
}
