// Хакерский ASCII рендерер в стиле Watch Dogs 2

// Компактный Doge
const DOGE = `
    ▄              ▄
   ▌▒█           ▄▀▒▌
   ▌▒▒█        ▄▀▒▒▒▐
  ▐▄▀▒▒▀▀▀▀▄▄▄▀▒▒▒▒▒▐
 ▄▀▒▒▒░░░▒▒▒▒▒▒█▒▒▄█▒▐
▐▒▒▒▄▄▒▒▒▒░░░▒▒▒▒▒▀▄▒▒
▌░░▌█▀▒▒▒▒▄▀█▄▒▒▒▒▒█▒▐
▐░░░▒▒▒▒▒▒▌██▀▒▒░░░▒▒▀
▌░▒▄██▄▒▒▒▒▒▒░░░░░░▒▒▒
 ▀▄▒▒▒▒▒▒▒▒▒▒▄▄▄▀▒▒▒▄▀
   ▀▀▀▀▀▀▀▀▀▀▀`;

// Компактный Skull
const SKULL = `
    ▄▄▄▄▄▄▄▄▄
  ▄███████████▄
 ███▀▀▀▀▀▀▀███
 ██  ▄▄ ▄▄  ██
 ██  ▀▀ ▀▀  ██
 ██    ▄    ██
 ██  ▀███▀  ██
  ▀█▄▄▄▄▄▄▄█▀
    ▀▀▀▀▀▀▀`;

// Компактная DedSec маска
const DEDSEC = `
   ▄▄▄▄▄▄▄▄▄
  █░░░░░░░░░█
 █░▄▄░░░░▄▄░█
 █░▀▀░░░░▀▀░█
 █░░░░▄▄░░░░█
 █░░░█▄▄█░░░█
  █░▀▄▄▄▄▀░█
   ▀▀▀▀▀▀▀▀▀`;

// Хакерские сообщения (короткие)
const HACKER_MESSAGES = [
  "NEURAL LINK ACTIVE...",
  "BYPASSING FIREWALL...",
  "INJECTING PAYLOAD...",
  "DECRYPTING CHANNEL...",
  "SPOOFING LOCATION...",
  "STEALTH MODE ON...",
  "COVERT TUNNEL...",
  "DARK NODE ROUTING...",
  "QUANTUM ENCRYPT...",
  "DPI EVASION...",
  "HACK THE PLANET!",
  "WE ARE DEDSEC",
];

// Doge сообщения
const DOGE_MESSAGES = [
  "wow", "such vpn", "much secure", "very encrypt",
  "so stealth", "many packets", "wow tunnel",
  "such privacy", "very anon", "much freedom",
];

// Глитч символы
const GLITCH_CHARS = '█▓▒░▄▀▌▐│┤╡╢╣║╗╝┐└┴┬├─┼╚╔╩╦╠═╬';

class GlobeRenderer {
  constructor(element, width = 40, height = 15) {
    this.element = element;
    this.width = width;
    this.height = height;
    this.timer = null;
    this.frame = 0;
    this.artIndex = 0;
    this.messageIndex = 0;
    this.tick = 0;
  }

  glitch(text, intensity = 0.1) {
    return text.split('').map(c => {
      if (c !== ' ' && c !== '\n' && Math.random() < intensity) {
        return GLITCH_CHARS[Math.floor(Math.random() * GLITCH_CHARS.length)];
      }
      return c;
    }).join('');
  }

  getArt() {
    const arts = [DOGE, SKULL, DEDSEC];
    return arts[this.artIndex % arts.length];
  }

  getMessage() {
    if (this.artIndex % 3 === 0) {
      const msg1 = DOGE_MESSAGES[this.messageIndex % DOGE_MESSAGES.length];
      const msg2 = DOGE_MESSAGES[(this.messageIndex + 3) % DOGE_MESSAGES.length];
      return `// ${msg1}. ${msg2}.`;
    }
    return HACKER_MESSAGES[this.messageIndex % HACKER_MESSAGES.length];
  }

  getSpinner() {
    const frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    return frames[this.tick % frames.length];
  }

  render() {
    this.tick++;
    
    if (this.tick % 80 === 0) this.artIndex++;
    if (this.tick % 25 === 0) this.messageIndex++;

    let art = this.getArt();
    
    if (this.tick % 40 < 2) {
      art = this.glitch(art, 0.12);
    }

    return `${this.getSpinner()} ${this.getMessage()}\n${art}`;
  }

  start() {
    if (this.timer) return;
    this.timer = setInterval(() => {
      this.element.textContent = this.render();
      this.frame++;
    }, 80);
  }

  stop() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }
}

window.GlobeRenderer = GlobeRenderer;
window.DOGE = DOGE;
window.SKULL = SKULL;
window.DEDSEC = DEDSEC;
