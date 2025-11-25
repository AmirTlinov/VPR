// VPR TUI Bridge - xterm.js integration
// Renders TUI from Rust backend via Tauri IPC

const { invoke } = window.__TAURI__.core;

class TuiBridge {
    constructor(container) {
        this.container = container;
        this.terminal = null;
        this.fitAddon = null;
        this.running = false;
        this.tickInterval = null;
        this.renderInterval = null;
        this.width = 80;
        this.height = 24;
    }

    async init() {
        // Create terminal element
        this.terminalDiv = document.createElement('div');
        this.terminalDiv.id = 'tui-terminal';
        this.terminalDiv.style.cssText = `
            width: 100%;
            height: 100%;
            background: #0a0a0a;
        `;
        this.container.appendChild(this.terminalDiv);

        // Initialize xterm.js
        this.terminal = new Terminal({
            cursorBlink: false,
            cursorStyle: 'block',
            disableStdin: true,
            fontFamily: '"Fira Code", "JetBrains Mono", monospace',
            fontSize: 14,
            lineHeight: 1.1,
            theme: {
                background: '#0a0a0a',
                foreground: '#00ff9c',
                cursor: '#00ff9c',
                cursorAccent: '#0a0a0a',
                black: '#0a0a0a',
                red: '#ff4444',
                green: '#00ff9c',
                yellow: '#ffcc00',
                blue: '#00bfff',
                magenta: '#ff00ff',
                cyan: '#00ffff',
                white: '#ffffff',
                brightBlack: '#555555',
                brightRed: '#ff6666',
                brightGreen: '#00ffaa',
                brightYellow: '#ffdd33',
                brightBlue: '#33ccff',
                brightMagenta: '#ff33ff',
                brightCyan: '#33ffff',
                brightWhite: '#ffffff',
            },
            allowTransparency: true,
            scrollback: 0,
            convertEol: true,
        });

        // Load fit addon
        this.fitAddon = new FitAddon.FitAddon();
        this.terminal.loadAddon(this.fitAddon);

        // Open terminal
        this.terminal.open(this.terminalDiv);
        this.fitAddon.fit();

        // Get dimensions
        this.updateDimensions();

        // Handle resize
        window.addEventListener('resize', () => this.handleResize());

        // Handle keyboard input
        this.terminal.onKey(({ key, domEvent }) => this.handleKey(domEvent));
        document.addEventListener('keydown', (e) => this.handleKeyDown(e));

        console.log('[TUI] Initialized xterm.js terminal');
    }

    updateDimensions() {
        this.width = this.terminal.cols;
        this.height = this.terminal.rows;
        console.log(`[TUI] Dimensions: ${this.width}x${this.height}`);
    }

    handleResize() {
        if (this.fitAddon) {
            this.fitAddon.fit();
            this.updateDimensions();
            // Immediate re-render after resize
            this.renderFrame();
        }
    }

    async handleKey(event) {
        // Prevent default browser behavior
        event.preventDefault();
        event.stopPropagation();

        const key = this.domEventToKey(event);
        if (key) {
            try {
                const shouldContinue = await invoke('tui_key', { key });
                if (!shouldContinue && key === 'q') {
                    // User pressed Q on main screen - could close app
                    console.log('[TUI] Quit requested');
                }
                // Re-render after key press
                await this.renderFrame();
            } catch (e) {
                console.error('[TUI] Key handling error:', e);
            }
        }
    }

    handleKeyDown(event) {
        // Handle special keys that xterm might not capture
        const specialKeys = ['Escape', 'F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8', 'F9', 'F10', 'F11', 'F12'];
        if (specialKeys.includes(event.key) || (event.ctrlKey || event.altKey)) {
            event.preventDefault();
            this.handleKey(event);
        }
    }

    domEventToKey(event) {
        // Map DOM keyboard events to key names for Rust
        const keyMap = {
            'Enter': 'Enter',
            'Escape': 'Escape',
            'Backspace': 'Backspace',
            'Tab': 'Tab',
            'Delete': 'Delete',
            'ArrowUp': 'Up',
            'ArrowDown': 'Down',
            'ArrowLeft': 'Left',
            'ArrowRight': 'Right',
            'Home': 'Home',
            'End': 'End',
            'PageUp': 'PageUp',
            'PageDown': 'PageDown',
            'F1': 'F1',
            'F2': 'F2',
            'F3': 'F3',
            'F4': 'F4',
            'F5': 'F5',
            'F6': 'F6',
            'F7': 'F7',
            'F8': 'F8',
            'F9': 'F9',
            'F10': 'F10',
            'F11': 'F11',
            'F12': 'F12',
            ' ': 'Space',
        };

        if (keyMap[event.key]) {
            return keyMap[event.key];
        }

        // Single character keys
        if (event.key.length === 1) {
            return event.key;
        }

        return null;
    }

    async renderFrame() {
        try {
            const ansi = await invoke('tui_render', {
                width: this.width,
                height: this.height
            });
            
            // Clear and write new content
            this.terminal.reset();
            this.terminal.write(ansi);
        } catch (e) {
            console.error('[TUI] Render error:', e);
        }
    }

    async tick() {
        try {
            await invoke('tui_tick');
        } catch (e) {
            console.error('[TUI] Tick error:', e);
        }
    }

    start() {
        if (this.running) return;
        this.running = true;

        // Animation tick - 30 FPS for smooth globe animation
        this.tickInterval = setInterval(() => this.tick(), 33);

        // Render frames - 15 FPS for display
        this.renderInterval = setInterval(() => this.renderFrame(), 66);

        // Initial render
        this.renderFrame();

        console.log('[TUI] Started render loop');
    }

    stop() {
        this.running = false;
        if (this.tickInterval) {
            clearInterval(this.tickInterval);
            this.tickInterval = null;
        }
        if (this.renderInterval) {
            clearInterval(this.renderInterval);
            this.renderInterval = null;
        }
        console.log('[TUI] Stopped render loop');
    }

    destroy() {
        this.stop();
        if (this.terminal) {
            this.terminal.dispose();
            this.terminal = null;
        }
        if (this.terminalDiv) {
            this.terminalDiv.remove();
            this.terminalDiv = null;
        }
    }
}

// Global TUI instance
let tuiBridge = null;

// Initialize TUI when document loads
document.addEventListener('DOMContentLoaded', async () => {
    // Check if we're in TUI mode
    const urlParams = new URLSearchParams(window.location.search);
    const tuiMode = urlParams.get('tui') === '1';

    if (tuiMode) {
        const container = document.getElementById('tui-container');
        if (container) {
            tuiBridge = new TuiBridge(container);
            await tuiBridge.init();
            tuiBridge.start();
        }
    }
});

// Export for manual control
window.TuiBridge = TuiBridge;
window.getTuiBridge = () => tuiBridge;
