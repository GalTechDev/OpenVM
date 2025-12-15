const socket = io('/terminal');

class TerminalManager {
    constructor() {
        this.tabs = {}; // termId -> { term, fitAddon, element, tabElement }
        this.activeId = null;
        this.wrapper = document.getElementById('terminal-wrapper');
        this.tabContainer = document.getElementById('terminalTabs');
        this.btn = this.tabContainer.querySelector('.add-tab-btn');

        // Socket Events
        socket.on('connect', () => {
            console.log('Socket Connected');
            this.reconnectTabs();
            // Hide loading overlay
            const loader = document.getElementById('loadingOverlay');
            if (loader) loader.style.display = 'none';
        });

        socket.on('connect_error', () => {
            // Hide loading overlay even on error
            const loader = document.getElementById('loadingOverlay');
            if (loader) loader.style.display = 'none';
        });

        socket.on('output', (payload) => {
            // payload = { term_id, data }
            const { term_id, data } = payload;
            if (this.tabs[term_id]) {
                this.tabs[term_id].term.write(data);
            }
        });

        // Window Resize
        window.addEventListener('resize', () => {
            if (this.activeId && this.tabs[this.activeId]) {
                const { fitAddon } = this.tabs[this.activeId];
                fitAddon.fit();
                this.emitResize(this.activeId);
            }
        });

        // Initial setup
        this.loadFromStorage();
    }

    generateId() {
        if (crypto && crypto.randomUUID) {
            return crypto.randomUUID();
        }
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
            var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }

    addTab(termId = null) {
        const id = termId || this.generateId();
        const activeContainerId = document.getElementById('activeContainerId') ? document.getElementById('activeContainerId').value : null;

        if (!activeContainerId) {
            console.error("No active container ID found.");
            return;
        }

        // DOM Element for Terminal
        const termDiv = document.createElement('div');
        termDiv.style.width = '100%';
        termDiv.style.height = '100%';
        termDiv.style.display = 'none'; // Hidden by default
        this.wrapper.appendChild(termDiv);

        // Xterm Setup
        const term = new Terminal({
            cursorBlink: true,
            cursorStyle: 'bar',
            fontFamily: '"JetBrains Mono", "Fira Code", monospace',
            fontSize: 14,
            theme: { background: '#0a0a0a', foreground: '#f8fafc' }
        });
        const fitAddon = new FitAddon.FitAddon();
        term.loadAddon(fitAddon);
        term.open(termDiv);

        // Input Handler
        term.onData(data => {
            socket.emit('input', { term_id: id, data: data });
        });

        // Tab UI Element
        const tabEl = document.createElement('div');
        tabEl.className = 'term-tab';
        tabEl.innerHTML = `Term ${Object.keys(this.tabs).length + 1} <span class="close-tab" onclick="terminalManager.closeTab('${id}', event)">&times;</span>`;
        tabEl.onclick = (e) => {
            if (e.target.classList.contains('close-tab')) return;
            this.switchTab(id);
        };
        this.tabContainer.insertBefore(tabEl, this.btn);

        // Store
        this.tabs[id] = { term, fitAddon, element: termDiv, tabElement: tabEl, id: id };

        // Switch to new tab
        this.switchTab(id);

        // Start Backend Session
        // Wait for next tick to ensure fit
        setTimeout(() => {
            fitAddon.fit();
            const dims = fitAddon.proposeDimensions();
            socket.emit('start_terminal', {
                term_id: id,
                container_id: activeContainerId,
                cols: dims ? dims.cols : 80,
                rows: dims ? dims.rows : 24
            });
        }, 100);

        this.saveToStorage();
    }

    switchTab(id) {
        if (!this.tabs[id]) return;

        // Hide current
        if (this.activeId && this.tabs[this.activeId]) {
            this.tabs[this.activeId].element.style.display = 'none';
            this.tabs[this.activeId].tabElement.classList.remove('active');
        }

        // Show new
        this.activeId = id;
        const target = this.tabs[id];
        target.element.style.display = 'block';
        target.tabElement.classList.add('active');

        target.fitAddon.fit();
        target.term.focus();

        // Emit resize just in case
        setTimeout(() => this.emitResize(id), 50);
        this.saveToStorage();
    }

    closeTab(id, event) {
        if (event) event.stopPropagation();
        if (!this.tabs[id]) return;

        const target = this.tabs[id];
        target.term.dispose();
        target.element.remove();
        target.tabElement.remove();

        delete this.tabs[id];

        if (this.activeId === id) {
            const keys = Object.keys(this.tabs);
            if (keys.length > 0) {
                this.switchTab(keys[keys.length - 1]);
            } else {
                this.activeId = null;
            }
        }
        this.saveToStorage();
    }

    emitResize(id) {
        if (!this.tabs[id]) return;
        const { fitAddon } = this.tabs[id];
        const dims = fitAddon.proposeDimensions();
        if (dims) {
            socket.emit('resize', { term_id: id, cols: dims.cols, rows: dims.rows });
        }
    }

    saveToStorage() {
        const keys = Object.keys(this.tabs);
        const activeContainerId = document.getElementById('activeContainerId') ? document.getElementById('activeContainerId').value : 'default';
        localStorage.setItem(`openvm_tabs_${activeContainerId}`, JSON.stringify(keys));
        localStorage.setItem(`openvm_active_tab_${activeContainerId}`, this.activeId);
    }

    loadFromStorage() {
        const activeContainerId = document.getElementById('activeContainerId') ? document.getElementById('activeContainerId').value : 'default';
        const storedTabs = JSON.parse(localStorage.getItem(`openvm_tabs_${activeContainerId}`) || '[]');
        const storedActive = localStorage.getItem(`openvm_active_tab_${activeContainerId}`);

        if (storedTabs.length > 0) {
            storedTabs.forEach(id => this.addTab(id));
            if (storedActive && this.tabs[storedActive]) {
                this.switchTab(storedActive);
            }
        } else {
            this.addTab(); // Default one
        }
    }

    reconnectTabs() {
        // Called on socket reconnect
        Object.keys(this.tabs).forEach(id => {
            const activeContainerId = document.getElementById('activeContainerId') ? document.getElementById('activeContainerId').value : null;
            // Re-emit start_terminal to rejoin room and replay history
            socket.emit('start_terminal', {
                term_id: id,
                container_id: activeContainerId
            });
        });
    }
}

// Global Instance
let terminalManager;
document.addEventListener('DOMContentLoaded', () => {
    if (document.getElementById('terminal-wrapper')) {
        terminalManager = new TerminalManager();
    }
});

// Legacy Helpers for Dashboard buttons (if we keep them)
function fitTerminal() {
    if (terminalManager && terminalManager.activeId) {
        const t = terminalManager.tabs[terminalManager.activeId];
        t.fitAddon.fit();
        terminalManager.emitResize(terminalManager.activeId);
        t.term.focus();
    }
}

function clearTerminal() {
    if (terminalManager && terminalManager.activeId) {
        terminalManager.tabs[terminalManager.activeId].term.clear();
    }
}

async function controlContainer(action) {
    if (!await showConfirm('Container Action', `Are you sure you want to ${action} the container?`)) return;

    const activeContainerId = document.getElementById('activeContainerId') ? document.getElementById('activeContainerId').value : null;

    fetch(`/api/container/${action}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ container_id: activeContainerId })
    })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                alert('Error: ' + data.error);
            } else {
                // Update status badge
                const badge = document.getElementById('status-badge');
                if (badge) {
                    badge.className = `status-badge ${data.new_status}`;
                    badge.innerHTML = `<span class="dot"></span> ${data.new_status}`;
                }
            }
        })
        .catch(error => console.error('Error:', error));
}
