/**
 * ThreatLoom WebSocket client - real-time event streaming.
 */
class ThreatLoomWS {
    constructor() {
        this.connections = {};
        this.handlers = {};
        this.reconnectDelay = 3000;
    }

    connect(channel, onMessage) {
        const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
        const token = localStorage.getItem('token') || '';
        const url = `${protocol}//${location.host}/ws/${channel}?token=${encodeURIComponent(token)}`;

        const ws = new WebSocket(url);
        this.connections[channel] = ws;
        this.handlers[channel] = onMessage;

        ws.onopen = () => {
            console.log(`[ThreatLoom WS] Connected to ${channel}`);
        };

        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                if (onMessage) onMessage(data);
            } catch (e) {
                console.error('[ThreatLoom WS] Parse error:', e);
            }
        };

        ws.onclose = () => {
            console.log(`[ThreatLoom WS] Disconnected from ${channel}, reconnecting...`);
            setTimeout(() => this.connect(channel, onMessage), this.reconnectDelay);
        };

        ws.onerror = (err) => {
            console.error(`[ThreatLoom WS] Error on ${channel}:`, err);
        };

        // Keepalive ping every 30s
        setInterval(() => {
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'ping' }));
            }
        }, 30000);

        return ws;
    }

    disconnect(channel) {
        if (this.connections[channel]) {
            this.connections[channel].close();
            delete this.connections[channel];
        }
    }

    disconnectAll() {
        Object.keys(this.connections).forEach(ch => this.disconnect(ch));
    }
}

// Global instance
window.threatLoomWS = new ThreatLoomWS();
