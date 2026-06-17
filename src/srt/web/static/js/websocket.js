/**
 * SRT WebSocket Client Manager
 * Handles connection to /ws/live with reconnection and message dispatch.
 */

const SRTWebSocket = (function () {
    let ws = null;
    let reconnectAttempts = 0;
    const maxReconnectAttempts = 20;
    const baseDelay = 1000;
    const handlers = {};
    let connected = false;

    function getWsUrl() {
        const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        return proto + '//' + window.location.host + '/ws/live';
    }

    function connect() {
        if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
            return;
        }

        try {
            ws = new WebSocket(getWsUrl());
        } catch (e) {
            console.error('[WS] Failed to create WebSocket:', e);
            scheduleReconnect();
            return;
        }

        ws.onopen = function () {
            console.log('[WS] Connected');
            reconnectAttempts = 0;
            connected = true;
            updateStatusIndicator(true);
            dispatch('connection', { status: 'connected' });

            // Request initial state
            send({ type: 'get_state' });
        };

        ws.onmessage = function (event) {
            try {
                const msg = JSON.parse(event.data);
                dispatch('message', msg);

                // Route by type
                if (msg.type) {
                    dispatch(msg.type, msg);
                }

                // Route by topic
                if (msg.topic) {
                    dispatch('topic:' + msg.topic, msg);
                    // Also dispatch by topic prefix
                    const parts = msg.topic.split('/');
                    if (parts.length >= 2) {
                        dispatch('topic_prefix:' + parts[0] + '/' + parts[1], msg);
                    }
                }
            } catch (e) {
                console.warn('[WS] Failed to parse message:', event.data);
            }
        };

        ws.onclose = function (event) {
            console.log('[WS] Disconnected (code=' + event.code + ')');
            connected = false;
            updateStatusIndicator(false);
            dispatch('connection', { status: 'disconnected' });
            scheduleReconnect();
        };

        ws.onerror = function (err) {
            console.error('[WS] Error:', err);
            connected = false;
            updateStatusIndicator(false);
        };
    }

    function scheduleReconnect() {
        if (reconnectAttempts >= maxReconnectAttempts) {
            console.warn('[WS] Max reconnect attempts reached');
            return;
        }
        // Exponential backoff with jitter
        const delay = Math.min(baseDelay * Math.pow(2, reconnectAttempts), 30000);
        const jitter = delay * 0.3 * Math.random();
        reconnectAttempts++;
        console.log('[WS] Reconnecting in ' + Math.round(delay + jitter) + 'ms (attempt ' + reconnectAttempts + ')');
        setTimeout(connect, delay + jitter);
    }

    function send(data) {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(data));
        }
    }

    function on(event, handler) {
        if (!handlers[event]) {
            handlers[event] = [];
        }
        handlers[event].push(handler);
    }

    function off(event, handler) {
        if (handlers[event]) {
            handlers[event] = handlers[event].filter(function (h) { return h !== handler; });
        }
    }

    function dispatch(event, data) {
        if (handlers[event]) {
            handlers[event].forEach(function (h) {
                try {
                    h(data);
                } catch (e) {
                    console.error('[WS] Handler error for event "' + event + '":', e);
                }
            });
        }
    }

    function updateStatusIndicator(isConnected) {
        const el = document.getElementById('nav-status');
        if (!el) return;
        if (isConnected) {
            el.className = 'status-indicator status-connected';
            el.querySelector('.status-text').textContent = 'CONNECTED';
        } else {
            el.className = 'status-indicator status-disconnected';
            el.querySelector('.status-text').textContent = 'DISCONNECTED';
        }
    }

    function isConnected() {
        return connected;
    }

    return {
        connect: connect,
        send: send,
        on: on,
        off: off,
        isConnected: isConnected
    };
})();
