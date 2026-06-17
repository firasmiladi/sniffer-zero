/**
 * SRT Alert Feed Component
 * Displays real-time alerts color-coded by severity.
 */

const SRTAlerts = (function () {
    let alertsEl = null;
    let alerts = [];
    const maxAlerts = 50;

    function init() {
        alertsEl = document.getElementById('alerts-panel');
        fetchAlerts();

        // Listen for WebSocket alert messages
        SRTWebSocket.on('message', function (msg) {
            if (msg.type === 'alert' || (msg.topic && msg.topic.indexOf('srt/alerts') >= 0)) {
                addAlert(msg.data || msg.payload || msg);
            }
            // Also pick up alerts from state updates
            if (msg.type === 'state' && msg.data && msg.data.alerts) {
                updateAlerts(msg.data.alerts);
            }
        });
    }

    function fetchAlerts() {
        fetch('/api/cartography/alerts')
            .then(function (res) { return res.json(); })
            .then(function (data) {
                var alertList = data.alerts || data || [];
                updateAlerts(alertList);
            })
            .catch(function (err) {
                console.error('[Alerts] Failed to fetch:', err);
            });
    }

    function updateAlerts(alertList) {
        if (!Array.isArray(alertList)) return;
        alerts = alertList.slice(0, maxAlerts);
        render();
        updateAlertCount();
    }

    function addAlert(alert) {
        if (!alert) return;
        alerts.unshift(alert);
        if (alerts.length > maxAlerts) {
            alerts = alerts.slice(0, maxAlerts);
        }
        render();
        updateAlertCount();
    }

    function updateAlertCount() {
        var el = document.getElementById('stat-alerts');
        if (el) el.textContent = alerts.length;
    }

    function getSeverityClass(alert) {
        var level = alert.niveau_menace || alert.severity || alert.level || 0;
        var type = (alert.type || '').toLowerCase();

        if (type === 'critique' || type === 'critical' || level >= 80) return 'alert-critical';
        if (type === 'haute' || type === 'high' || level >= 60) return 'alert-high';
        if (type === 'moyenne' || type === 'medium' || level >= 40) return 'alert-medium';
        return 'alert-low';
    }

    function formatTime(timestamp) {
        if (!timestamp) return '--:--:--';
        try {
            var d = new Date(timestamp);
            if (isNaN(d.getTime())) return timestamp;
            return d.toLocaleTimeString('en-US', { hour12: false });
        } catch (e) {
            return timestamp;
        }
    }

    function render() {
        if (!alertsEl) return;

        if (alerts.length === 0) {
            alertsEl.innerHTML = '<p class="panel-placeholder">No alerts. System nominal.</p>';
            return;
        }

        var html = '';
        alerts.forEach(function (alert) {
            var severityClass = getSeverityClass(alert);
            var type = alert.type || 'unknown';
            var desc = alert.description || alert.message || '';
            var time = formatTime(alert.timestamp);
            var emitter = alert.emetteur_id || alert.emitter || '';

            html += '<div class="alert-item ' + severityClass + '">';
            html += '  <div class="alert-header">';
            html += '    <span class="alert-type">' + escapeHtml(type) + '</span>';
            html += '    <span class="alert-time">' + escapeHtml(time) + '</span>';
            html += '  </div>';
            html += '  <div class="alert-desc">';
            if (emitter) {
                html += '<span class="text-mono">[' + escapeHtml(emitter) + ']</span> ';
            }
            html += escapeHtml(desc);
            html += '  </div>';
            html += '</div>';
        });

        alertsEl.innerHTML = html;
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    return {
        init: init,
        fetchAlerts: fetchAlerts,
        addAlert: addAlert
    };
})();
