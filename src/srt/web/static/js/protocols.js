/**
 * SRT Protocol-specific Views
 * WiFi, BLE, LoRa tabs with data tables.
 */

const SRTProtocols = (function () {
    let activeTab = 'all';

    function init() {
        // Set up tab button handlers
        var tabBtns = document.querySelectorAll('.tab-btn');
        tabBtns.forEach(function (btn) {
            btn.addEventListener('click', function () {
                switchTab(btn.getAttribute('data-tab'));
            });
        });

        // Listen for WebSocket state updates
        SRTWebSocket.on('state', function (msg) {
            if (msg.data) {
                if (msg.data.wifi) updateWifi(msg.data.wifi);
                if (msg.data.ble) updateBle(msg.data.ble);
                if (msg.data.lora) updateLora(msg.data.lora);
            }
        });

        // Initial data fetch
        fetchProtocolData();
    }

    function switchTab(tab) {
        activeTab = tab;

        // Update button states
        document.querySelectorAll('.tab-btn').forEach(function (btn) {
            btn.classList.toggle('active', btn.getAttribute('data-tab') === tab);
        });

        // Update content visibility
        document.querySelectorAll('.tab-content').forEach(function (content) {
            content.classList.toggle('active', content.id === 'tab-content-' + tab);
        });
    }

    function fetchProtocolData() {
        // Fetch WiFi data
        fetch('/api/wifi/networks')
            .then(function (r) { return r.json(); })
            .then(function (data) { updateWifi({ networks: data.networks || data }); })
            .catch(function () {});

        // Fetch BLE data
        fetch('/api/ble/devices')
            .then(function (r) { return r.json(); })
            .then(function (data) { updateBle({ devices: data.devices || data }); })
            .catch(function () {});

        // Fetch LoRa data
        fetch('/api/lora/devices')
            .then(function (r) { return r.json(); })
            .then(function (data) { updateLora({ devices: data.devices || data }); })
            .catch(function () {});
    }

    function updateWifi(data) {
        var container = document.getElementById('wifi-table-container');
        if (!container) return;

        var networks = data.networks || [];
        if (networks.length === 0) {
            container.innerHTML = '<p class="panel-placeholder">No WiFi networks detected</p>';
            return;
        }

        var html = '<table class="proto-table"><thead><tr>';
        html += '<th>SSID</th><th>BSSID</th><th>CH</th><th>ENC</th><th>RSSI</th>';
        html += '</tr></thead><tbody>';

        networks.forEach(function (net) {
            html += '<tr>';
            html += '<td class="wifi-color">' + escapeHtml(net.ssid || net.SSID || '(hidden)') + '</td>';
            html += '<td class="text-mono">' + escapeHtml(net.bssid || net.BSSID || '-') + '</td>';
            html += '<td>' + (net.channel || net.ch || '-') + '</td>';
            html += '<td>' + escapeHtml(net.encryption || net.enc || '-') + '</td>';
            html += '<td>' + (net.rssi || net.signal || '-') + '</td>';
            html += '</tr>';
        });

        html += '</tbody></table>';
        container.innerHTML = html;
    }

    function updateBle(data) {
        var container = document.getElementById('ble-table-container');
        if (!container) return;

        var devices = data.devices || [];
        if (devices.length === 0) {
            container.innerHTML = '<p class="panel-placeholder">No BLE devices detected</p>';
            return;
        }

        var html = '<table class="proto-table"><thead><tr>';
        html += '<th>NAME</th><th>MAC</th><th>RSSI</th><th>SERVICES</th>';
        html += '</tr></thead><tbody>';

        devices.forEach(function (dev) {
            html += '<tr>';
            html += '<td class="ble-color">' + escapeHtml(dev.name || dev.nom || '(unnamed)') + '</td>';
            html += '<td class="text-mono">' + escapeHtml(dev.mac || dev.address || '-') + '</td>';
            html += '<td>' + (dev.rssi || '-') + '</td>';
            var services = dev.services || dev.service_uuids || [];
            html += '<td>' + (Array.isArray(services) ? services.length : 0) + '</td>';
            html += '</tr>';
        });

        html += '</tbody></table>';
        container.innerHTML = html;
    }

    function updateLora(data) {
        var container = document.getElementById('lora-table-container');
        if (!container) return;

        var devices = data.devices || [];
        if (devices.length === 0) {
            container.innerHTML = '<p class="panel-placeholder">No LoRa devices detected</p>';
            return;
        }

        var html = '<table class="proto-table"><thead><tr>';
        html += '<th>DEV ADDR</th><th>FREQ</th><th>SF</th><th>FRAMES</th>';
        html += '</tr></thead><tbody>';

        devices.forEach(function (dev) {
            html += '<tr>';
            html += '<td class="lora-color text-mono">' + escapeHtml(dev.dev_addr || dev.devaddr || '-') + '</td>';
            html += '<td>' + (dev.frequency || dev.freq || '-') + '</td>';
            html += '<td>' + (dev.spreading_factor || dev.sf || '-') + '</td>';
            html += '<td>' + (dev.frame_count || dev.frames || 0) + '</td>';
            html += '</tr>';
        });

        html += '</tbody></table>';
        container.innerHTML = html;
    }

    function updateAllTab(emitters) {
        var container = document.getElementById('tab-content-all');
        if (!container) return;

        if (!emitters || emitters.length === 0) {
            container.innerHTML = '<p class="panel-placeholder">No emitters detected. Click SCAN to begin.</p>';
            return;
        }

        var html = '<table class="proto-table"><thead><tr>';
        html += '<th>ID</th><th>TYPE</th><th>THREAT</th><th>FREQ</th>';
        html += '</tr></thead><tbody>';

        emitters.forEach(function (em) {
            var id = em.identification || {};
            var cls = em.classification || {};
            var sig = em.signaux || {};
            var threat = (em.menaces && em.menaces.niveau) || cls.niveau_menace || 0;
            var type = cls.type || 'unknown';
            var protocol = getProtocolFromType(type);
            var colorClass = protocol + '-color';
            var freqs = sig.frequences_utilisees || [];

            html += '<tr>';
            html += '<td class="' + colorClass + '">' + escapeHtml(id.nom || id.ssid || id.id || '-') + '</td>';
            html += '<td>' + escapeHtml(type) + '</td>';
            html += '<td style="color:' + getThreatColor(threat) + '">' + threat + '</td>';
            html += '<td class="text-mono">' + (freqs.length > 0 ? freqs[0] + ' MHz' : '-') + '</td>';
            html += '</tr>';
        });

        html += '</tbody></table>';
        container.innerHTML = html;
    }

    function getProtocolFromType(type) {
        if (!type) return 'unknown';
        type = type.toLowerCase();
        if (type.indexOf('wifi') >= 0) return 'wifi';
        if (type.indexOf('ble') >= 0 || type.indexOf('bluetooth') >= 0) return 'ble';
        if (type.indexOf('lora') >= 0) return 'lora';
        return 'unknown';
    }

    function getThreatColor(level) {
        if (level >= 80) return '#ff1744';
        if (level >= 60) return '#ff9100';
        if (level >= 40) return '#ffea00';
        return '#00e676';
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    return {
        init: init,
        switchTab: switchTab,
        fetchProtocolData: fetchProtocolData,
        updateAllTab: updateAllTab
    };
})();
