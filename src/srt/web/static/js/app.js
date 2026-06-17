/**
 * SRT Main Application Controller
 * Initializes all components and manages application state.
 */

const SRTApp = (function () {
    let refreshInterval = null;
    const REFRESH_MS = 5000; // Auto-refresh every 5 seconds

    function init() {
        console.log('[SRT] Initializing Tactical RF Platform...');

        // Initialize WebSocket connection
        SRTWebSocket.connect();

        // Initialize map
        SRTMap.init();

        // Initialize panels
        SRTModules.init();
        SRTProtocols.init();
        SRTAlerts.init();
        SRTSpectrum.init();
        SRTScenarios.init();
        SRTRealtime.init();

        // Set up scan button
        var scanBtn = document.getElementById('btn-scan');
        if (scanBtn) {
            scanBtn.addEventListener('click', triggerScan);
        }

        // Listen for state updates from WebSocket
        SRTWebSocket.on('state', function (msg) {
            if (msg.data && msg.data.emitters) {
                SRTMap.updateEmitters(msg.data.emitters);
                SRTProtocols.updateAllTab(msg.data.emitters);
            }
        });

        // Auto-refresh cartography data
        refreshInterval = setInterval(refreshCartography, REFRESH_MS);

        // Initial data load
        refreshCartography();

        console.log('[SRT] Platform ready.');
    }

    function triggerScan() {
        var scanBtn = document.getElementById('btn-scan');
        if (scanBtn) {
            scanBtn.classList.add('scanning');
            scanBtn.disabled = true;
            scanBtn.textContent = '\u23F3 SCANNING...';
        }

        fetch('/api/cartography/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        })
            .then(function (res) { return res.json(); })
            .then(function (data) {
                console.log('[SRT] Scan complete:', data);

                // Process results
                if (data.nouveaux_emetteurs || data.signaux_detectes) {
                    refreshCartography();
                }

                // Process alerts from scan
                if (data.alertes && data.alertes.length > 0) {
                    data.alertes.forEach(function (alert) {
                        SRTAlerts.addAlert(alert);
                    });
                }

                // Refresh all data
                SRTAlerts.fetchAlerts();
                SRTSpectrum.fetchBands();
                SRTProtocols.fetchProtocolData();
            })
            .catch(function (err) {
                console.error('[SRT] Scan failed:', err);
            })
            .finally(function () {
                if (scanBtn) {
                    scanBtn.classList.remove('scanning');
                    scanBtn.disabled = false;
                    scanBtn.textContent = '\u23F3 SCAN';
                }
            });
    }

    function refreshCartography() {
        // Fetch emitters
        fetch('/api/cartography/emitters')
            .then(function (res) { return res.json(); })
            .then(function (data) {
                var emitters = data.emitters || data || [];
                SRTMap.updateEmitters(emitters);
                SRTProtocols.updateAllTab(emitters);
            })
            .catch(function () {});

        // Fetch stats
        fetch('/api/cartography/stats')
            .then(function (res) { return res.json(); })
            .then(function (data) {
                var stats = data.stats || data || {};
                var el = document.getElementById('stat-emitters');
                if (el && stats.nb_emetteurs_uniques !== undefined) {
                    el.textContent = stats.nb_emetteurs_uniques;
                }
            })
            .catch(function () {});
    }

    // Start the app when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    return {
        triggerScan: triggerScan,
        refreshCartography: refreshCartography
    };
})();
