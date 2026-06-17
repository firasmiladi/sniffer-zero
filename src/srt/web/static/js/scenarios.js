/**
 * SRT Scenarios Panel
 * Fetches and renders scenarios grouped by category, with launch and progress tracking.
 */

const SRTScenarios = (function () {
    let panelEl = null;
    let scenarios = [];

    function init() {
        panelEl = document.getElementById('scenarios-panel');
        fetchScenarios();

        // Listen for scenario progress messages from WebSocket
        SRTWebSocket.on('scenario_progress', function (msg) {
            handleProgress(msg);
        });
    }

    function fetchScenarios() {
        fetch('/api/scenarios')
            .then(function (res) { return res.json(); })
            .then(function (data) {
                scenarios = data || [];
                render(scenarios);
            })
            .catch(function (err) {
                console.error('[Scenarios] Failed to fetch:', err);
                if (panelEl) {
                    panelEl.innerHTML = '<p class="panel-placeholder">Scenarios unavailable</p>';
                }
            });
    }

    function render(list) {
        if (!panelEl) return;
        if (!list || list.length === 0) {
            panelEl.innerHTML = '<p class="panel-placeholder">No scenarios available</p>';
            return;
        }

        // Group by category
        var groups = {};
        list.forEach(function (sc) {
            var cat = sc.category || 'other';
            if (!groups[cat]) groups[cat] = [];
            groups[cat].push(sc);
        });

        var html = '';
        var categoryLabels = {
            recon: 'Reconnaissance',
            survey: 'Survey',
            continuous: 'Monitoring',
            cartographie: 'Cartography',
            wifi: 'WiFi',
            ble: 'BLE',
            lora: 'LoRa',
            full: 'Full Audit',
            other: 'Other'
        };

        Object.keys(groups).forEach(function (cat) {
            var label = categoryLabels[cat] || cat.toUpperCase();
            html += '<div class="scenario-group">';
            html += '<div class="scenario-group-label">' + escapeHtml(label) + '</div>';

            groups[cat].forEach(function (sc) {
                var desc = sc.description || '';
                if (desc.length > 60) desc = desc.substring(0, 60) + '...';

                html += '<div class="scenario-card" data-name="' + escapeHtml(sc.name) + '">';
                html += '  <div class="scenario-card-header">';
                html += '    <span class="scenario-name">' + escapeHtml(sc.name) + '</span>';
                html += '    <span class="scenario-status-badge" id="badge-' + escapeHtml(sc.name) + '"></span>';
                html += '  </div>';
                html += '  <div class="scenario-desc">' + escapeHtml(desc) + '</div>';
                html += '  <div class="scenario-card-footer">';
                html += '    <span class="scenario-steps-count">' + sc.steps_count + ' steps</span>';
                html += '    <button class="btn-launch btn-scenario-launch" data-scenario="' + escapeHtml(sc.name) + '">LAUNCH</button>';
                html += '  </div>';
                html += '  <div class="scenario-progress-bar" id="progress-' + escapeHtml(sc.name) + '" style="display:none">';
                html += '    <div class="scenario-progress-fill"></div>';
                html += '  </div>';
                html += '</div>';
            });

            html += '</div>';
        });

        panelEl.innerHTML = html;

        // Attach launch button handlers
        var buttons = panelEl.querySelectorAll('.btn-scenario-launch');
        buttons.forEach(function (btn) {
            btn.addEventListener('click', function () {
                var name = btn.getAttribute('data-scenario');
                launchScenario(name);
            });
        });
    }

    function launchScenario(name) {
        // Disable button
        var btn = panelEl.querySelector('[data-scenario="' + name + '"]');
        if (btn) {
            btn.disabled = true;
            btn.textContent = 'RUNNING...';
        }

        // Set badge to RUNNING
        var badge = document.getElementById('badge-' + name);
        if (badge) {
            badge.textContent = 'RUNNING';
            badge.className = 'scenario-status-badge badge-running';
        }

        // Show progress bar
        var progressEl = document.getElementById('progress-' + name);
        if (progressEl) {
            progressEl.style.display = 'block';
            var fill = progressEl.querySelector('.scenario-progress-fill');
            if (fill) fill.style.width = '0%';
        }

        fetch('/api/scenarios/' + encodeURIComponent(name) + '/launch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        })
            .then(function (res) { return res.json(); })
            .then(function (data) {
                console.log('[Scenarios] Launched:', name, data);
            })
            .catch(function (err) {
                console.error('[Scenarios] Launch failed:', err);
                if (btn) {
                    btn.disabled = false;
                    btn.textContent = 'LAUNCH';
                }
                if (badge) {
                    badge.textContent = 'FAILED';
                    badge.className = 'scenario-status-badge badge-failed';
                }
            });
    }

    function handleProgress(msg) {
        var name = msg.scenario_name;
        if (!name) return;

        var badge = document.getElementById('badge-' + name);
        var progressEl = document.getElementById('progress-' + name);

        if (msg.status === 'completed') {
            if (badge) {
                badge.textContent = 'COMPLETED';
                badge.className = 'scenario-status-badge badge-completed';
            }
            if (progressEl) {
                var fill = progressEl.querySelector('.scenario-progress-fill');
                if (fill) fill.style.width = '100%';
            }
            // Re-enable launch button
            var btn = panelEl ? panelEl.querySelector('[data-scenario="' + name + '"]') : null;
            if (btn) {
                btn.disabled = false;
                btn.textContent = 'LAUNCH';
            }
        } else if (msg.status === 'failed') {
            if (badge) {
                badge.textContent = 'FAILED';
                badge.className = 'scenario-status-badge badge-failed';
            }
        } else if (msg.status === 'running') {
            // Update progress bar
            if (progressEl && msg.step_index !== undefined) {
                progressEl.style.display = 'block';
                // Get total steps from scenario data
                var sc = scenarios.find(function (s) { return s.name === name; });
                var total = sc ? sc.steps_count : 1;
                var pct = Math.round(((msg.step_index + 1) / total) * 100);
                var fill = progressEl.querySelector('.scenario-progress-fill');
                if (fill) fill.style.width = pct + '%';
            }
        }
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    return {
        init: init,
        fetchScenarios: fetchScenarios
    };
})();
