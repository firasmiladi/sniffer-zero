/**
 * SRT Module Launcher Panel
 * Fetches modules from API and provides launch controls.
 */

const SRTModules = (function () {
    let modules = [];
    let panelEl = null;

    function init() {
        panelEl = document.getElementById('modules-panel');
        fetchModules();
    }

    function fetchModules() {
        fetch('/api/modules')
            .then(function (res) { return res.json(); })
            .then(function (data) {
                modules = data.modules || data || [];
                render();
                updateModuleCount();
            })
            .catch(function (err) {
                console.error('[Modules] Failed to fetch:', err);
                if (panelEl) {
                    panelEl.innerHTML = '<p class="panel-placeholder">Failed to load modules</p>';
                }
            });
    }

    function updateModuleCount() {
        var el = document.getElementById('stat-modules');
        if (el) el.textContent = modules.length;
    }

    function getProtocolBadge(protocol) {
        if (!protocol) return '';
        var cls = 'badge badge-' + protocol.toLowerCase();
        return '<span class="' + cls + '">' + escapeHtml(protocol.toUpperCase()) + '</span>';
    }

    function getRiskBadge(risk) {
        if (!risk) return '';
        var level = risk.toLowerCase();
        var cls = 'badge badge-risk-' + level;
        return '<span class="' + cls + '">' + escapeHtml(risk.toUpperCase()) + '</span>';
    }

    function render() {
        if (!panelEl) return;

        if (modules.length === 0) {
            panelEl.innerHTML = '<p class="panel-placeholder">No modules registered</p>';
            return;
        }

        var html = '';
        modules.forEach(function (mod) {
            var name = mod.name || 'unknown';
            var desc = mod.description || '';
            var protocol = mod.protocol || '';
            var risk = mod.risk || 'low';
            var isActive = (risk === 'active-lab' || risk === 'destructive-lab');

            html += '<div class="module-card' + (isActive ? ' module-card-active' : '') + '" data-module="' + escapeHtml(name) + '">';
            if (isActive) {
                html += '  <div class="module-active-banner">MODULE ACTIF - LAB</div>';
            }
            html += '  <div class="module-card-body">';
            html += '    <div class="module-info">';
            html += '      <div class="module-name">' + escapeHtml(name) + '</div>';
            html += '      <div class="module-desc">' + escapeHtml(desc) + '</div>';
            html += '    </div>';
            html += '    <div class="module-badges">';
            html += '      ' + getProtocolBadge(protocol);
            html += '      ' + getRiskBadge(risk);
            html += '      <button class="btn-launch" onclick="SRTModules.launch(\'' + escapeHtml(name) + '\')">RUN</button>';
            html += '    </div>';
            html += '  </div>';
            html += '</div>';
        });

        panelEl.innerHTML = html;
    }

    function launch(moduleName) {
        console.log('[Modules] Launching:', moduleName);

        // Find the button and disable it
        var card = panelEl.querySelector('[data-module="' + moduleName + '"]');
        if (card) {
            var btn = card.querySelector('.btn-launch');
            if (btn) {
                btn.textContent = '...';
                btn.disabled = true;
            }
        }

        fetch('/api/modules/' + encodeURIComponent(moduleName) + '/launch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ params: {}, dry_run: false })
        })
            .then(function (res) { return res.json(); })
            .then(function (data) {
                console.log('[Modules] Launch result:', data);
                if (card) {
                    var btn = card.querySelector('.btn-launch');
                    if (btn) {
                        btn.textContent = 'DONE';
                        btn.style.borderColor = '#00e676';
                        btn.style.color = '#00e676';
                        setTimeout(function () {
                            btn.textContent = 'RUN';
                            btn.style.borderColor = '';
                            btn.style.color = '';
                            btn.disabled = false;
                        }, 3000);
                    }
                }
            })
            .catch(function (err) {
                console.error('[Modules] Launch failed:', err);
                if (card) {
                    var btn = card.querySelector('.btn-launch');
                    if (btn) {
                        btn.textContent = 'ERR';
                        btn.style.borderColor = '#ff1744';
                        btn.style.color = '#ff1744';
                        btn.disabled = false;
                        setTimeout(function () {
                            btn.textContent = 'RUN';
                            btn.style.borderColor = '';
                            btn.style.color = '';
                        }, 3000);
                    }
                }
            });
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    return {
        init: init,
        launch: launch,
        fetchModules: fetchModules
    };
})();
