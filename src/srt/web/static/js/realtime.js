/**
 * SRT Realtime Module
 * Listens to WebSocket messages for live emitter tracking, band updates,
 * scan progress, and timeline rendering.
 */

const SRTRealtime = (function () {
    let timelineEl = null;
    let scanProgressEl = null;
    let timelineEntries = [];

    function init() {
        timelineEl = document.getElementById('timeline-panel');
        scanProgressEl = document.getElementById('scan-progress-container');

        // Register WebSocket event handlers
        SRTWebSocket.on('emitter_new', handleEmitterNew);
        SRTWebSocket.on('emitter_update', handleEmitterUpdate);
        SRTWebSocket.on('band_update', handleBandUpdate);
        SRTWebSocket.on('scan_progress', handleScanProgress);
        SRTWebSocket.on('spectrum_update', handleSpectrumUpdate);

        // Initial timeline fetch
        fetchTimeline();
    }

    function handleEmitterNew(msg) {
        var emitter = msg.emitter;
        if (!emitter) return;

        // Add pulsing marker on map
        if (typeof SRTMap !== 'undefined' && SRTMap.addEmitterWithPulse) {
            SRTMap.addEmitterWithPulse(emitter);
        }

        // Flash in sidebar
        flashEmitterInSidebar(emitter);

        // Add to timeline
        addToTimeline(emitter, 'new');
    }

    function handleEmitterUpdate(msg) {
        var emitter = msg.emitter;
        if (!emitter) return;

        // Animate marker change on map
        if (typeof SRTMap !== 'undefined' && SRTMap.updateEmitters) {
            SRTMap.updateEmitters([emitter]);
        }

        // Update timeline entry
        addToTimeline(emitter, 'update');
    }

    function handleBandUpdate(msg) {
        var bands = msg.bands;
        if (!bands) return;

        // Update spectrum bars with animation
        if (typeof SRTSpectrum !== 'undefined' && SRTSpectrum.updateBand) {
            SRTSpectrum.updateBand(bands);
        }
    }

    function handleSpectrumUpdate(msg) {
        var data = msg.data;
        if (!data) return;

        // Dispatch to SRTSpectrum for live rendering
        if (typeof SRTSpectrum !== 'undefined' && SRTSpectrum.handleSpectrumUpdate) {
            SRTSpectrum.handleSpectrumUpdate(data);
        }
    }

    function handleScanProgress(msg) {
        if (!scanProgressEl) return;

        var status = msg.status;
        var totalSteps = msg.total_steps || 1;
        var completedSteps = msg.completed_steps || 0;
        var freqMhz = msg.current_freq_mhz || 0;

        var fill = scanProgressEl.querySelector('.scan-progress-fill');
        var label = scanProgressEl.querySelector('.scan-progress-label');

        if (status === 'started') {
            scanProgressEl.style.display = 'block';
            if (fill) fill.style.width = '0%';
            if (label) label.textContent = 'SCANNING ' + freqMhz.toFixed(0) + ' MHz...';
        } else if (status === 'completed') {
            if (fill) fill.style.width = '100%';
            if (label) label.textContent = 'SCAN COMPLETE';
            setTimeout(function () {
                scanProgressEl.style.display = 'none';
            }, 3000);
        } else {
            // In progress
            scanProgressEl.style.display = 'block';
            var pct = Math.round((completedSteps / totalSteps) * 100);
            if (fill) fill.style.width = pct + '%';
            if (label) label.textContent = 'SCANNING ' + freqMhz.toFixed(0) + ' MHz (' + pct + '%)';
        }
    }

    function flashEmitterInSidebar(emitter) {
        // Find the sidebar element and add a flash effect
        var id = (emitter.identification && emitter.identification.id) || emitter.id_unique || '';
        var type = '';
        if (emitter.classification) {
            type = emitter.classification.type || '';
        }

        // Add a flash notification to the ALL tab
        var allTab = document.getElementById('tab-content-all');
        if (allTab) {
            var flashDiv = document.createElement('div');
            flashDiv.className = 'emitter-flash';
            var name = '';
            if (emitter.identification) {
                name = emitter.identification.nom || emitter.identification.ssid || emitter.identification.mac || id;
            } else {
                name = id;
            }
            flashDiv.innerHTML = '<span class="flash-icon">&#9679;</span> NEW: ' + escapeHtml(name);
            allTab.insertBefore(flashDiv, allTab.firstChild);

            // Remove flash after animation
            setTimeout(function () {
                if (flashDiv.parentNode) {
                    flashDiv.parentNode.removeChild(flashDiv);
                }
            }, 5000);
        }
    }

    function addToTimeline(emitter, eventType) {
        if (!timelineEl) return;

        var id = emitter.id_unique || (emitter.identification && emitter.identification.id) || '';
        var type = '';
        if (emitter.classification) {
            type = emitter.classification.type || '';
        }
        var protocol = getProtocolFromType(type);

        var entry = {
            id: id,
            type: eventType,
            protocol: protocol,
            timestamp: new Date().toISOString(),
            name: ''
        };
        if (emitter.identification) {
            entry.name = emitter.identification.nom || emitter.identification.ssid || emitter.identification.mac || id;
        } else {
            entry.name = id;
        }

        timelineEntries.unshift(entry);
        if (timelineEntries.length > 50) {
            timelineEntries = timelineEntries.slice(0, 50);
        }

        renderTimeline();
    }

    function fetchTimeline() {
        fetch('/api/cartography/timeline')
            .then(function (res) { return res.json(); })
            .then(function (data) {
                if (Array.isArray(data)) {
                    data.slice(0, 30).forEach(function (em) {
                        var id = em.id_unique || (em.identification && em.identification.id) || '';
                        var type = '';
                        if (em.classification) {
                            type = em.classification.type || '';
                        }
                        timelineEntries.push({
                            id: id,
                            type: 'existing',
                            protocol: getProtocolFromType(type),
                            timestamp: em.first_seen || '',
                            name: (em.identification && (em.identification.nom || em.identification.ssid || em.identification.mac)) || id
                        });
                    });
                    renderTimeline();
                }
            })
            .catch(function () {
                // Silently ignore if timeline not populated yet
            });
    }

    function renderTimeline() {
        if (!timelineEl) return;

        if (timelineEntries.length === 0) {
            timelineEl.innerHTML = '<p class="panel-placeholder">No timeline data. Run a scan to populate.</p>';
            return;
        }

        var html = '<div class="timeline-container">';
        timelineEntries.forEach(function (entry) {
            var colorClass = 'timeline-dot-' + entry.protocol;
            var timeStr = entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : '';
            html += '<div class="timeline-entry">';
            html += '  <div class="timeline-dot ' + colorClass + '"></div>';
            html += '  <div class="timeline-info">';
            html += '    <span class="timeline-name">' + escapeHtml(entry.name) + '</span>';
            html += '    <span class="timeline-time">' + escapeHtml(timeStr) + '</span>';
            html += '  </div>';
            html += '</div>';
        });
        html += '</div>';

        timelineEl.innerHTML = html;
    }

    function getProtocolFromType(type) {
        if (!type) return 'unknown';
        type = type.toLowerCase();
        if (type.indexOf('wifi') >= 0) return 'wifi';
        if (type.indexOf('ble') >= 0 || type.indexOf('bluetooth') >= 0) return 'ble';
        if (type.indexOf('lora') >= 0) return 'lora';
        return 'unknown';
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    return {
        init: init,
        fetchTimeline: fetchTimeline
    };
})();
