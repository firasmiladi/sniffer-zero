/**
 * SRT Spectrum / Band Occupation Visualization
 * Shows ISM band occupation as horizontal progress bars.
 * Live HackRF sweep data rendered as spectrum waterfall/bar chart.
 */

const SRTSpectrum = (function () {
    let panelEl = null;
    let liveEl = null;
    let latestSweep = null;

    function init() {
        panelEl = document.getElementById('spectrum-panel');
        liveEl = document.getElementById('spectrum-live');
        fetchBands();
    }

    function fetchBands() {
        fetch('/api/cartography/bands')
            .then(function (res) { return res.json(); })
            .then(function (data) {
                var bands = data.bands || data || {};
                render(bands);
            })
            .catch(function (err) {
                console.error('[Spectrum] Failed to fetch bands:', err);
                if (panelEl) {
                    panelEl.innerHTML = '<p class="panel-placeholder">Band data unavailable</p>';
                }
            });
    }

    function render(bands) {
        if (!panelEl) return;

        var keys = Object.keys(bands);
        if (keys.length === 0) {
            panelEl.innerHTML = '<p class="panel-placeholder">No band data. Run a scan to populate.</p>';
            return;
        }

        var html = '';
        keys.forEach(function (bandName) {
            var band = bands[bandName];
            var occupation = band.occupation_pourcent || 0;
            var emitters = band.nb_emetteurs || band.num_bins || 0;
            var freqMin = band.frequence_min_mhz || band.freq_min_mhz || 0;
            var freqMax = band.frequence_max_mhz || band.freq_max_mhz || 0;
            var powerMax = band.puissance_max_dbm || band.peak_power_db || 0;
            var types = band.types_presents || [];

            var fillClass = '';
            if (occupation >= 80) fillClass = 'critical';
            else if (occupation >= 50) fillClass = 'high';

            html += '<div class="band-bar">';
            html += '  <div class="band-name">' + escapeHtml(bandName) + '</div>';
            html += '  <div class="band-progress">';
            html += '    <div class="band-fill ' + fillClass + '" style="width: ' + Math.min(100, occupation) + '%"></div>';
            html += '  </div>';
            html += '  <div class="band-stats">';
            html += '    ' + freqMin + '-' + freqMax + ' MHz | ';
            html += '    ' + emitters + ' emitters | ';
            html += '    ' + occupation + '% occ';
            if (powerMax) html += ' | ' + powerMax + ' dBm max';
            html += '  </div>';
            html += '</div>';
        });

        panelEl.innerHTML = html;
    }

    function updateBand(bands) {
        // Live update: re-render the bands with transition animation
        var bandsData = bands.bands || bands || {};
        render(bandsData);
    }

    /**
     * Handle a spectrum_update WebSocket message from HackRF sweep.
     * Renders live spectrum data as a bar chart showing power per frequency bin.
     */
    function handleSpectrumUpdate(data) {
        if (!data) return;

        // Store latest sweep data
        if (data.frequencies_mhz && data.powers_db) {
            latestSweep = data;
            renderLiveSpectrum(data);
        } else if (data.status === 'scanning') {
            renderScanningIndicator(data);
        }

        // Also update band summary if available
        if (data.bands) {
            render(data.bands);
        }
    }

    function renderLiveSpectrum(sweep) {
        var container = liveEl || panelEl;
        if (!container) return;

        var freqs = sweep.frequencies_mhz || [];
        var powers = sweep.powers_db || [];
        var numBins = freqs.length;

        if (numBins === 0) return;

        // Create a canvas-based spectrum display
        var html = '<div class="spectrum-live-container">';
        html += '<div class="spectrum-header">';
        html += '  <span class="spectrum-title">HackRF Live Spectrum</span>';
        html += '  <span class="spectrum-info">';
        html += '    ' + (sweep.freq_start_mhz || freqs[0]).toFixed(0) + ' - ';
        html += '    ' + (sweep.freq_end_mhz || freqs[freqs.length - 1]).toFixed(0) + ' MHz';
        html += '    | Peak: ' + (sweep.peak_power_db || 0).toFixed(1) + ' dBm';
        html += '    | Noise: ' + (sweep.noise_floor_db || -90).toFixed(1) + ' dBm';
        html += '    | Bins: ' + numBins;
        html += '  </span>';
        html += '</div>';

        // Render spectrum bars (limit to max ~200 displayed bars for performance)
        var step = Math.max(1, Math.floor(numBins / 200));
        var minPower = -100;
        var maxPower = -20;

        html += '<div class="spectrum-bars">';
        for (var i = 0; i < numBins; i += step) {
            var power = powers[i];
            var height = Math.max(0, Math.min(100, ((power - minPower) / (maxPower - minPower)) * 100));
            var color = getSpectrumColor(power);
            var freq = freqs[i];

            html += '<div class="spectrum-bar" style="height: ' + height + '%; background: ' + color + ';" ';
            html += 'title="' + freq.toFixed(2) + ' MHz: ' + power.toFixed(1) + ' dBm"></div>';
        }
        html += '</div>';

        // Frequency axis labels
        html += '<div class="spectrum-axis">';
        var labelCount = 5;
        for (var j = 0; j <= labelCount; j++) {
            var idx = Math.floor((j / labelCount) * (numBins - 1));
            html += '<span>' + freqs[idx].toFixed(0) + '</span>';
        }
        html += '</div>';
        html += '</div>';

        container.innerHTML = html;
    }

    function renderScanningIndicator(data) {
        var container = liveEl || panelEl;
        if (!container) return;

        var html = '<div class="spectrum-scanning">';
        html += '  <div class="scanning-pulse"></div>';
        html += '  <span>Scanning ' + (data.freq_start_mhz || '').toFixed(0);
        html += '  - ' + (data.freq_end_mhz || '').toFixed(0) + ' MHz...</span>';
        html += '</div>';
        container.innerHTML = html;
    }

    function getSpectrumColor(power_db) {
        // Color gradient: blue (low) -> green -> yellow -> red (high signal)
        var normalized = Math.max(0, Math.min(1, (power_db + 100) / 60));
        if (normalized < 0.25) {
            return 'rgba(0, 100, 200, 0.7)';
        } else if (normalized < 0.5) {
            return 'rgba(0, 200, 100, 0.8)';
        } else if (normalized < 0.75) {
            return 'rgba(255, 200, 0, 0.9)';
        } else {
            return 'rgba(255, 50, 50, 1.0)';
        }
    }

    /**
     * Trigger a HackRF sweep via API and display results.
     */
    function triggerSweep(freqStart, freqEnd) {
        var url = '/api/spectrum/sweep?freq_start_mhz=' + (freqStart || 2400);
        url += '&freq_end_mhz=' + (freqEnd || 2500);

        fetch(url, { method: 'POST' })
            .then(function (res) { return res.json(); })
            .then(function (data) {
                if (data.frequencies_mhz) {
                    handleSpectrumUpdate(data);
                }
            })
            .catch(function (err) {
                console.error('[Spectrum] Sweep failed:', err);
            });
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    return {
        init: init,
        fetchBands: fetchBands,
        updateBand: updateBand,
        handleSpectrumUpdate: handleSpectrumUpdate,
        triggerSweep: triggerSweep
    };
})();
