/**
 * SRT Leaflet.js Map Integration
 * Renders RF emitters as circle markers colored by protocol.
 */

const SRTMap = (function () {
    let map = null;
    let markers = {};
    let heatmapLayer = null;
    let layerGroups = {
        wifi: null,
        ble: null,
        lora: null,
        unknown: null
    };

    const PROTOCOL_COLORS = {
        wifi: '#4caf50',
        ble: '#2196f3',
        lora: '#ff9800',
        unknown: '#8b949e'
    };

    const THREAT_COLORS = {
        critical: '#ff1744',
        high: '#ff9100',
        medium: '#ffea00',
        low: '#00e676'
    };

    // Default center: Paris
    const DEFAULT_CENTER = [48.8566, 2.3522];
    const DEFAULT_ZOOM = 13;

    function init() {
        map = L.map('map', {
            center: DEFAULT_CENTER,
            zoom: DEFAULT_ZOOM,
            zoomControl: true,
            attributionControl: true
        });

        // OpenStreetMap tile layer
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '&copy; OpenStreetMap contributors',
            maxZoom: 19
        }).addTo(map);

        // Create layer groups for each protocol
        layerGroups.wifi = L.layerGroup().addTo(map);
        layerGroups.ble = L.layerGroup().addTo(map);
        layerGroups.lora = L.layerGroup().addTo(map);
        layerGroups.unknown = L.layerGroup().addTo(map);

        // Add layer control
        var overlays = {
            '<span style="color:#4caf50">WiFi</span>': layerGroups.wifi,
            '<span style="color:#2196f3">BLE</span>': layerGroups.ble,
            '<span style="color:#ff9800">LoRa</span>': layerGroups.lora,
            '<span style="color:#8b949e">Unknown</span>': layerGroups.unknown
        };
        L.control.layers(null, overlays, { position: 'topright' }).addTo(map);

        // Listen for WebSocket emitter updates
        SRTWebSocket.on('message', function (msg) {
            if (msg.type === 'state' && msg.data && msg.data.emitters) {
                updateEmitters(msg.data.emitters);
            }
        });
    }

    function getProtocolFromType(type) {
        if (!type) return 'unknown';
        type = type.toLowerCase();
        if (type.indexOf('wifi') >= 0) return 'wifi';
        if (type.indexOf('ble') >= 0 || type.indexOf('bluetooth') >= 0) return 'ble';
        if (type.indexOf('lora') >= 0) return 'lora';
        return 'unknown';
    }

    function getMarkerColor(emitter) {
        // If high threat, use threat color
        var threatLevel = 0;
        if (emitter.menaces) {
            threatLevel = emitter.menaces.niveau || 0;
        } else if (emitter.classification) {
            threatLevel = emitter.classification.niveau_menace || 0;
        }

        if (threatLevel >= 80) return THREAT_COLORS.critical;
        if (threatLevel >= 60) return THREAT_COLORS.high;
        if (threatLevel >= 40) return THREAT_COLORS.medium;

        // Otherwise, protocol color
        var type = '';
        if (emitter.classification) {
            type = emitter.classification.type || '';
        }
        var protocol = getProtocolFromType(type);
        return PROTOCOL_COLORS[protocol] || PROTOCOL_COLORS.unknown;
    }

    function getMarkerRadius(emitter) {
        var priority = 50;
        if (emitter.classification) {
            priority = emitter.classification.priorite || 50;
        }
        return Math.max(4, Math.min(12, priority / 8));
    }

    function createPopupContent(emitter) {
        var id = emitter.identification || {};
        var cls = emitter.classification || {};
        var sig = emitter.signaux || {};
        var menaces = emitter.menaces || {};

        var name = id.nom || id.ssid || id.mac || id.id || 'Unknown';
        var type = cls.type || 'unknown';
        var protocol = getProtocolFromType(type);
        var threat = menaces.niveau || cls.niveau_menace || 0;
        var freqs = sig.frequences_utilisees || [];

        var html = '<div class="emitter-popup">';
        html += '<strong style="color:' + (PROTOCOL_COLORS[protocol] || '#e6edf3') + '">' + escapeHtml(name) + '</strong><br>';
        html += '<span style="color:#8b949e">Type:</span> ' + escapeHtml(type) + '<br>';
        if (freqs.length > 0) {
            html += '<span style="color:#8b949e">Freq:</span> ' + freqs.map(function (f) { return f + ' MHz'; }).join(', ') + '<br>';
        }
        html += '<span style="color:#8b949e">Threat:</span> <span style="color:' + getThreatColor(threat) + '">' + threat + '/100</span><br>';
        if (id.mac) {
            html += '<span style="color:#8b949e">MAC:</span> ' + escapeHtml(id.mac) + '<br>';
        }
        html += '</div>';
        return html;
    }

    function getThreatColor(level) {
        if (level >= 80) return THREAT_COLORS.critical;
        if (level >= 60) return THREAT_COLORS.high;
        if (level >= 40) return THREAT_COLORS.medium;
        return THREAT_COLORS.low;
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function updateEmitters(emitters) {
        if (!Array.isArray(emitters)) return;

        // Track which emitters we see this update
        var seenIds = {};

        emitters.forEach(function (emitter) {
            var id = (emitter.identification && emitter.identification.id) || Math.random().toString(36);
            seenIds[id] = true;

            // Determine position (use derniere_position or center of map)
            var pos = null;
            if (emitter.localisation && emitter.localisation.derniere_position) {
                var p = emitter.localisation.derniere_position;
                if (p.lat && p.lon) {
                    pos = [p.lat, p.lon];
                } else if (p.latitude && p.longitude) {
                    pos = [p.latitude, p.longitude];
                }
            }

            // If no position data, scatter around center for visualization
            if (!pos) {
                var hash = simpleHash(id);
                var latOff = ((hash % 1000) - 500) / 10000;
                var lonOff = (((hash >> 10) % 1000) - 500) / 10000;
                pos = [DEFAULT_CENTER[0] + latOff, DEFAULT_CENTER[1] + lonOff];
            }

            var color = getMarkerColor(emitter);
            var radius = getMarkerRadius(emitter);
            var type = (emitter.classification && emitter.classification.type) || '';
            var protocol = getProtocolFromType(type);

            if (markers[id]) {
                // Update existing marker
                markers[id].setLatLng(pos);
                markers[id].setStyle({ fillColor: color, color: color, radius: radius });
                markers[id].setPopupContent(createPopupContent(emitter));
            } else {
                // Create new marker
                var marker = L.circleMarker(pos, {
                    radius: radius,
                    fillColor: color,
                    color: color,
                    weight: 1,
                    opacity: 0.8,
                    fillOpacity: 0.6
                });
                marker.bindPopup(createPopupContent(emitter));

                var layer = layerGroups[protocol] || layerGroups.unknown;
                marker.addTo(layer);
                markers[id] = marker;
            }
        });

        // Remove markers no longer in the data
        Object.keys(markers).forEach(function (id) {
            if (!seenIds[id]) {
                Object.values(layerGroups).forEach(function (lg) {
                    if (lg.hasLayer(markers[id])) {
                        lg.removeLayer(markers[id]);
                    }
                });
                delete markers[id];
            }
        });

        // Update nav stat
        var el = document.getElementById('stat-emitters');
        if (el) el.textContent = emitters.length;
    }

    function simpleHash(str) {
        var hash = 0;
        for (var i = 0; i < str.length; i++) {
            hash = ((hash << 5) - hash) + str.charCodeAt(i);
            hash = hash & hash; // Convert to 32bit int
        }
        return Math.abs(hash);
    }

    function addEmitterWithPulse(emitter) {
        var id = (emitter.identification && emitter.identification.id) || emitter.id_unique || Math.random().toString(36);

        // Determine position
        var pos = null;
        if (emitter.localisation && emitter.localisation.derniere_position) {
            var p = emitter.localisation.derniere_position;
            if (p.lat && p.lon) {
                pos = [p.lat, p.lon];
            } else if (p.latitude && p.longitude) {
                pos = [p.latitude, p.longitude];
            }
        }
        if (!pos) {
            var hash = simpleHash(id);
            var latOff = ((hash % 1000) - 500) / 10000;
            var lonOff = (((hash >> 10) % 1000) - 500) / 10000;
            pos = [DEFAULT_CENTER[0] + latOff, DEFAULT_CENTER[1] + lonOff];
        }

        var color = getMarkerColor(emitter);
        var radius = getMarkerRadius(emitter);
        var type = (emitter.classification && emitter.classification.type) || '';
        var protocol = getProtocolFromType(type);

        // Create marker with pulse animation class
        var marker = L.circleMarker(pos, {
            radius: radius,
            fillColor: color,
            color: color,
            weight: 2,
            opacity: 1.0,
            fillOpacity: 0.8,
            className: 'emitter-pulse-marker'
        });
        marker.bindPopup(createPopupContent(emitter));

        var layer = layerGroups[protocol] || layerGroups.unknown;
        marker.addTo(layer);
        markers[id] = marker;

        // Remove pulse class after animation
        setTimeout(function () {
            if (markers[id]) {
                markers[id].setStyle({ weight: 1, opacity: 0.8, fillOpacity: 0.6 });
            }
        }, 3000);

        return marker;
    }

    function addHeatmapLayer(points) {
        // Using semi-transparent circle markers with varying radius for heatmap effect
        if (!map) return;

        // Remove existing heatmap markers if any
        if (heatmapLayer) {
            map.removeLayer(heatmapLayer);
        }
        heatmapLayer = L.layerGroup();

        points.forEach(function (point) {
            if (!point.lat || !point.lon) return;
            var intensity = point.intensity || 0.5;
            var radius = 8 + intensity * 20;
            var opacity = 0.1 + intensity * 0.4;

            L.circleMarker([point.lat, point.lon], {
                radius: radius,
                fillColor: getHeatColor(intensity),
                color: 'transparent',
                weight: 0,
                fillOpacity: opacity
            }).addTo(heatmapLayer);
        });

        heatmapLayer.addTo(map);
    }

    function getHeatColor(intensity) {
        // Gradient from blue (low) through green/yellow to red (high)
        if (intensity < 0.25) return '#2196f3';
        if (intensity < 0.5) return '#4caf50';
        if (intensity < 0.75) return '#ff9800';
        return '#f44336';
    }

    function clearMarkers() {
        Object.keys(markers).forEach(function (id) {
            Object.values(layerGroups).forEach(function (lg) {
                if (lg.hasLayer(markers[id])) {
                    lg.removeLayer(markers[id]);
                }
            });
        });
        markers = {};
    }

    function getMap() {
        return map;
    }

    return {
        init: init,
        updateEmitters: updateEmitters,
        addEmitterWithPulse: addEmitterWithPulse,
        addHeatmapLayer: addHeatmapLayer,
        clearMarkers: clearMarkers,
        getMap: getMap
    };
})();
