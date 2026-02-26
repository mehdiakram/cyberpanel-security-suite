/* ═══════════════════════════════════════════════════════════════════════════
   CyberPanel Security Suite — JavaScript v1.0
   AJAX utilities for Fail2ban management. No external CDN dependencies.
   ═══════════════════════════════════════════════════════════════════════════ */

var SS = (function () {
    'use strict';

    // ── Helpers ────────────────────────────────────────────────────────────
    var BASE_URL = '/securitysuite/';
    var autoRefreshTimer = null;

    function getCSRFToken() {
        var meta = document.querySelector('meta[name="csrf-token"]');
        if (meta) return meta.getAttribute('content');
        // Fallback: grab from cookie
        var match = document.cookie.match(/csrftoken=([^;]+)/);
        return match ? match[1] : '';
    }

    function apiGet(endpoint) {
        return fetch(BASE_URL + endpoint, {
            method: 'GET',
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
            credentials: 'same-origin'
        }).then(function (r) { return r.json(); });
    }

    function apiPost(endpoint, data) {
        return fetch(BASE_URL + endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCSRFToken(),
                'X-Requested-With': 'XMLHttpRequest'
            },
            credentials: 'same-origin',
            body: JSON.stringify(data)
        }).then(function (r) { return r.json(); });
    }

    function escapeHtml(str) {
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(str));
        return div.innerHTML;
    }

    // ── Toast Notifications ───────────────────────────────────────────────
    function toast(message, type) {
        type = type || 'info';
        var container = document.getElementById('ss-toast-container');
        if (!container) return;
        var el = document.createElement('div');
        el.className = 'ss-toast ss-toast-' + type;
        el.textContent = message;
        container.appendChild(el);
        setTimeout(function () {
            el.style.opacity = '0';
            el.style.transform = 'translateX(40px)';
            el.style.transition = '0.3s ease';
            setTimeout(function () { el.remove(); }, 300);
        }, 4000);
    }

    // ── Modal ─────────────────────────────────────────────────────────────
    function closeModal(id) {
        var modal = document.getElementById(id);
        if (modal) modal.style.display = 'none';
    }

    // ── Overview ──────────────────────────────────────────────────────────
    function refreshOverview() {
        apiGet('api/status/').then(function (res) {
            if (!res.status) { toast(res.error || 'Error', 'error'); return; }
            var d = res.data;
            // Service status
            var statusEl = document.getElementById('service-status');
            if (statusEl) {
                if (!d.installed) {
                    statusEl.innerHTML = '<span class="ss-badge ss-badge-inactive">Not Installed</span>';
                } else if (d.active) {
                    statusEl.innerHTML = '<span class="ss-badge ss-badge-active">Active</span>';
                } else {
                    statusEl.innerHTML = '<span class="ss-badge ss-badge-inactive">Inactive</span>';
                }
            }
            // Jail count
            var jailEl = document.getElementById('jail-count');
            if (jailEl) jailEl.textContent = d.jail_count || 0;

            // Load banned IPs for count + recent table
            apiGet('api/jails/').then(function (jr) {
                if (!jr.status) return;
                var totalBanned = 0;
                var allBanned = [];
                jr.data.forEach(function (jail) {
                    totalBanned += jail.currently_banned || 0;
                    (jail.banned_ips || []).forEach(function (ip) {
                        allBanned.push({ ip: ip, jail: jail.jail });
                    });
                });
                var bannedEl = document.getElementById('banned-count');
                if (bannedEl) bannedEl.textContent = totalBanned;

                // Recent banned IPs (last 10)
                var tbody = document.getElementById('recent-banned-body');
                if (tbody) {
                    var recent = allBanned.slice(-10).reverse();
                    if (recent.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="3" class="ss-text-center ss-text-muted">No banned IPs found.</td></tr>';
                    } else {
                        tbody.innerHTML = recent.map(function (item) {
                            return '<tr>' +
                                '<td><code>' + escapeHtml(item.ip) + '</code></td>' +
                                '<td><span class="ss-badge ss-badge-warning">' + escapeHtml(item.jail) + '</span></td>' +
                                '<td><button class="ss-btn ss-btn-xs ss-btn-danger" onclick="SS.unbanIP(\'' +
                                escapeHtml(item.jail) + '\', \'' + escapeHtml(item.ip) + '\')">Unban</button></td>' +
                                '</tr>';
                        }).join('');
                    }
                }
            });
        }).catch(function () { toast('Failed to load status', 'error'); });
    }

    // ── Jails ─────────────────────────────────────────────────────────────
    function loadJails() {
        apiGet('api/jails/').then(function (res) {
            if (!res.status) { toast(res.error || 'Error', 'error'); return; }
            var tbody = document.getElementById('jails-body');
            if (!tbody) return;
            if (res.data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" class="ss-text-center ss-text-muted">No active jails found.</td></tr>';
                return;
            }
            tbody.innerHTML = res.data.map(function (j) {
                return '<tr>' +
                    '<td><strong>' + escapeHtml(j.jail) + '</strong></td>' +
                    '<td>' + (j.currently_failed || 0) + '</td>' +
                    '<td>' + (j.total_failed || 0) + '</td>' +
                    '<td><span class="ss-badge ' + (j.currently_banned > 0 ? 'ss-badge-inactive' : 'ss-badge-active') + '">' +
                    (j.currently_banned || 0) + '</span></td>' +
                    '<td>' + (j.total_banned || 0) + '</td>' +
                    '<td><small class="ss-text-muted">' + escapeHtml(j.filter || '—') + '</small></td>' +
                    '<td><button class="ss-btn ss-btn-xs ss-btn-primary" onclick="SS.viewJail(\'' +
                    escapeHtml(j.jail) + '\')">Details</button></td>' +
                    '</tr>';
            }).join('');
        }).catch(function () { toast('Failed to load jails', 'error'); });
    }

    function viewJail(name) {
        var modal = document.getElementById('jail-modal');
        var title = document.getElementById('jail-modal-title');
        var body = document.getElementById('jail-modal-body');
        if (!modal || !body) return;
        title.textContent = 'Jail: ' + name;
        body.innerHTML = '<p class="ss-text-muted">Loading…</p>';
        modal.style.display = 'flex';

        apiGet('api/jail/' + encodeURIComponent(name) + '/').then(function (res) {
            if (!res.status) { body.innerHTML = '<p class="ss-text-muted">' + escapeHtml(res.error) + '</p>'; return; }
            var d = res.data;
            var bannedHtml = '';
            if (d.banned_ips && d.banned_ips.length > 0) {
                bannedHtml = '<div class="ss-ip-list">' + d.banned_ips.map(function (ip) {
                    return '<span class="ss-ip-tag"><code>' + escapeHtml(ip) + '</code>' +
                        '<button class="ss-unban-btn" title="Unban" onclick="SS.unbanIP(\'' +
                        escapeHtml(d.jail) + '\', \'' + escapeHtml(ip) + '\'); SS.closeModal(\'jail-modal\');">&times;</button></span>';
                }).join('') + '</div>';
            } else {
                bannedHtml = '<p class="ss-text-muted">No banned IPs.</p>';
            }

            body.innerHTML =
                '<table class="ss-table ss-table-info">' +
                '<tr><th>Currently Failed</th><td>' + d.currently_failed + '</td></tr>' +
                '<tr><th>Total Failed</th><td>' + d.total_failed + '</td></tr>' +
                '<tr><th>Currently Banned</th><td>' + d.currently_banned + '</td></tr>' +
                '<tr><th>Total Banned</th><td>' + d.total_banned + '</td></tr>' +
                '<tr><th>Log Files</th><td><small>' + escapeHtml(d.filter || '—') + '</small></td></tr>' +
                '</table>' +
                '<h4 style="margin:20px 0 12px;">Banned IPs</h4>' + bannedHtml;
        }).catch(function () { body.innerHTML = '<p class="ss-text-muted">Error loading details.</p>'; });
    }

    // ── Banned IPs ────────────────────────────────────────────────────────
    function loadBannedIPs() {
        // Populate jail dropdown
        apiGet('api/status/').then(function (res) {
            if (!res.status) return;
            var sel = document.getElementById('ban-jail');
            if (sel) {
                var current = sel.value;
                sel.innerHTML = '<option value="">Select Jail…</option>';
                (res.data.jails || []).forEach(function (j) {
                    var opt = document.createElement('option');
                    opt.value = j;
                    opt.textContent = j;
                    if (j === current) opt.selected = true;
                    sel.appendChild(opt);
                });
            }
        });

        apiGet('api/jails/').then(function (res) {
            if (!res.status) { toast(res.error || 'Error', 'error'); return; }
            var container = document.getElementById('banned-ips-container');
            if (!container) return;

            var hasAny = false;
            var html = '';
            res.data.forEach(function (jail) {
                var ips = jail.banned_ips || [];
                if (ips.length === 0) return;
                hasAny = true;
                html += '<div class="ss-jail-group" data-jail="' + escapeHtml(jail.jail) + '">' +
                    '<div class="ss-jail-group-header">' +
                    '&#128274; ' + escapeHtml(jail.jail) +
                    ' <span class="ss-jail-group-count">' + ips.length + '</span>' +
                    '</div>' +
                    '<div class="ss-ip-list">';
                ips.forEach(function (ip) {
                    html += '<span class="ss-ip-tag" data-ip="' + escapeHtml(ip) + '">' +
                        '<code>' + escapeHtml(ip) + '</code>' +
                        '<button class="ss-unban-btn" title="Unban" onclick="SS.unbanIP(\'' +
                        escapeHtml(jail.jail) + '\', \'' + escapeHtml(ip) + '\')">&times;</button></span>';
                });
                html += '</div></div>';
            });

            if (!hasAny) {
                container.innerHTML = '<p class="ss-no-data">No banned IPs across any jail.</p>';
            } else {
                container.innerHTML = html;
            }
        }).catch(function () { toast('Failed to load banned IPs', 'error'); });
    }

    function filterBannedIPs() {
        var query = (document.getElementById('ip-search').value || '').toLowerCase();
        var tags = document.querySelectorAll('.ss-ip-tag');
        tags.forEach(function (tag) {
            var ip = (tag.getAttribute('data-ip') || '').toLowerCase();
            tag.style.display = ip.indexOf(query) >= 0 ? '' : 'none';
        });
    }

    // ── Ban / Unban ───────────────────────────────────────────────────────
    function banIP(jail, ip) {
        apiPost('api/ban/', { jail: jail, ip: ip }).then(function (res) {
            toast(res.message || res.error, res.status ? 'success' : 'error');
            if (res.status) {
                loadBannedIPs();
                refreshOverview && refreshOverview();
            }
        }).catch(function () { toast('Ban request failed', 'error'); });
    }

    function unbanIP(jail, ip) {
        if (!confirm('Unban ' + ip + ' from ' + jail + '?')) return;
        apiPost('api/unban/', { jail: jail, ip: ip }).then(function (res) {
            toast(res.message || res.error, res.status ? 'success' : 'error');
            if (res.status) {
                loadBannedIPs();
                refreshOverview && refreshOverview();
                loadJails && loadJails();
            }
        }).catch(function () { toast('Unban request failed', 'error'); });
    }

    function handleBanForm(e) {
        e.preventDefault();
        var jail = document.getElementById('ban-jail').value;
        var ip = document.getElementById('ban-ip').value.trim();
        if (!jail || !ip) { toast('Please select a jail and enter an IP.', 'error'); return false; }
        banIP(jail, ip);
        document.getElementById('ban-ip').value = '';
        return false;
    }

    // ── Reload / Restart ──────────────────────────────────────────────────
    function reloadFail2ban() {
        apiPost('api/reload/', {}).then(function (res) {
            toast(res.message || res.error, res.status ? 'success' : 'error');
        }).catch(function () { toast('Reload failed', 'error'); });
    }

    function restartFail2ban() {
        if (!confirm('Are you sure you want to restart the Fail2ban service?')) return;
        toast('Restarting Fail2ban…', 'info');
        // Restart is done via reload endpoint (service restart needs special handling)
        apiPost('api/reload/', {}).then(function (res) {
            toast(res.message || res.error, res.status ? 'success' : 'error');
        }).catch(function () { toast('Restart failed', 'error'); });
    }

    // ── Logs ──────────────────────────────────────────────────────────────
    function loadLogs() {
        apiGet('api/logs/').then(function (res) {
            var viewer = document.getElementById('log-viewer');
            if (!viewer) return;
            if (!res.status) { viewer.textContent = res.error || 'Error loading logs.'; return; }
            viewer.textContent = (res.data || []).join('\n') || 'Log file is empty.';
            viewer.scrollTop = viewer.scrollHeight;
        }).catch(function () {
            var viewer = document.getElementById('log-viewer');
            if (viewer) viewer.textContent = 'Failed to load logs.';
        });
    }

    function toggleAutoRefresh() {
        var cb = document.getElementById('auto-refresh-toggle');
        if (cb && cb.checked) {
            loadLogs();
            autoRefreshTimer = setInterval(loadLogs, 10000);
            toast('Auto-refresh enabled (10s)', 'info');
        } else {
            if (autoRefreshTimer) { clearInterval(autoRefreshTimer); autoRefreshTimer = null; }
            toast('Auto-refresh disabled', 'info');
        }
    }

    // ── Settings ──────────────────────────────────────────────────────────
    function refreshSettings() {
        apiGet('api/status/').then(function (res) {
            if (!res.status) return;
            var d = res.data;
            var statusEl = document.getElementById('settings-service-status');
            var instEl = document.getElementById('settings-installed');
            var jailsEl = document.getElementById('settings-jails');

            if (statusEl) {
                statusEl.innerHTML = d.active
                    ? '<span class="ss-badge ss-badge-active">Active</span>'
                    : '<span class="ss-badge ss-badge-inactive">Inactive</span>';
            }
            if (instEl) instEl.textContent = d.installed ? 'Yes' : 'No';
            if (jailsEl) jailsEl.textContent = (d.jails || []).join(', ') || 'None';
        });
    }

    // ── Public API ────────────────────────────────────────────────────────
    return {
        refreshOverview: refreshOverview,
        loadJails: loadJails,
        viewJail: viewJail,
        loadBannedIPs: loadBannedIPs,
        filterBannedIPs: filterBannedIPs,
        banIP: banIP,
        unbanIP: unbanIP,
        handleBanForm: handleBanForm,
        reloadFail2ban: reloadFail2ban,
        restartFail2ban: restartFail2ban,
        loadLogs: loadLogs,
        toggleAutoRefresh: toggleAutoRefresh,
        refreshSettings: refreshSettings,
        closeModal: closeModal,
        toast: toast
    };
})();
