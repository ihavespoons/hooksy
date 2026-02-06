// Hooksy Dashboard Application
(function() {
    'use strict';

    // State
    let eventSource = null;
    let selectedSessionId = null;
    let events = [];
    let reconnectAttempts = 0;
    const maxReconnectAttempts = 10;
    const reconnectDelay = 2000;

    // Filter/sort state
    let sortOrder = 'desc'; // 'asc' or 'desc'
    let filters = {
        eventType: '',
        decision: '',
        toolName: ''
    };

    // DOM Elements
    const connectionStatus = document.getElementById('connection-status');
    const totalSessions = document.getElementById('total-sessions');
    const activeSessions = document.getElementById('active-sessions');
    const events24h = document.getElementById('events-24h');
    const violations24h = document.getElementById('violations-24h');
    const sessionsList = document.getElementById('sessions-list');
    const rulesList = document.getElementById('rules-list');
    const eventsList = document.getElementById('events-list');
    const violationsList = document.getElementById('violations-list');
    const filterInfo = document.getElementById('filter-info');

    // Filter elements
    const filterEventType = document.getElementById('filter-event-type');
    const filterDecision = document.getElementById('filter-decision');
    const filterTool = document.getElementById('filter-tool');
    const sortToggle = document.getElementById('sort-toggle');
    const exportJsonBtn = document.getElementById('export-json');
    const exportCsvBtn = document.getElementById('export-csv');

    // Initialize
    function init() {
        connectSSE();
        loadInitialData();
        setupFilterListeners();
        setInterval(refreshStats, 30000);
    }

    // Setup filter event listeners
    function setupFilterListeners() {
        filterEventType.addEventListener('change', applyFilters);
        filterDecision.addEventListener('change', applyFilters);
        filterTool.addEventListener('input', debounce(applyFilters, 300));
        sortToggle.addEventListener('click', toggleSort);
        exportJsonBtn.addEventListener('click', () => exportEvents('json'));
        exportCsvBtn.addEventListener('click', () => exportEvents('csv'));
    }

    // Debounce helper
    function debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    // Toggle sort order
    function toggleSort() {
        sortOrder = sortOrder === 'desc' ? 'asc' : 'desc';
        sortToggle.textContent = sortOrder === 'desc' ? 'Newest First' : 'Oldest First';
        refreshEvents();
    }

    // Apply filters
    function applyFilters() {
        filters.eventType = filterEventType.value;
        filters.decision = filterDecision.value;
        filters.toolName = filterTool.value;
        refreshEvents();
    }

    // Build events URL with filters
    function buildEventsURL(limit) {
        let url = `/api/events?limit=${limit}&sort=${sortOrder}`;
        if (selectedSessionId) url += `&session_id=${encodeURIComponent(selectedSessionId)}`;
        if (filters.eventType) url += `&event_type=${encodeURIComponent(filters.eventType)}`;
        if (filters.decision) url += `&decision=${encodeURIComponent(filters.decision)}`;
        if (filters.toolName) url += `&tool_name=${encodeURIComponent(filters.toolName)}`;
        return url;
    }

    // Build export URL with filters
    function buildExportURL(format) {
        let url = `/api/events/export?format=${format}&sort=${sortOrder}`;
        if (selectedSessionId) url += `&session_id=${encodeURIComponent(selectedSessionId)}`;
        if (filters.eventType) url += `&event_type=${encodeURIComponent(filters.eventType)}`;
        if (filters.decision) url += `&decision=${encodeURIComponent(filters.decision)}`;
        if (filters.toolName) url += `&tool_name=${encodeURIComponent(filters.toolName)}`;
        return url;
    }

    // Export events
    function exportEvents(format) {
        window.location.href = buildExportURL(format);
    }

    // SSE Connection
    function connectSSE() {
        if (eventSource) {
            eventSource.close();
        }

        eventSource = new EventSource('/sse/events');

        eventSource.onopen = function() {
            connectionStatus.textContent = 'Connected';
            connectionStatus.className = 'status connected';
            reconnectAttempts = 0;
        };

        eventSource.onerror = function() {
            connectionStatus.textContent = 'Disconnected';
            connectionStatus.className = 'status disconnected';
            eventSource.close();

            if (reconnectAttempts < maxReconnectAttempts) {
                reconnectAttempts++;
                setTimeout(connectSSE, reconnectDelay * reconnectAttempts);
            }
        };

        eventSource.addEventListener('connected', function(e) {
            console.log('SSE connected:', JSON.parse(e.data));
        });

        eventSource.addEventListener('event_new', function(e) {
            const event = JSON.parse(e.data);
            addEvent(event);
            refreshStats();
        });

        eventSource.addEventListener('rule_match', function(e) {
            const match = JSON.parse(e.data);
            if (match.decision === 'deny' || match.decision === 'block') {
                refreshViolations();
            }
        });

        eventSource.addEventListener('heartbeat', function(e) {
            console.log('Heartbeat:', JSON.parse(e.data));
        });
    }

    // Load initial data
    async function loadInitialData() {
        await Promise.all([
            refreshStats(),
            refreshSessions(),
            refreshRules(),
            refreshEvents(),
            refreshViolations()
        ]);
    }

    // API calls
    async function fetchJSON(url) {
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        return response.json();
    }

    async function refreshStats() {
        try {
            const stats = await fetchJSON('/api/stats');
            totalSessions.textContent = stats.total_sessions || 0;
            activeSessions.textContent = stats.active_sessions || 0;
            events24h.textContent = stats.events_24h || 0;
            violations24h.textContent = stats.violations_24h || 0;
        } catch (err) {
            console.error('Failed to fetch stats:', err);
        }
    }

    async function refreshSessions() {
        try {
            const sessions = await fetchJSON('/api/sessions');
            renderSessions(sessions);
        } catch (err) {
            console.error('Failed to fetch sessions:', err);
            sessionsList.innerHTML = '<div class="error">Failed to load sessions</div>';
        }
    }

    async function refreshRules() {
        try {
            const rules = await fetchJSON('/api/rules');
            renderRules(rules);
        } catch (err) {
            console.error('Failed to fetch rules:', err);
            rulesList.innerHTML = '<div class="error">Failed to load rules</div>';
        }
    }

    async function refreshEvents() {
        try {
            const eventData = await fetchJSON(buildEventsURL(50));
            events = eventData;
            renderEvents(events);
        } catch (err) {
            console.error('Failed to fetch events:', err);
            eventsList.innerHTML = '<div class="error">Failed to load events</div>';
        }
    }

    async function refreshViolations() {
        try {
            const eventData = await fetchJSON('/api/events?limit=20');
            const violations = eventData.filter(e =>
                e.decision === 'deny' || e.decision === 'block'
            );
            renderViolations(violations);
        } catch (err) {
            console.error('Failed to fetch violations:', err);
            violationsList.innerHTML = '<div class="error">Failed to load violations</div>';
        }
    }

    // Rendering
    function renderSessions(sessions) {
        if (!sessions || sessions.length === 0) {
            sessionsList.innerHTML = '<div class="empty">No sessions found</div>';
            return;
        }

        sessionsList.innerHTML = sessions.map(session => `
            <div class="session-item ${selectedSessionId === session.session_id ? 'selected' : ''}"
                 data-session-id="${escapeHtml(session.session_id)}"
                 onclick="selectSession('${escapeHtml(session.session_id)}')">
                <div class="session-id">${escapeHtml(session.session_id.substring(0, 8))}...</div>
                <div class="session-cwd">${escapeHtml(session.cwd || 'Unknown')}</div>
                <div class="session-meta">
                    <span class="event-count">${session.event_count} events</span>
                    <span class="last-seen">${formatTime(session.last_seen_at)}</span>
                </div>
            </div>
        `).join('');
    }

    function renderRules(rules) {
        if (!rules || rules.length === 0) {
            rulesList.innerHTML = '<div class="empty">No rules configured</div>';
            return;
        }

        const enabledRules = rules.filter(r => r.enabled);
        rulesList.innerHTML = enabledRules.map(rule => `
            <div class="rule-item">
                <div class="rule-name">${escapeHtml(rule.name)}</div>
                <div class="rule-meta">
                    <span class="rule-type">${escapeHtml(rule.event_type)}</span>
                    <span class="rule-decision decision-${rule.decision}">${escapeHtml(rule.decision)}</span>
                </div>
            </div>
        `).join('');
    }

    function renderEvents(eventData) {
        if (!eventData || eventData.length === 0) {
            eventsList.innerHTML = '<div class="empty">No events found</div>';
            return;
        }

        eventsList.innerHTML = eventData.map(event => `
            <div class="event-item decision-${event.decision || 'allow'}" onclick="showEventDetail(${event.id})">
                <div class="event-header">
                    <span class="event-type">${escapeHtml(event.event_type)}</span>
                    <span class="event-time">${formatTime(event.timestamp)}</span>
                </div>
                <div class="event-tool">${escapeHtml(event.tool_name || '-')}</div>
                ${event.decision ? `<div class="event-decision decision-${event.decision}">${escapeHtml(event.decision)}</div>` : ''}
                ${event.rule_matched ? `<div class="event-rule">Rule: ${escapeHtml(event.rule_matched)}</div>` : ''}
            </div>
        `).join('');
    }

    // Show event detail modal
    window.showEventDetail = async function(eventId) {
        try {
            const event = await fetchJSON(`/api/events/${eventId}`);
            document.getElementById('event-detail-content').innerHTML = renderEventDetail(event);
            document.getElementById('event-modal').classList.remove('hidden');
        } catch (err) {
            console.error('Failed to fetch event detail:', err);
        }
    };

    // Close event detail modal
    window.closeEventModal = function() {
        document.getElementById('event-modal').classList.add('hidden');
    };

    // Render event detail
    function renderEventDetail(event) {
        return `
            <div class="event-detail">
                <div class="detail-row">
                    <span class="detail-label">Event ID:</span>
                    <span class="detail-value">${event.id}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Session ID:</span>
                    <span class="detail-value monospace">${escapeHtml(event.session_id)}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Event Type:</span>
                    <span class="detail-value">${escapeHtml(event.event_type)}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Tool Name:</span>
                    <span class="detail-value monospace">${escapeHtml(event.tool_name || '-')}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Tool Use ID:</span>
                    <span class="detail-value monospace">${escapeHtml(event.tool_use_id || '-')}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Timestamp:</span>
                    <span class="detail-value">${new Date(event.timestamp).toLocaleString()}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Decision:</span>
                    <span class="detail-value decision-${event.decision || 'allow'}">${escapeHtml(event.decision || 'allow')}</span>
                </div>
                ${event.rule_matched ? `
                <div class="detail-row">
                    <span class="detail-label">Rule Matched:</span>
                    <span class="detail-value">${escapeHtml(event.rule_matched)}</span>
                </div>
                ` : ''}
                ${event.tool_input ? `
                <div class="detail-section">
                    <h4>Tool Input</h4>
                    <pre class="detail-json">${escapeHtml(JSON.stringify(event.tool_input, null, 2))}</pre>
                </div>
                ` : ''}
                ${event.tool_response ? `
                <div class="detail-section">
                    <h4>Tool Response</h4>
                    <pre class="detail-json">${escapeHtml(JSON.stringify(event.tool_response, null, 2))}</pre>
                </div>
                ` : ''}
            </div>
        `;
    }

    function renderViolations(violations) {
        if (!violations || violations.length === 0) {
            violationsList.innerHTML = '<div class="empty">No violations found</div>';
            return;
        }

        violationsList.innerHTML = violations.map(event => `
            <div class="violation-item decision-${event.decision}">
                <div class="violation-header">
                    <span class="violation-decision">${escapeHtml(event.decision).toUpperCase()}</span>
                    <span class="violation-time">${formatTime(event.timestamp)}</span>
                </div>
                <div class="violation-tool">${escapeHtml(event.tool_name || '-')}</div>
                <div class="violation-rule">${escapeHtml(event.rule_matched || 'Unknown rule')}</div>
            </div>
        `).join('');
    }

    function addEvent(event) {
        // Only add if we're not filtering or if it matches the filter
        if (selectedSessionId && event.session_id !== selectedSessionId) {
            return;
        }

        events.unshift(event);
        if (events.length > 100) {
            events.pop();
        }
        renderEvents(events);

        // Update violations if needed
        if (event.decision === 'deny' || event.decision === 'block') {
            refreshViolations();
        }
    }

    // Session selection
    window.selectSession = async function(sessionId) {
        if (selectedSessionId === sessionId) {
            selectedSessionId = null;
            filterInfo.textContent = '';
        } else {
            selectedSessionId = sessionId;
            filterInfo.textContent = `(filtered by ${sessionId.substring(0, 8)}...)`;
        }

        // Update UI
        document.querySelectorAll('.session-item').forEach(el => {
            el.classList.toggle('selected', el.dataset.sessionId === selectedSessionId);
        });

        // Refresh rules for selected session (or global rules if none selected)
        if (selectedSessionId) {
            try {
                const rules = await fetchJSON(`/api/rules?session_id=${encodeURIComponent(selectedSessionId)}`);
                renderRules(rules);
            } catch (err) {
                console.error('Failed to fetch session rules:', err);
            }
        } else {
            refreshRules();
        }

        refreshEvents();
    };

    // Utilities
    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function formatTime(timestamp) {
        if (!timestamp) return '-';
        const date = new Date(timestamp);
        const now = new Date();
        const diff = now - date;

        if (diff < 60000) {
            return 'just now';
        } else if (diff < 3600000) {
            const mins = Math.floor(diff / 60000);
            return `${mins}m ago`;
        } else if (diff < 86400000) {
            const hours = Math.floor(diff / 3600000);
            return `${hours}h ago`;
        } else {
            return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
        }
    }

    // Start the app
    init();
})();
