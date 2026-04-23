/**
 * SHIELD ANALYZER — Frontend Application Logic
 * Handles: Auth, Single Scan, Compare, Batch Scan, History, PDF Export
 */

const API_BASE = "http://localhost:5000/api";

// ─────────────────────────────────────────────
// SESSION STATE
// ─────────────────────────────────────────────
let currentUser = null;
let lastScanResult = null;  // For PDF export

// On load: check if already logged in
window.onload = () => {
  const saved = localStorage.getItem("shield_user");
  if (saved) {
    currentUser = JSON.parse(saved);
    showApp();
  }
  // Apply saved theme
  const theme = localStorage.getItem("shield_theme") || "dark";
  document.documentElement.setAttribute("data-theme", theme);
};

// ─────────────────────────────────────────────
// AUTH
// ─────────────────────────────────────────────
function switchToRegister() {
  document.getElementById("login-form").classList.add("hidden");
  document.getElementById("register-form").classList.remove("hidden");
}

function switchToLogin() {
  document.getElementById("register-form").classList.add("hidden");
  document.getElementById("login-form").classList.remove("hidden");
}

async function handleLogin() {
  const username = document.getElementById("login-username").value.trim();
  const password = document.getElementById("login-password").value;
  const errorEl = document.getElementById("login-error");

  if (!username || !password) {
    errorEl.textContent = "Please enter username and password.";
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();

    if (!res.ok) {
      errorEl.textContent = data.error || "Login failed.";
      return;
    }

    // Save session
    currentUser = { username: data.username, token: data.token };
    localStorage.setItem("shield_user", JSON.stringify(currentUser));
    showApp();
  } catch (e) {
    errorEl.textContent = "Cannot reach server. Is the backend running?";
  }
}

async function handleRegister() {
  const username = document.getElementById("reg-username").value.trim();
  const password = document.getElementById("reg-password").value;
  const errorEl = document.getElementById("reg-error");

  if (!username || !password) {
    errorEl.textContent = "All fields required.";
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();

    if (!res.ok) {
      errorEl.textContent = data.error || "Registration failed.";
      return;
    }

    // Auto-login after register
    currentUser = { username };
    localStorage.setItem("shield_user", JSON.stringify(currentUser));
    showApp();
  } catch (e) {
    errorEl.textContent = "Cannot reach server.";
  }
}

function guestLogin() {
  currentUser = { username: "Guest" };
  showApp();
}

function showApp() {
  document.getElementById("auth-overlay").classList.add("hidden");
  document.getElementById("app").classList.remove("hidden");
  const name = currentUser?.username || "Guest";
  document.getElementById("sidebar-username").textContent = name;
  document.getElementById("user-avatar").textContent = name[0].toUpperCase();
}

function logout() {
  currentUser = null;
  localStorage.removeItem("shield_user");
  document.getElementById("auth-overlay").classList.remove("hidden");
  document.getElementById("app").classList.add("hidden");
}

// ─────────────────────────────────────────────
// NAVIGATION
// ─────────────────────────────────────────────
function switchTab(tabName, clickedEl) {
  // Hide all panels
  document.querySelectorAll(".tab-panel").forEach(p => p.classList.add("hidden"));
  document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));

  // Show selected
  document.getElementById(`tab-${tabName}`).classList.remove("hidden");
  clickedEl.classList.add("active");

  // Auto-load history when switching to it
  if (tabName === "history") loadHistory();
}

// ─────────────────────────────────────────────
// THEME TOGGLE
// ─────────────────────────────────────────────
function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme");
  const next = current === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  localStorage.setItem("shield_theme", next);
  document.querySelector(".theme-btn").textContent = next === "dark" ? "☀" : "🌙";
}

// ─────────────────────────────────────────────
// UTILITY HELPERS
// ─────────────────────────────────────────────
function riskToColor(riskLevel) {
  const map = { "LOW": "var(--green)", "MODERATE": "var(--yellow)", "HIGH": "var(--orange)", "CRITICAL": "var(--red)" };
  return map[riskLevel] || "var(--text-muted)";
}

function riskToClass(riskLevel) {
  const map = { "LOW": "risk-green", "MODERATE": "risk-yellow", "HIGH": "risk-orange", "CRITICAL": "risk-red" };
  return map[riskLevel] || "";
}

function riskToStatusClass(riskLevel) {
  const map = { "LOW": "risk-green", "MODERATE": "risk-yellow", "HIGH": "risk-orange", "CRITICAL": "risk-red" };
  return map[riskLevel] || "";
}

function scoreToColor(score) {
  if (score >= 85) return "var(--green)";
  if (score >= 65) return "var(--yellow)";
  if (score >= 40) return "var(--orange)";
  return "var(--red)";
}

function formatDate(isoString) {
  if (!isoString) return "—";
  const d = new Date(isoString);
  return d.toLocaleString();
}

function showEl(id) { document.getElementById(id).classList.remove("hidden"); }
function hideEl(id) { document.getElementById(id).classList.add("hidden"); }
function setHTML(id, html) { document.getElementById(id).innerHTML = html; }

// ─────────────────────────────────────────────
// SINGLE SCAN
// ─────────────────────────────────────────────
function quickScan(domain) {
  document.getElementById("scan-url").value = domain;
  startScan();
}

async function startScan() {
  const url = document.getElementById("scan-url").value.trim();
  if (!url) return;

  hideEl("scan-results");
  hideEl("scan-error");
  showEl("scan-loading");

  try {
    const res = await fetch(`${API_BASE}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    hideEl("scan-loading");

    if (!res.ok || data.error) {
      document.getElementById("scan-error").textContent = "⚠ " + (data.error || "Unknown error");
      showEl("scan-error");
      return;
    }

    lastScanResult = data;
    renderScanResults(data, "scan-results");
    showEl("scan-results");

  } catch (e) {
    hideEl("scan-loading");
    document.getElementById("scan-error").textContent = "⚠ Cannot connect to backend. Make sure Flask is running on port 5000.";
    showEl("scan-error");
  }
}

// ─────────────────────────────────────────────
// RENDER SCAN RESULTS (used by both scan + compare)
// ─────────────────────────────────────────────
function renderScanResults(data, containerId) {
  const color = scoreToColor(data.score);
  const riskClass = riskToClass(data.risk_level);

  // Build SVG circle progress
  const radius = 40;
  const circ = 2 * Math.PI * radius;
  const offset = circ - (data.score / 100) * circ;

  // Info disclosures
  let disclosureHTML = "";
  if (data.info_disclosures && data.info_disclosures.length > 0) {
    const items = data.info_disclosures.map(d => `
      <div class="info-disclosure-item">
        ⚠ <strong>${d.type}:</strong> ${escapeHtml(d.value)} — ${d.risk}
      </div>
    `).join("");
    disclosureHTML = `
      <div class="info-disclosure-banner">
        <div class="info-disclosure-title">⚠ Information Disclosure Detected</div>
        ${items}
      </div>
    `;
  }

  // Header cards for PRESENT headers
  let foundCards = "";
  if (data.found_headers && data.found_headers.length > 0) {
    foundCards = data.found_headers.map(h => `
      <div class="header-card header-present">
        <div class="header-card-top">
          <div class="header-name-group">
            <div class="header-short">${h.short}</div>
            <div>
              <div class="header-full-name">${h.name}</div>
              <div class="header-category">${h.category}</div>
            </div>
          </div>
          <div class="header-status-icon" title="Present">✅</div>
        </div>
        <div class="header-card-body">
          <div class="header-value-box">${escapeHtml(h.value || "—")}</div>
          <div class="danger-text">✓ This header is correctly configured, protecting against ${h.category} threats.</div>
        </div>
      </div>
    `).join("");
  }

  // Header cards for MISSING headers
  let missingCards = "";
  if (data.missing_headers && data.missing_headers.length > 0) {
    missingCards = data.missing_headers.map(h => `
      <div class="header-card header-missing">
        <div class="header-card-top">
          <div class="header-name-group">
            <div class="header-short">${h.short}</div>
            <div>
              <div class="header-full-name">${h.name}</div>
              <div class="header-category">${h.category}</div>
            </div>
          </div>
          <div class="header-status-icon" title="Missing">❌</div>
        </div>
        <div class="header-card-body">
          <span class="risk-badge ${riskToClass(h.risk)}">${h.risk} RISK</span>
          <div class="danger-text" style="margin-top: 10px">
            <strong style="color: var(--red)">Why this is dangerous:</strong><br>${h.danger}
          </div>
          <div class="fix-box">
            <div class="fix-label">💡 Recommended Fix</div>
            <div class="fix-code">${escapeHtml(h.fix)}</div>
          </div>
          <a href="${h.learn_more}" target="_blank" class="learn-more-link">📖 MDN Documentation →</a>
        </div>
      </div>
    `).join("");
  }

  const httpsStatus = data.is_https
    ? `<div class="meta-chip">🔒 HTTPS</div>`
    : `<div class="meta-chip" style="color:var(--red)">⚠ HTTP (No SSL)</div>`;

  const html = `
    <div id="report-printable">
      <div class="results-header">
        <div class="score-block" style="flex:1">
          <div class="score-circle">
            <svg width="100" height="100" viewBox="0 0 100 100">
              <circle cx="50" cy="50" r="${radius}" fill="none" stroke="var(--border)" stroke-width="8"/>
              <circle cx="50" cy="50" r="${radius}" fill="none" stroke="${color}" stroke-width="8"
                stroke-dasharray="${circ}" stroke-dashoffset="${offset}"
                stroke-linecap="round" style="transition: stroke-dashoffset 1s ease"/>
            </svg>
            <div class="score-circle-text">
              <span class="score-number" style="color:${color}">${data.score}</span>
              <span class="score-label">/ 100</span>
            </div>
          </div>
          <div class="score-details">
            <div class="score-domain">${data.domain}</div>
            <div class="score-meta">
              <span class="risk-badge ${riskClass}">${data.risk_level} RISK</span>
              <span class="meta-chip">Grade: ${data.grade}</span>
              ${httpsStatus}
              <span class="meta-chip">⏱ ${data.response_time_ms}ms</span>
              <span class="meta-chip">HTTP ${data.status_code}</span>
            </div>
            <div class="score-bar-wrapper">
              <div class="score-bar" style="width: ${data.score}%; background: ${color}"></div>
            </div>
            <div style="font-size: 11px; color: var(--text-muted); margin-top: 6px">
              Scanned: ${formatDate(data.scanned_at)}
            </div>
          </div>
        </div>
        <div class="results-actions">
          <button class="btn-action" onclick="exportPDF()">📄 Export PDF</button>
          <button class="btn-action" onclick="loadDomainHistory('${data.domain}')">📈 History</button>
        </div>
      </div>

      <div class="summary-strip">
        <div class="summary-card">
          <div class="summary-value" style="color: var(--accent)">${data.total_headers_checked}</div>
          <div class="summary-key">Headers Checked</div>
        </div>
        <div class="summary-card">
          <div class="summary-value" style="color: var(--green)">${data.headers_present}</div>
          <div class="summary-key">Present</div>
        </div>
        <div class="summary-card">
          <div class="summary-value" style="color: var(--red)">${data.headers_missing}</div>
          <div class="summary-key">Missing</div>
        </div>
        <div class="summary-card">
          <div class="summary-value" style="color: ${color}">${data.grade}</div>
          <div class="summary-key">Security Grade</div>
        </div>
      </div>

      ${disclosureHTML}

      ${missingCards ? `
        <div class="section-title" style="color: var(--red)">❌ Missing Headers (${data.headers_missing})</div>
        <div class="headers-grid">${missingCards}</div>
      ` : ""}

      ${foundCards ? `
        <div class="section-title" style="color: var(--green)">✅ Present Headers (${data.headers_present})</div>
        <div class="headers-grid">${foundCards}</div>
      ` : ""}
    </div>
  `;

  document.getElementById(containerId).innerHTML = html;
}

// ─────────────────────────────────────────────
// COMPARISON
// ─────────────────────────────────────────────
async function startCompare() {
  const url1 = document.getElementById("compare-url1").value.trim();
  const url2 = document.getElementById("compare-url2").value.trim();

  if (!url1 || !url2) return;

  hideEl("compare-results");
  hideEl("compare-error");
  showEl("compare-loading");

  try {
    const res = await fetch(`${API_BASE}/compare`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url1, url2 })
    });
    const data = await res.json();
    hideEl("compare-loading");

    if (!res.ok || data.error) {
      document.getElementById("compare-error").textContent = "⚠ " + data.error;
      showEl("compare-error");
      return;
    }

    renderCompare(data);
    showEl("compare-results");

  } catch (e) {
    hideEl("compare-loading");
    document.getElementById("compare-error").textContent = "⚠ Could not connect to backend.";
    showEl("compare-error");
  }
}

function renderCompare(data) {
  const s1 = data.site1;
  const s2 = data.site2;
  const c = data.comparison;

  const isWinner1 = data.winner === s1.domain;
  const isWinner2 = data.winner === s2.domain;

  const scoreCard = (site, isWinner) => `
    <div class="compare-score-card ${isWinner ? "winner" : ""}">
      ${isWinner ? '<div class="compare-winner-badge">🏆 Winner</div>' : '<div style="height: 24px"></div>'}
      <div class="compare-domain">${site.domain}</div>
      <div class="compare-big-score" style="color: ${scoreToColor(site.score)}">${site.score}</div>
      <div style="color: var(--text-muted); font-size: 12px; margin-bottom: 12px">/ 100 points</div>
      <span class="risk-badge ${riskToClass(site.risk_level)}">${site.risk_level} RISK</span>
      <div style="margin-top: 12px; font-size: 12px; color: var(--text-muted)">
        ${site.headers_present} present · ${site.headers_missing} missing
      </div>
    </div>
  `;

  // Matrix rows
  const matrixRows = c.map(row => {
    const s1Icon = row.site1 ? "✅" : "❌";
    const s2Icon = row.site2 ? "✅" : "❌";
    const winnerCell = row.winner === "site1" ? "← Site A wins"
                     : row.winner === "site2" ? "Site B wins →"
                     : row.winner === "tie" ? "Tie ✓"
                     : "Both missing";
    const winnerColor = row.winner === "tie" ? "var(--green)"
                      : row.winner === "none" ? "var(--red)"
                      : "var(--yellow)";
    return `
      <div class="matrix-row">
        <div class="matrix-name">${row.short} <span style="font-size: 10px; color: var(--text-muted)">${row.header.replace(/-/g,' ')}</span></div>
        <div class="matrix-check">${s1Icon}</div>
        <div class="matrix-check">${s2Icon}</div>
        <div class="matrix-cell" style="font-size: 11px; color: ${winnerColor}">${winnerCell}</div>
      </div>
    `;
  }).join("");

  const html = `
    <div class="compare-scores">
      ${scoreCard(s1, isWinner1)}
      <div class="compare-vs-divider">VS</div>
      ${scoreCard(s2, isWinner2)}
    </div>

    <div class="section-title">Header-by-Header Matrix</div>
    <div class="matrix-table">
      <div class="matrix-header">
        <div>Header</div>
        <div style="text-align:center">${s1.domain.substring(0, 12)}</div>
        <div style="text-align:center">${s2.domain.substring(0, 12)}</div>
        <div>Result</div>
      </div>
      ${matrixRows}
    </div>
  `;

  document.getElementById("compare-results").innerHTML = html;
}

// ─────────────────────────────────────────────
// BATCH SCAN
// ─────────────────────────────────────────────
async function startBatchScan() {
  const raw = document.getElementById("batch-urls").value.trim();
  const urls = raw.split("\n").map(u => u.trim()).filter(u => u.length > 0);

  if (urls.length === 0) return;

  hideEl("batch-results");
  hideEl("batch-error");
  showEl("batch-loading");

  try {
    const res = await fetch(`${API_BASE}/batch-scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ urls })
    });
    const data = await res.json();
    hideEl("batch-loading");

    if (!res.ok || data.error) {
      document.getElementById("batch-error").textContent = "⚠ " + data.error;
      showEl("batch-error");
      return;
    }

    renderBatch(data);
    showEl("batch-results");

  } catch (e) {
    hideEl("batch-loading");
    document.getElementById("batch-error").textContent = "⚠ Could not connect to backend.";
    showEl("batch-error");
  }
}

function renderBatch(data) {
  const summary = data.summary;

  const summaryHTML = `
    <div class="batch-summary">
      <div class="summary-card">
        <div class="summary-value" style="color: var(--accent)">${data.total}</div>
        <div class="summary-key">Sites Scanned</div>
      </div>
      <div class="summary-card">
        <div class="summary-value" style="color: var(--yellow)">${summary.average_score}</div>
        <div class="summary-key">Avg Score</div>
      </div>
      <div class="summary-card">
        <div class="summary-value" style="color: var(--red)">${summary.critical_sites}</div>
        <div class="summary-key">Critical Sites</div>
      </div>
    </div>
  `;

  const resultsHTML = data.results.map((r, i) => {
    if (r.error) return `
      <div class="batch-result-item">
        <div class="batch-rank">#${i+1}</div>
        <div class="batch-domain" style="color: var(--red)">${r.url}</div>
        <div style="font-size:12px; color: var(--red)">Error: ${r.error}</div>
      </div>
    `;
    return `
      <div class="batch-result-item">
        <div class="batch-rank">#${i+1}</div>
        <div class="batch-domain">${r.domain}</div>
        <div class="batch-bar-area">
          <div class="batch-bar-bg">
            <div class="batch-bar-fill" style="width: ${r.score}%; background: ${scoreToColor(r.score)}"></div>
          </div>
          <div style="display:flex; justify-content:space-between; font-size:10px; color: var(--text-muted); margin-top:3px">
            <span>${r.headers_present}/${r.total_headers_checked} headers</span>
            <span class="risk-badge ${riskToClass(r.risk_level)}" style="padding: 2px 8px; font-size:10px">${r.risk_level}</span>
          </div>
        </div>
        <div class="batch-score-text" style="color: ${scoreToColor(r.score)}">${r.score}</div>
      </div>
    `;
  }).join("");

  document.getElementById("batch-results").innerHTML = summaryHTML + `
    <div class="section-title">Results (Ranked by Security Score)</div>
    <div class="batch-results-list">${resultsHTML}</div>
  `;
}

// ─────────────────────────────────────────────
// HISTORY
// ─────────────────────────────────────────────
async function loadHistory() {
  showEl("history-loading");

  try {
    const res = await fetch(`${API_BASE}/history`);
    const data = await res.json();
    hideEl("history-loading");
    renderHistory(data);
  } catch (e) {
    hideEl("history-loading");
    setHTML("history-results", `<div class="error-card">⚠ Could not load history.</div>`);
  }
}

async function loadDomainHistory(domain) {
  // Switch to history tab and filter by domain
  document.querySelectorAll(".tab-panel").forEach(p => p.classList.add("hidden"));
  document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
  document.getElementById("tab-history").classList.remove("hidden");
  document.querySelector('[data-tab="history"]').classList.add("active");
  showEl("history-loading");

  try {
    const res = await fetch(`${API_BASE}/history/${encodeURIComponent(domain)}`);
    const data = await res.json();
    hideEl("history-loading");
    renderDomainHistory(data);
  } catch (e) {
    hideEl("history-loading");
    setHTML("history-results", `<div class="error-card">⚠ Could not load history.</div>`);
  }
}

function renderHistory(list) {
  if (!list || list.length === 0) {
    setHTML("history-results", `
      <div class="empty-state">
        <div class="empty-state-icon">📊</div>
        <p>No scan history yet. Run your first scan!</p>
      </div>
    `);
    return;
  }

  const html = list.map(item => `
    <div class="history-card" onclick="loadDomainHistory('${item.domain}')">
      <div class="history-card-top">
        <div class="history-domain">${item.domain}</div>
        <div class="history-scan-count">${item.scan_count} scan${item.scan_count !== 1 ? 's' : ''}</div>
      </div>
      <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px">
        <div>
          <span class="risk-badge ${riskToClass(item.latest_grade === 'A' ? 'LOW' : item.latest_grade === 'B' ? 'MODERATE' : item.latest_grade === 'C' ? 'HIGH' : 'CRITICAL')}">
            Grade ${item.latest_grade}
          </span>
          <span style="font-size: 12px; color: var(--text-muted); margin-left: 10px">
            Score: ${item.latest_score}/100 · Last: ${formatDate(item.latest_scan)}
          </span>
        </div>
        <span style="font-size: 12px; color: var(--accent)">View trend →</span>
      </div>
    </div>
  `).join("");

  setHTML("history-results", `
    <div class="section-title">All Scanned Domains (${list.length})</div>
    <div class="history-list">${html}</div>
  `);
}

function renderDomainHistory(data) {
  if (!data.scans || data.scans.length === 0) {
    setHTML("history-results", `
      <div class="empty-state">
        <div class="empty-state-icon">📊</div>
        <p>No history for <strong>${data.domain}</strong> yet.</p>
      </div>
    `);
    return;
  }

  const scans = data.scans;

  // Trend visualization
  const maxScore = 100;
  const trendBars = scans.map((s, i) => {
    const prev = scans[i - 1];
    const h = Math.max(4, (s.score / maxScore) * 40);
    let cls = "trend-same";
    if (prev) cls = s.score > prev.score ? "trend-up" : s.score < prev.score ? "trend-down" : "trend-same";
    return `<div class="trend-segment ${cls}" style="height: ${h}px;" title="Score: ${s.score}"></div>`;
  }).join("");

  const rowsHTML = [...scans].reverse().map((s, i) => {
    const prev = scans[scans.length - 2 - i];
    const delta = prev ? s.score - prev.score : null;
    const deltaText = delta === null ? "—"
      : delta > 0 ? `<span style="color: var(--green)">+${delta}</span>`
      : delta < 0 ? `<span style="color: var(--red)">${delta}</span>`
      : `<span style="color: var(--text-muted)">0</span>`;

    return `
      <div class="matrix-row">
        <div style="font-size: 12px; color: var(--text-secondary)">${formatDate(s.scanned_at)}</div>
        <div style="font-family: 'Space Mono'; font-weight: 700; color: ${scoreToColor(s.score)}">${s.score}</div>
        <div><span class="risk-badge ${riskToClass(s.risk_level)}" style="font-size:10px; padding:2px 8px">${s.risk_level}</span></div>
        <div style="font-size: 12px; color: var(--text-secondary)">${s.headers_present}/${s.headers_present + s.headers_missing}</div>
        <div>${deltaText}</div>
      </div>
    `;
  }).join("");

  setHTML("history-results", `
    <div style="margin-bottom: 20px">
      <a href="#" onclick="loadHistory()" style="font-size: 13px; color: var(--text-muted)">← All domains</a>
    </div>

    <div class="score-block" style="margin-bottom: 24px; gap: 20px; align-items: flex-start">
      <div>
        <div class="score-domain">${data.domain}</div>
        <div style="font-size: 13px; color: var(--text-secondary); margin-bottom: 16px">${data.total} scan${data.total !== 1 ? 's' : ''} recorded</div>
        <div class="history-trend">
          <span class="trend-label">Score Trend</span>
          <div class="trend-bar">${trendBars}</div>
        </div>
      </div>
    </div>

    <div class="section-title">Scan Timeline</div>
    <div class="matrix-table">
      <div class="matrix-header">
        <div>Scanned At</div>
        <div>Score</div>
        <div>Risk</div>
        <div>Headers OK</div>
        <div>Change</div>
      </div>
      ${rowsHTML}
    </div>
  `);
}

// ─────────────────────────────────────────────
// PDF EXPORT
// ─────────────────────────────────────────────
async function exportPDF() {
  if (!lastScanResult) return;

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ orientation: "portrait", format: "a4" });

  const d = lastScanResult;
  const pageW = 210;
  let y = 15;

  // Header
  doc.setFillColor(13, 16, 23);
  doc.rect(0, 0, pageW, 40, "F");

  doc.setFont("helvetica", "bold");
  doc.setFontSize(20);
  doc.setTextColor(0, 212, 255);
  doc.text("SHIELD ANALYZER", 15, 20);

  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  doc.setTextColor(120, 130, 160);
  doc.text("Security Header Intelligence Report", 15, 30);
  doc.text(`Generated: ${new Date().toLocaleString()}`, 15, 37);

  y = 55;

  // Domain + score
  doc.setFont("helvetica", "bold");
  doc.setFontSize(16);
  doc.setTextColor(40, 40, 60);
  doc.text(d.domain, 15, y);
  y += 8;

  doc.setFontSize(11);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(80, 90, 110);
  doc.text(`Security Score: ${d.score}/100   Grade: ${d.grade}   Risk: ${d.risk_level}`, 15, y);
  y += 6;
  doc.text(`Scanned: ${formatDate(d.scanned_at)}   Response: ${d.response_time_ms}ms   Status: HTTP ${d.status_code}`, 15, y);
  y += 6;
  doc.text(`HTTPS: ${d.is_https ? 'Yes ✓' : 'No ✗'}   Headers Present: ${d.headers_present}/${d.total_headers_checked}`, 15, y);

  // Score bar
  y += 10;
  doc.setFillColor(230, 230, 240);
  doc.rect(15, y, 180, 6, "F");
  const barColor = d.score >= 85 ? [0, 200, 100] : d.score >= 65 ? [255, 200, 0] : d.score >= 40 ? [255, 130, 0] : [255, 60, 80];
  doc.setFillColor(...barColor);
  doc.rect(15, y, 180 * d.score / 100, 6, "F");
  y += 16;

  // Missing Headers
  if (d.missing_headers && d.missing_headers.length > 0) {
    doc.setFont("helvetica", "bold");
    doc.setFontSize(13);
    doc.setTextColor(220, 50, 80);
    doc.text(`Missing Security Headers (${d.missing_headers.length})`, 15, y);
    y += 8;

    d.missing_headers.forEach(h => {
      if (y > 260) { doc.addPage(); y = 15; }

      doc.setFillColor(255, 245, 248);
      doc.rect(15, y - 4, 180, 26, "F");
      doc.setDrawColor(220, 80, 100);
      doc.rect(15, y - 4, 2, 26, "F");

      doc.setFont("helvetica", "bold");
      doc.setFontSize(11);
      doc.setTextColor(30, 30, 50);
      doc.text(`${h.name}  [${h.risk} RISK]`, 20, y + 2);

      doc.setFont("helvetica", "normal");
      doc.setFontSize(9);
      doc.setTextColor(80, 90, 110);

      // Word-wrap danger text
      const dangerLines = doc.splitTextToSize(`Why: ${h.danger}`, 170);
      doc.text(dangerLines.slice(0,2), 20, y + 8);

      doc.setTextColor(0, 100, 180);
      const fixLines = doc.splitTextToSize(`Fix: ${h.fix}`, 170);
      doc.text(fixLines.slice(0,1), 20, y + 18);

      y += 30;
    });
  }

  y += 4;

  // Present Headers
  if (d.found_headers && d.found_headers.length > 0) {
    if (y > 240) { doc.addPage(); y = 15; }

    doc.setFont("helvetica", "bold");
    doc.setFontSize(13);
    doc.setTextColor(0, 180, 80);
    doc.text(`Present Security Headers (${d.found_headers.length})`, 15, y);
    y += 8;

    d.found_headers.forEach(h => {
      if (y > 275) { doc.addPage(); y = 15; }

      doc.setFillColor(240, 255, 248);
      doc.rect(15, y - 4, 180, 16, "F");
      doc.setDrawColor(0, 180, 80);
      doc.rect(15, y - 4, 2, 16, "F");

      doc.setFont("helvetica", "bold");
      doc.setFontSize(10);
      doc.setTextColor(30, 30, 50);
      doc.text(`✓ ${h.name}`, 20, y + 2);

      doc.setFont("helvetica", "normal");
      doc.setFontSize(8);
      doc.setTextColor(80, 90, 110);
      const valText = (h.value || "").substring(0, 80);
      doc.text(valText, 20, y + 8);

      y += 20;
    });
  }

  // Footer
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(150, 160, 180);
    doc.text(`ShieldAnalyzer — Confidential Security Report · Page ${i} of ${pageCount}`, 15, 292);
  }

  doc.save(`shield-report-${d.domain}-${Date.now()}.pdf`);
}

// ─────────────────────────────────────────────
// XSS HELPER
// ─────────────────────────────────────────────
function escapeHtml(text) {
  if (!text) return "";
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
