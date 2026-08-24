/**
 * Batch Vulnerability Triage Queue Component Controller
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { api } from '../api.js';
import { state } from '../state.js';

let currentBatchResults = null;

export function renderTriageView(containerEl) {
    containerEl.innerHTML = `
        <div class="section-header">
            <div>
                <h2 class="section-title">Batch Vulnerability Triage Queue</h2>
                <p class="section-desc">Organizes multiple vulnerabilities into a deterministically ranked analyst triage queue under controlled asset criticality scenarios (Mode 1 Linear Baseline vs Mode 2 Nonlinear Risk Surface).</p>
            </div>
        </div>

        <div class="workspace-grid" style="grid-template-columns: 340px 1fr; align-items: start;">
            <!-- Batch Controls Form -->
            <div class="card">
                <h3 class="card-title">Batch Configuration</h3>
                
                <div class="input-group" style="margin-bottom: 16px;">
                    <label class="input-label">CVE Identifier List (Paste multiple CVEs)</label>
                    <textarea id="triage-cve-input" class="input-control" rows="7" placeholder="CVE-2021-44228&#10;CVE-2023-23397&#10;CVE-2022-22965&#10;CVE-2021-34527">CVE-2021-44228
CVE-2023-23397
CVE-2022-22965
CVE-2021-34527
CVE-2021-26855</textarea>
                    <div style="font-size: 11px; color: var(--text-sub); margin-top: 4px;">
                        Paste CVE IDs separated by line breaks, commas, or spaces (Max 100 items).
                    </div>
                </div>

                <div class="input-group" style="margin-bottom: 16px;">
                    <label class="input-label">Asset Criticality Tier (x4)</label>
                    <select id="triage-asset-select" class="input-control">
                        <option value="0.25">Tier 1 — Low Criticality (0.25)</option>
                        <option value="0.50">Tier 2 — Medium Criticality (0.50)</option>
                        <option value="0.75" selected>Tier 3 — High Criticality (0.75)</option>
                        <option value="1.00">Tier 4 — Critical Infrastructure (1.00)</option>
                    </select>
                </div>

                <div class="input-group" style="margin-bottom: 20px;">
                    <label class="input-label">Primary Ranking Mode</label>
                    <select id="triage-sort-select" class="input-control">
                        <option value="mode_2" selected>Mode 2 — Nonlinear Risk Surface (Recommended)</option>
                        <option value="mode_1">Mode 1 — Linear Equal-Weights Baseline</option>
                    </select>
                </div>

                <button class="btn btn-primary" id="btn-run-triage" style="width:100%;">
                    Execute Batch Triage Queue
                </button>
            </div>

            <!-- Ranked Queue Output Card -->
            <div class="card">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; flex-wrap:wrap; gap:10px;">
                    <h3 class="card-title" style="margin:0;">Ranked Triage Queue</h3>
                    <div id="triage-export-actions" style="display:none; gap:8px;">
                        <button class="btn btn-outline btn-sm" id="btn-export-csv">Export CSV</button>
                        <button class="btn btn-outline btn-sm" id="btn-export-json">Export JSON</button>
                        <button class="btn btn-outline btn-sm" id="btn-print-report">Print Report</button>
                    </div>
                </div>

                <div id="triage-output-container">
                    <div class="empty-state">
                        <p>Paste multiple CVE IDs and click "Execute Batch Triage Queue" to generate a deterministically ranked priority queue.</p>
                    </div>
                </div>
            </div>
        </div>
    `;

    const btnRun = containerEl.querySelector('#btn-run-triage');
    btnRun.addEventListener('click', async () => {
        const rawInput = containerEl.querySelector('#triage-cve-input').value;
        const assetVal = parseFloat(containerEl.querySelector('#triage-asset-select').value);
        const sortMode = containerEl.querySelector('#triage-sort-select').value;
        const outContainer = containerEl.querySelector('#triage-output-container');
        const exportActions = containerEl.querySelector('#triage-export-actions');

        // Parse CVE IDs from multiline/comma/space separated text
        const cveTokens = rawInput
            .split(/[\n,\s]+/)
            .map(t => t.trim().toUpperCase())
            .filter(t => t.length > 0);

        if (cveTokens.length === 0) {
            outContainer.innerHTML = `
                <div class="error-banner">
                    <strong>Input Error:</strong> Please enter at least one valid CVE ID to triage.
                </div>
            `;
            exportActions.style.display = 'none';
            return;
        }

        if (cveTokens.length > 100) {
            outContainer.innerHTML = `
                <div class="error-banner">
                    <strong>Batch Size Limit Exceeded:</strong> Maximum allowed batch size is 100 items (received ${cveTokens.length} items).
                </div>
            `;
            exportActions.style.display = 'none';
            return;
        }

        const payload = {
            items: cveTokens.map(cve => ({ cve_id: cve })),
            default_asset_criticality: assetVal,
            primary_sort: sortMode,
            sort_dir: "desc"
        };

        outContainer.innerHTML = `
            <div style="padding:40px; text-align:center;">
                <span class="loading-spinner"></span>
                <p style="margin-top:12px; color:var(--text-sub);">Fetching metadata & computing batch triage scores for ${cveTokens.length} items...</p>
            </div>
        `;
        exportActions.style.display = 'none';

        try {
            const response = await api.prioritizeBatch(payload);
            currentBatchResults = response;
            renderTriageQueueResults(outContainer, response);
            exportActions.style.display = 'flex';
        } catch (err) {
            outContainer.innerHTML = `
                <div class="error-banner">
                    <strong>Batch Triage Error:</strong> ${err.message}
                </div>
            `;
            exportActions.style.display = 'none';
        }
    });

    // Export Event Handlers
    containerEl.querySelector('#btn-export-csv').addEventListener('click', () => {
        if (currentBatchResults) downloadBatchCsv(currentBatchResults);
    });

    containerEl.querySelector('#btn-export-json').addEventListener('click', () => {
        if (currentBatchResults) downloadBatchJson(currentBatchResults);
    });

    containerEl.querySelector('#btn-print-report').addEventListener('click', () => {
        window.print();
    });
}

function renderTriageQueueResults(containerEl, data) {
    const summary = data.summary;

    let html = `
        <!-- KPI Summary Cards -->
        <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap:12px; margin-bottom:16px;">
            <div class="stat-card" style="padding:12px;">
                <div class="stat-label">Total Processed</div>
                <div class="stat-value" style="font-size:20px;">${summary.total_processed} / ${summary.total_requested}</div>
            </div>
            <div class="stat-card" style="padding:12px;">
                <div class="stat-label">High Priority (≥0.70)</div>
                <div class="stat-value" style="font-size:20px; color:var(--error);">${summary.high_priority_count}</div>
            </div>
            <div class="stat-card" style="padding:12px;">
                <div class="stat-label">CISA KEV Listed</div>
                <div class="stat-value" style="font-size:20px; color:var(--primary);">${summary.kev_count}</div>
            </div>
            <div class="stat-card" style="padding:12px;">
                <div class="stat-label">Avg Mode 2 Score</div>
                <div class="stat-value" style="font-size:20px;">${summary.avg_mode_2_score.toFixed(4)}</div>
            </div>
            <div class="stat-card" style="padding:12px;">
                <div class="stat-label">Max Score Shift</div>
                <div class="stat-value" style="font-size:20px; color:var(--primary);">+${summary.max_score_shift.toFixed(4)}</div>
            </div>
        </div>

        <!-- Filter Bar -->
        <div style="margin-bottom:12px; display:flex; gap:10px; align-items:center;">
            <input type="text" id="queue-search-filter" class="input-control" placeholder="Filter queue by CVE ID..." style="max-width:240px; padding:6px 10px; font-size:12px;">
            <label style="font-size:12px; cursor:pointer; display:flex; align-items:center; gap:4px;">
                <input type="checkbox" id="queue-kev-only-filter"> KEV Listed Only
            </label>
        </div>

        <!-- Queue Table -->
        <div class="table-container" style="max-height: 520px; overflow-y: auto;">
            <table class="data-table" id="triage-queue-table">
                <thead>
                    <tr>
                        <th style="width:50px;">Rank</th>
                        <th>CVE Identifier</th>
                        <th>CVSS v3.1</th>
                        <th>EPSS Score</th>
                        <th>KEV Status</th>
                        <th>Mode 1 (Lin)</th>
                        <th>Mode 2 (Nonlin)</th>
                        <th>Shift (Δ)</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="triage-queue-tbody">
    `;

    data.items.forEach(item => {
        html += renderQueueRow(item);
    });

    html += `
                </tbody>
            </table>
        </div>
    `;

    containerEl.innerHTML = html;

    // Table Filter Listener
    const searchInput = containerEl.querySelector('#queue-search-filter');
    const kevFilter = containerEl.querySelector('#queue-kev-only-filter');
    const tbody = containerEl.querySelector('#triage-queue-tbody');

    const applyTableFilters = () => {
        const query = searchInput.value.trim().toUpperCase();
        const kevOnly = kevFilter.checked;

        const filtered = data.items.filter(item => {
            const matchesQuery = !query || (item.cve_id && item.cve_id.toUpperCase().includes(query));
            const matchesKev = !kevOnly || item.is_kev === true;
            return matchesQuery && matchesKev;
        });

        tbody.innerHTML = filtered.map(renderQueueRow).join('');
    };

    searchInput.addEventListener('input', applyTableFilters);
    kevFilter.addEventListener('change', applyTableFilters);
}

function renderQueueRow(item) {
    if (item.status !== 'success') {
        const badgeClass = item.status === 'not_found' ? 'badge-warning' : 'badge-danger';
        const labelText = item.status === 'not_found' ? 'Not Found' : 'Validation Error';
        return `
            <tr style="background-color: var(--bg-surface-low); opacity: 0.85;">
                <td><span class="badge" style="background:var(--border-color); color:var(--text-sub);">${item.rank}</span></td>
                <td><strong>${item.cve_id || item.custom_label || 'Unknown'}</strong></td>
                <td colspan="6" style="color: var(--text-sub); font-size: 11px; font-style: italic;">
                    ${item.error_message || 'Processing Error'}
                </td>
                <td><span class="badge ${badgeClass}">${labelText}</span></td>
                <td>—</td>
            </tr>
        `;
    }

    const cvss = item.cvss_score;
    let cvssBadge = 'badge-secondary';
    if (cvss >= 9.0) cvssBadge = 'badge-danger';
    else if (cvss >= 7.0) cvssBadge = 'badge-warning';
    else if (cvss >= 4.0) cvssBadge = 'badge-info';

    const epssPct = item.epss_score !== null ? `${(item.epss_score * 100).toFixed(2)}%` : 'N/A';
    const kevBadge = item.is_kev ? '<span class="badge badge-danger">KEV Listed</span>' : '<span class="badge badge-secondary">No</span>';
    
    const shift = item.score_shift || 0.0;
    const shiftColor = shift >= 0 ? 'color: var(--primary); font-weight:700;' : 'color: var(--error);';

    return `
        <tr>
            <td><strong style="font-family: var(--font-mono); color: var(--primary);">#${item.rank}</strong></td>
            <td>
                <a href="javascript:void(0)" onclick="if(window.showVulnerabilityDetail) window.showVulnerabilityDetail('${item.cve_id}')" style="font-weight:700; color:var(--primary); text-decoration:none;">
                    ${item.cve_id}
                </a>
                ${item.is_analyst_override ? '<span class="badge badge-info" style="font-size:9px; margin-left:4px;">Override</span>' : ''}
            </td>
            <td><span class="badge ${cvssBadge}">${cvss !== null ? cvss.toFixed(1) : 'N/A'}</span></td>
            <td style="font-family:var(--font-mono); font-size:11px;">${epssPct}</td>
            <td>${kevBadge}</td>
            <td style="font-family:var(--font-mono); font-size:12px;">${item.linear_score.toFixed(4)}</td>
            <td style="font-family:var(--font-mono); font-size:12px; font-weight:700; color:var(--primary);">${item.nonlinear_score.toFixed(4)}</td>
            <td style="font-family:var(--font-mono); font-size:11px; ${shiftColor}">${shift >= 0 ? '+' : ''}${shift.toFixed(4)}</td>
            <td><span class="badge badge-success">Processed</span></td>
            <td>
                <button class="btn btn-outline btn-sm" style="padding:2px 6px; font-size:10px;" onclick="if(window.showVulnerabilityDetail) window.showVulnerabilityDetail('${item.cve_id}')">Details</button>
            </td>
        </tr>
    `;
}

function downloadBatchCsv(data) {
    const headers = ["Rank", "CVE_ID", "CVSS_v31", "EPSS_Score", "Is_KEV", "Asset_Criticality", "Mode_1_Linear_Score", "Mode_2_Nonlinear_Score", "Score_Shift_Delta", "Status", "Error_Message"];
    const rows = data.items.map(it => [
        it.rank,
        `"${it.cve_id || ''}"`,
        it.cvss_score !== null ? it.cvss_score : '',
        it.epss_score !== null ? it.epss_score : '',
        it.is_kev !== null ? it.is_kev : '',
        it.asset_criticality,
        it.linear_score !== null ? it.linear_score : '',
        it.nonlinear_score !== null ? it.nonlinear_score : '',
        it.score_shift !== null ? it.score_shift : '',
        `"${it.status}"`,
        `"${it.error_message || ''}"`
    ]);

    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map(r => r.join(","))].join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `triage_queue_${new Date().toISOString().slice(0,10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

function downloadBatchJson(data) {
    const jsonStr = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `triage_queue_${new Date().toISOString().slice(0,10)}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}
