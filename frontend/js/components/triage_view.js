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
                <h2 class="section-title">Batch Triage Queue</h2>
                <p class="section-desc">Organizes multiple vulnerabilities into a deterministically ranked triage queue comparing Mode 1 linear baseline and Mode 2 nonlinear risk surface under controlled asset criticality tiers.</p>
            </div>
        </div>

        <div class="workspace-grid" style="grid-template-columns: 320px 1fr; gap: 24px; align-items: start;">
            <!-- Batch Controls Form -->
            <div class="card">
                <div class="card-header" style="padding-bottom: 12px; margin-bottom: 16px; border-bottom: 1px solid var(--border-subtle);">
                    <div style="display: flex; justify-content: space-between; align-items: baseline; width: 100%;">
                        <h3 class="card-title" style="font-size: 15px;">Queue Parameters</h3>
                        <button type="button" class="btn btn-ghost btn-sm" id="btn-load-sample" style="font-size: 11px; padding: 2px 6px;">
                            Load Sample
                        </button>
                    </div>
                </div>
                
                <div class="form-group" style="margin-bottom: 16px;">
                    <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 4px;">
                        <label class="form-label" for="triage-cve-input" style="margin-bottom: 0;">CVE Identifier List</label>
                        <span id="cve-count-label" style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">5 CVEs</span>
                    </div>
                    <textarea id="triage-cve-input" class="form-textarea" rows="7" style="font-family: var(--font-mono); font-size: 12px; line-height: 1.6;" placeholder="CVE-2021-44228&#10;CVE-2023-23397&#10;CVE-2022-22965">CVE-2021-44228
CVE-2023-23397
CVE-2022-22965
CVE-2021-34527
CVE-2021-26855</textarea>
                    <span class="form-hint">Separate by line breaks, commas, or spaces (Max 100).</span>
                </div>

                <div class="form-group" style="margin-bottom: 16px;">
                    <label class="form-label" for="triage-asset-select">Asset Criticality Tier (x₄)</label>
                    <select id="triage-asset-select" class="form-select">
                        <option value="0.25">Tier 1 · Low Criticality (0.25)</option>
                        <option value="0.50">Tier 2 · Medium Criticality (0.50)</option>
                        <option value="0.75" selected>Tier 3 · High Criticality (0.75)</option>
                        <option value="1.00">Tier 4 · Critical Infrastructure (1.00)</option>
                    </select>
                </div>

                <div class="form-group" style="margin-bottom: 20px;">
                    <label class="form-label" for="triage-sort-select">Primary Ranking Metric</label>
                    <select id="triage-sort-select" class="form-select">
                        <option value="mode_2" selected>Mode 2 · Nonlinear Risk Surface (Recommended)</option>
                        <option value="mode_1">Mode 1 · Linear Baseline</option>
                    </select>
                </div>

                <button class="btn btn-primary" id="btn-run-triage" type="button" style="width: 100%; justify-content: center; height: 38px;">
                    Execute Batch Triage
                </button>
            </div>

            <!-- Ranked Queue Output Card -->
            <div class="card">
                <div class="card-header" style="padding-bottom: 12px; margin-bottom: 16px; border-bottom: 1px solid var(--border-subtle); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
                    <h3 class="card-title" style="font-size: 15px; margin: 0;">Ranked Triage Queue</h3>
                    <div id="triage-export-actions" style="display: none; gap: 6px;">
                        <button class="btn btn-secondary btn-sm" id="btn-export-csv" type="button">CSV</button>
                        <button class="btn btn-secondary btn-sm" id="btn-export-json" type="button">JSON</button>
                        <button class="btn btn-ghost btn-sm" id="btn-print-report" type="button">Print</button>
                    </div>
                </div>

                <div id="triage-output-container">
                    <div class="empty-state" style="padding: 48px 24px;">
                        <div style="font-family: var(--font-mono); font-size: 12px; color: var(--text-muted); margin-bottom: 8px;">QUEUE EMPTY</div>
                        <p style="margin: 0; font-size: 13px; color: var(--text-secondary); max-width: 340px; margin-left: auto; margin-right: auto;">
                            Paste vulnerability identifiers in the left pane and execute triage to compute deterministic dual-mode queue rankings.
                        </p>
                    </div>
                </div>
            </div>
        </div>
    `;

    const cveInput = containerEl.querySelector('#triage-cve-input');
    const cveCountLabel = containerEl.querySelector('#cve-count-label');
    const btnLoadSample = containerEl.querySelector('#btn-load-sample');
    const btnRun = containerEl.querySelector('#btn-run-triage');

    const updateCveCount = () => {
        const tokens = cveInput.value.split(/[\n,\s]+/).map(t => t.trim()).filter(Boolean);
        cveCountLabel.textContent = `${tokens.length} CVE${tokens.length === 1 ? '' : 's'}`;
    };

    cveInput.addEventListener('input', updateCveCount);

    btnLoadSample.addEventListener('click', () => {
        cveInput.value = `CVE-2021-44228\nCVE-2023-23397\nCVE-2022-22965\nCVE-2021-34527\nCVE-2021-26855\nCVE-2023-38606\nCVE-2022-30190\nCVE-2020-1472`;
        updateCveCount();
    });

    btnRun.addEventListener('click', async () => {
        const rawInput = cveInput.value;
        const assetVal = parseFloat(containerEl.querySelector('#triage-asset-select').value);
        const sortMode = containerEl.querySelector('#triage-sort-select').value;
        const outContainer = containerEl.querySelector('#triage-output-container');
        const exportActions = containerEl.querySelector('#triage-export-actions');

        const cveTokens = rawInput
            .split(/[\n,\s]+/)
            .map(t => t.trim().toUpperCase())
            .filter(Boolean);

        if (cveTokens.length === 0) {
            outContainer.innerHTML = `
                <div style="background: var(--bg-muted); border: 1px solid var(--accent-scarlet); border-radius: var(--radius-sm); padding: 14px;">
                    <div style="font-family: var(--font-mono); font-size: 11px; font-weight: 600; color: var(--accent-scarlet);">INPUT ERROR</div>
                    <div style="font-size: 13px; color: var(--text-primary); margin-top: 4px;">Please provide at least one CVE identifier.</div>
                </div>
            `;
            exportActions.style.display = 'none';
            return;
        }

        if (cveTokens.length > 100) {
            outContainer.innerHTML = `
                <div style="background: var(--bg-muted); border: 1px solid var(--accent-scarlet); border-radius: var(--radius-sm); padding: 14px;">
                    <div style="font-family: var(--font-mono); font-size: 11px; font-weight: 600; color: var(--accent-scarlet);">LIMIT EXCEEDED</div>
                    <div style="font-size: 13px; color: var(--text-primary); margin-top: 4px;">Maximum queue batch size is 100 items (submitted ${cveTokens.length}).</div>
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
            <div style="padding: 48px 24px; text-align: center;">
                <span class="loading-spinner"></span>
                <p style="margin-top: 14px; font-size: 13px; color: var(--text-secondary);">Querying metadata and calculating dual-mode queue rankings for ${cveTokens.length} items...</p>
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
                <div style="background: var(--bg-muted); border: 1px solid var(--accent-scarlet); border-radius: var(--radius-sm); padding: 16px;">
                    <div style="font-family: var(--font-mono); font-size: 12px; font-weight: 600; color: var(--accent-scarlet);">BATCH EXECUTION ERROR</div>
                    <div style="margin-top: 6px; font-size: 13px; color: var(--text-primary); line-height: 1.5;">${escapeHtml(err.message)}</div>
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
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 10px; margin-bottom: 16px;">
            <div class="card" style="padding: 10px 12px; margin-bottom: 0;">
                <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em;">Processed</div>
                <div style="font-family: var(--font-mono); font-size: 18px; font-weight: 700; color: var(--text-primary); margin-top: 2px;">
                    ${summary.total_processed} / ${summary.total_requested}
                </div>
            </div>
            <div class="card" style="padding: 10px 12px; margin-bottom: 0;">
                <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em;">High Priority</div>
                <div style="font-family: var(--font-mono); font-size: 18px; font-weight: 700; color: var(--accent-scarlet); margin-top: 2px;">
                    ${summary.high_priority_count}
                </div>
            </div>
            <div class="card" style="padding: 10px 12px; margin-bottom: 0;">
                <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em;">KEV Listed</div>
                <div style="font-family: var(--font-mono); font-size: 18px; font-weight: 700; color: var(--accent-scarlet); margin-top: 2px;">
                    ${summary.kev_count}
                </div>
            </div>
            <div class="card" style="padding: 10px 12px; margin-bottom: 0;">
                <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em;">Avg Mode 2</div>
                <div style="font-family: var(--font-mono); font-size: 18px; font-weight: 700; color: var(--text-primary); margin-top: 2px;">
                    ${summary.avg_mode_2_score.toFixed(4)}
                </div>
            </div>
            <div class="card" style="padding: 10px 12px; margin-bottom: 0;">
                <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em;">Max Shift (Δ)</div>
                <div style="font-family: var(--font-mono); font-size: 18px; font-weight: 700; color: var(--accent-gold); margin-top: 2px;">
                    +${summary.max_score_shift.toFixed(4)}
                </div>
            </div>
        </div>

        <!-- Filter Bar -->
        <div style="margin-bottom: 12px; display: flex; gap: 14px; align-items: center; flex-wrap: wrap;">
            <input type="text" id="queue-search-filter" class="form-input" placeholder="Filter queue by CVE ID..." style="max-width: 220px; font-size: 12px; padding: 6px 10px;">
            <label style="font-size: 12px; cursor: pointer; display: flex; align-items: center; gap: 6px; color: var(--text-secondary); user-select: none;">
                <input type="checkbox" id="queue-kev-only-filter"> Listed in KEV only
            </label>
        </div>

        <!-- Queue Table -->
        <div class="table-container" style="max-height: 480px; overflow-y: auto;">
            <table class="data-table" id="triage-queue-table">
                <thead>
                    <tr>
                        <th style="width: 44px; text-align: center;">Rank</th>
                        <th>CVE Identifier</th>
                        <th>CVSS v3.1</th>
                        <th>EPSS Score</th>
                        <th>KEV</th>
                        <th>Mode 1 (Lin)</th>
                        <th>Mode 2 (Nonlin)</th>
                        <th>Shift (Δ)</th>
                        <th>Status</th>
                        <th style="text-align: right;">Action</th>
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
        const labelText = item.status === 'not_found' ? 'Not Found' : 'Error';
        return `
            <tr style="opacity: 0.65;">
                <td style="text-align: center; font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">${item.rank}</td>
                <td><strong style="font-family: var(--font-mono); font-size: 12px;">${escapeHtml(item.cve_id || item.custom_label || 'Unknown')}</strong></td>
                <td colspan="6" style="color: var(--text-muted); font-size: 11px; font-style: italic;">
                    ${escapeHtml(item.error_message || 'Processing Error')}
                </td>
                <td><span class="badge badge-neutral" style="font-size: 10px;">${labelText}</span></td>
                <td>—</td>
            </tr>
        `;
    }

    const cvss = item.cvss_score;
    let cvssBadge = 'badge-neutral';
    if (cvss >= 9.0) cvssBadge = 'badge-scarlet';
    else if (cvss >= 7.0) cvssBadge = 'badge-gold';

    const epssPct = item.epss_score !== null ? `${(item.epss_score * 100).toFixed(2)}%` : '—';
    const kevBadge = item.is_kev ? '<span class="badge badge-scarlet">KEV</span>' : '<span style="color: var(--text-muted); font-size: 11px;">—</span>';
    
    const shift = item.score_shift || 0.0;
    const isPos = shift >= 0;

    return `
        <tr>
            <td style="text-align: center; font-family: var(--font-mono); font-size: 12px; font-weight: 600; color: var(--text-primary);">
                #${item.rank}
            </td>
            <td>
                <a href="javascript:void(0)" onclick="if(window.showVulnerabilityDetail) window.showVulnerabilityDetail('${escapeHtml(item.cve_id)}')" style="font-family: var(--font-mono); font-weight: 600; font-size: 12px; color: var(--text-primary); text-decoration: none;">
                    ${escapeHtml(item.cve_id)}
                </a>
                ${item.is_analyst_override ? '<span class="badge badge-neutral" style="font-size: 9px; margin-left: 4px;">Override</span>' : ''}
            </td>
            <td><span class="badge ${cvssBadge}">${cvss !== null ? cvss.toFixed(1) : '—'}</span></td>
            <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-secondary);">${epssPct}</td>
            <td>${kevBadge}</td>
            <td style="font-family: var(--font-mono); font-size: 12px; color: var(--text-secondary);">${item.linear_score.toFixed(4)}</td>
            <td style="font-family: var(--font-mono); font-size: 12px; font-weight: 700; color: var(--text-primary);">${item.nonlinear_score.toFixed(4)}</td>
            <td style="font-family: var(--font-mono); font-size: 11px; color: ${isPos ? 'var(--accent-scarlet)' : 'var(--text-secondary)'};">
                ${isPos ? '+' : ''}${shift.toFixed(4)}
            </td>
            <td><span class="badge badge-success" style="font-size: 10px;">Processed</span></td>
            <td style="text-align: right;">
                <button class="btn btn-ghost btn-sm" style="padding: 2px 6px; font-size: 11px;" type="button" onclick="if(window.showVulnerabilityDetail) window.showVulnerabilityDetail('${escapeHtml(item.cve_id)}')">Detail</button>
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

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
