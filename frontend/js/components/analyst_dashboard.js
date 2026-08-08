/**
 * Security Analyst Role Dashboard Component
 * Purpose: Operational Vulnerability Triage & Remediation Prioritization
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { api } from '../api.js';
import { state } from '../state.js';

export function renderAnalystDashboard(containerEl) {
    containerEl.innerHTML = `
        <div class="section-header">
            <div>
                <h2 class="section-title">Security Analyst Operational Triage Dashboard</h2>
                <p class="section-desc">Real-time vulnerability triage, active threat discovery, KEV catalog highlights, and guided triage workflows.</p>
            </div>
            <span class="badge badge-low" style="font-size: 12px; padding: 6px 12px;">Active Role: Security Analyst</span>
        </div>

        <div id="analyst-status-container"></div>

        <!-- Operational Triage KPIs -->
        <div class="provenance-grid" style="margin-bottom: 24px;">
            <div class="provenance-stat-box">
                <div class="provenance-stat-label">Total Canonical CVEs</div>
                <div class="provenance-stat-val" id="analyst-stat-cves">366,547</div>
                <div style="font-size: 11px; color: var(--text-sub); margin-top: 4px;">NVD CVE Dataset (2002–2026)</div>
            </div>

            <div class="provenance-stat-box" style="border-left: 4px solid var(--error);">
                <div class="provenance-stat-label">CISA KEV Exploited CVEs</div>
                <div class="provenance-stat-val" id="analyst-stat-kev" style="color: var(--error);">1,647</div>
                <div style="font-size: 11px; color: var(--error); font-weight: 600; margin-top: 4px;">Active In-the-Wild Exploitation</div>
            </div>

            <div class="provenance-stat-box">
                <div class="provenance-stat-label">EPSS Snapshot Coverage</div>
                <div class="provenance-stat-val" id="analyst-stat-epss">348,900</div>
                <div style="font-size: 11px; color: var(--text-sub); margin-top: 4px;">Snapshot Dated 2026-07-16</div>
            </div>

            <div class="provenance-stat-box">
                <div class="provenance-stat-label">Prioritization Engine</div>
                <div class="provenance-stat-val" style="font-size: 16px; color: var(--primary);">Dual-Mode Ready</div>
                <div style="font-size: 11px; color: var(--text-sub); margin-top: 4px;">Mode 1 Linear & Mode 2 Surface</div>
            </div>
        </div>

        <!-- Operational Guided Workflow Grid -->
        <h3 class="section-title" style="font-size: 16px; margin-bottom: 12px;">Operational Triage Workflow</h3>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 14px; margin-bottom: 24px;">
            <div class="card" style="margin-bottom: 0; cursor: pointer; border-left: 3px solid var(--primary);" onclick="window.location.hash='explorer'">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <strong style="font-size: 13px; color: var(--primary);">Step 1: Explore & Filter</strong>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
                </div>
                <p style="font-size: 12px; color: var(--text-sub);">Search 366,547 CVEs by vendor, CWE weakness, CVSS range, and KEV presence.</p>
            </div>

            <div class="card" style="margin-bottom: 0; cursor: pointer; border-left: 3px solid var(--tertiary);" onclick="window.location.hash='predict'">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <strong style="font-size: 13px; color: var(--tertiary);">Step 2: Predict Risk</strong>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
                </div>
                <p style="font-size: 12px; color: var(--text-sub);">Run EXP-A1 CVSS estimation or EXP-B2 publication-time KEV risk classifier.</p>
            </div>

            <div class="card" style="margin-bottom: 0; cursor: pointer; border-left: 3px solid var(--success);" onclick="window.location.hash='prioritize'">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <strong style="font-size: 13px; color: var(--success);">Step 3: Asset Prioritization</strong>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
                </div>
                <p style="font-size: 12px; color: var(--text-sub);">Simulate Asset Criticality Tiers (0.25 to 1.00) using Mode 1 vs Mode 2 surfaces.</p>
            </div>

            <div class="card" style="margin-bottom: 0; cursor: pointer; border-left: 3px solid var(--primary);" onclick="window.location.hash='explain'">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <strong style="font-size: 13px; color: var(--primary);">Step 4: Explain Features</strong>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
                </div>
                <p style="font-size: 12px; color: var(--text-sub);">Inspect local SHAP TreeExplainer feature attributions and disclosure signals.</p>
            </div>
        </div>

        <div class="workspace-grid" style="margin-bottom: 24px;">
            <!-- Active KEV High-Priority Triage Panel -->
            <div class="card" style="margin-bottom: 0;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                    <h3 class="card-title" style="margin-bottom: 0;">CISA KEV Catalog Highlights</h3>
                    <button class="btn btn-outline btn-sm" onclick="window.location.hash='explorer'">View All in Explorer &rarr;</button>
                </div>
                <div style="overflow-x: auto;">
                    <table class="triage-table">
                        <thead>
                            <tr>
                                <th>CVE ID</th>
                                <th>CVSS v3.1</th>
                                <th>EPSS Score</th>
                                <th>Published</th>
                                <th>Triage Action</th>
                            </tr>
                        </thead>
                        <tbody id="analyst-kev-table-body">
                            <tr><td colspan="5" style="text-align: center; color: var(--text-sub); padding: 16px;">Loading active KEV vulnerabilities...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Recently Visited CVE Triage History (localStorage) -->
            <div class="card" style="margin-bottom: 0;">
                <h3 class="card-title">Recent Analyst Triage History</h3>
                <p style="font-size: 12px; color: var(--text-sub); margin-bottom: 12px;">Recently inspected vulnerabilities saved in local session history.</p>
                <div id="analyst-recent-history-container">
                    <!-- Populated dynamically -->
                </div>
            </div>
        </div>
    `;

    loadAnalystDashboardData(containerEl);
}

async function loadAnalystDashboardData(containerEl) {
    // Load KEV Vulnerabilities for Triage Table
    const kevTbody = containerEl.querySelector('#analyst-kev-table-body');
    try {
        const res = await api.getVulnerabilities({ is_kev: 'true', page_size: 5, sort_by: 'published', sort_dir: 'desc' });
        if (res && res.items && res.items.length > 0) {
            kevTbody.innerHTML = res.items.map(item => `
                <tr>
                    <td style="font-family: var(--font-mono); font-weight: 600; color: var(--primary);">${item.cve_id}</td>
                    <td>
                        <span class="badge ${item.authoritative_cvss_v31_base_score >= 9.0 ? 'badge-high' : 'badge-medium'}">
                            ${item.authoritative_cvss_v31_base_score !== null ? item.authoritative_cvss_v31_base_score.toFixed(1) : 'N/A'}
                        </span>
                    </td>
                    <td style="font-family: var(--font-mono); font-size: 12px;">
                        ${item.epss_score !== null ? (item.epss_score * 100).toFixed(2) + '%' : 'N/A'}
                    </td>
                    <td style="font-size: 11px; color: var(--text-sub);">${item.published_date ? item.published_date.split('T')[0] : 'N/A'}</td>
                    <td>
                        <button class="btn btn-outline btn-sm analyst-triage-btn" data-cve="${item.cve_id}" style="padding: 2px 8px; font-size: 11px;">
                            Prioritize &rarr;
                        </button>
                    </td>
                </tr>
            `).join('');

            kevTbody.querySelectorAll('.analyst-triage-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    const cveId = btn.getAttribute('data-cve');
                    state.setState({
                        prioritizationInput: {
                            ...state.getState().prioritizationInput,
                            cve_id: cveId
                        }
                    });
                    window.location.hash = 'prioritize';
                });
            });
        }
    } catch (err) {
        if (kevTbody) {
            kevTbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-sub);">Unable to fetch live KEV vulnerabilities.</td></tr>`;
        }
    }

    // Load Recent History from localStorage
    const historyContainer = containerEl.querySelector('#analyst-recent-history-container');
    try {
        const recentStr = localStorage.getItem('wdl_recent_cves');
        const recentItems = recentStr ? JSON.parse(recentStr) : [];
        if (recentItems.length === 0) {
            historyContainer.innerHTML = `
                <div style="font-size: 12px; color: var(--text-sub); background: var(--bg-surface-low); padding: 12px; border-radius: var(--radius-md); text-align: center;">
                    No recent vulnerability detail inspections in this session. Inspect CVEs in the Explorer to add them to your history.
                </div>
            `;
        } else {
            historyContainer.innerHTML = `
                <div style="display: flex; flex-direction: column; gap: 8px;">
                    ${recentItems.slice(0, 5).map(r => `
                        <div style="display: flex; justify-content: space-between; align-items: center; background: var(--bg-surface-low); padding: 10px; border-radius: var(--radius-md); border: 1px solid var(--border-color);">
                            <div>
                                <strong style="font-family: var(--font-mono); font-size: 12px; color: var(--primary);">${r.cve_id}</strong>
                                <span style="font-size: 11px; color: var(--text-sub); margin-left: 6px;">CVSS: ${r.cvss || 'N/A'}</span>
                            </div>
                            <button class="btn btn-outline btn-sm history-open-btn" data-cve="${r.cve_id}" style="padding: 2px 8px; font-size: 11px;">View Detail</button>
                        </div>
                    `).join('')}
                </div>
            `;

            historyContainer.querySelectorAll('.history-open-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    const cveId = btn.getAttribute('data-cve');
                    state.setState({ selectedCveId: cveId });
                });
            });
        }
    } catch (e) {
        historyContainer.innerHTML = `<div style="font-size: 12px; color: var(--text-sub);">No history available.</div>`;
    }
}
