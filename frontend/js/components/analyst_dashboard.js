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
                <h2 class="section-title">Security Analyst Operational Workspace</h2>
                <p class="section-desc">Active threat triage queue, CISA KEV catalog highlights, dual-mode priority scoring, and recent inspection audit trail.</p>
            </div>
            <span class="badge badge-gold" style="font-size: 11px;">Role: Security Analyst</span>
        </div>

        <div id="analyst-status-container"></div>

        <!-- Operational KPIs -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 14px; margin-bottom: 24px;">
            <div class="card" style="padding: 14px 16px; margin-bottom: 0;">
                <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em;">Canonical Corpus</div>
                <div style="font-family: var(--font-mono); font-size: 22px; font-weight: 700; color: var(--text-primary); margin-top: 4px;" id="analyst-stat-cves">366,547</div>
                <div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px;">NVD CVEs (2002–2026)</div>
            </div>

            <div class="card" style="padding: 14px 16px; margin-bottom: 0; border-top: 3px solid var(--accent-scarlet);">
                <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--accent-scarlet); letter-spacing: 0.04em;">CISA KEV Exploited</div>
                <div style="font-family: var(--font-mono); font-size: 22px; font-weight: 700; color: var(--accent-scarlet); margin-top: 4px;" id="analyst-stat-kev">1,647</div>
                <div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px;">Confirmed in-the-wild threats</div>
            </div>

            <div class="card" style="padding: 14px 16px; margin-bottom: 0;">
                <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em;">EPSS Coverage</div>
                <div style="font-family: var(--font-mono); font-size: 22px; font-weight: 700; color: var(--text-primary); margin-top: 4px;" id="analyst-stat-epss">348,900</div>
                <div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px;">Snapshot 2026-07-16</div>
            </div>

            <div class="card" style="padding: 14px 16px; margin-bottom: 0;">
                <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em;">Prioritization Surface</div>
                <div style="font-family: var(--font-mono); font-size: 18px; font-weight: 700; color: var(--text-primary); margin-top: 8px;">Dual-Mode Engine</div>
                <div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px;">Mode 1 Linear & Mode 2 Surface</div>
            </div>
        </div>

        <!-- Guided Workflows -->
        <div style="margin-bottom: 24px;">
            <div style="font-family: var(--font-mono); font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-muted); margin-bottom: 12px;">
                OPERATIONAL WORKFLOWS
            </div>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px;">
                <div class="card" style="margin-bottom: 0; cursor: pointer; padding: 16px; transition: all var(--transition-fast);" onclick="window.location.hash='explorer'">
                    <div style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 4px;">1. Explorer & Search &rarr;</div>
                    <div style="font-size: 12px; color: var(--text-secondary); line-height: 1.5;">Query 366,547 CVEs by vendor, CWE weakness, and CVSS range.</div>
                </div>

                <div class="card" style="margin-bottom: 0; cursor: pointer; padding: 16px; transition: all var(--transition-fast);" onclick="window.location.hash='triage'">
                    <div style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 4px;">2. Batch Triage Queue &rarr;</div>
                    <div style="font-size: 12px; color: var(--text-secondary); line-height: 1.5;">Rank multiple vulnerability lists under asset criticality tiers.</div>
                </div>

                <div class="card" style="margin-bottom: 0; cursor: pointer; padding: 16px; transition: all var(--transition-fast);" onclick="window.location.hash='prioritize'">
                    <div style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 4px;">3. Prioritization Sandbox &rarr;</div>
                    <div style="font-size: 12px; color: var(--text-secondary); line-height: 1.5;">Compare Mode 1 linear baseline vs Mode 2 interactive surface.</div>
                </div>

                <div class="card" style="margin-bottom: 0; cursor: pointer; padding: 16px; transition: all var(--transition-fast);" onclick="window.location.hash='predict'">
                    <div style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 4px;">4. ML Predictions &rarr;</div>
                    <div style="font-size: 12px; color: var(--text-secondary); line-height: 1.5;">Run EXP-A1 CVSS estimation or EXP-B2 publication-time KEV risk.</div>
                </div>
            </div>
        </div>

        <div class="workspace-grid" style="grid-template-columns: 1.2fr 0.8fr; gap: 24px; align-items: start;">
            <!-- Active KEV High-Priority Triage Panel -->
            <div class="card">
                <div class="card-header" style="padding-bottom: 12px; margin-bottom: 16px; border-bottom: 1px solid var(--border-subtle); display: flex; justify-content: space-between; align-items: center;">
                    <h3 class="card-title" style="font-size: 15px; margin: 0;">Recent CISA KEV Exploitations</h3>
                    <button class="btn btn-secondary btn-sm" onclick="window.location.hash='explorer'">View in Explorer</button>
                </div>
                <div class="table-container">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>CVE ID</th>
                                <th>CVSS v3.1</th>
                                <th>EPSS</th>
                                <th>Published</th>
                                <th style="text-align: right;">Action</th>
                            </tr>
                        </thead>
                        <tbody id="analyst-kev-table-body">
                            <tr><td colspan="5" style="text-align: center; color: var(--text-secondary); padding: 24px;">Querying KEV entries...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Recently Visited CVE Triage History (localStorage) -->
            <div class="card">
                <div class="card-header" style="padding-bottom: 12px; margin-bottom: 16px; border-bottom: 1px solid var(--border-subtle);">
                    <h3 class="card-title" style="font-size: 15px; margin: 0;">Inspection History</h3>
                    <p style="font-size: 12px; color: var(--text-secondary); margin: 2px 0 0 0;">Recently examined vulnerabilities in local session.</p>
                </div>
                <div id="analyst-recent-history-container">
                    <!-- Populated dynamically -->
                </div>
            </div>
        </div>
    `;

    loadAnalystDashboardData(containerEl);
}

async function loadAnalystDashboardData(containerEl) {
    const kevTbody = containerEl.querySelector('#analyst-kev-table-body');
    try {
        const res = await api.getVulnerabilities({ is_kev: 'true', page_size: 5, sort_by: 'published', sort_dir: 'desc' });
        if (res && res.items && res.items.length > 0) {
            kevTbody.innerHTML = res.items.map(item => {
                const cvss = item.authoritative_cvss_v31_base_score;
                const cvssBadge = cvss >= 9.0 ? 'badge-scarlet' : cvss >= 7.0 ? 'badge-gold' : 'badge-neutral';
                const epssPct = item.epss_score !== null ? (item.epss_score * 100).toFixed(2) + '%' : '—';
                const pubDate = item.published_date ? item.published_date.split('T')[0] : '—';

                return `
                    <tr>
                        <td style="font-family: var(--font-mono); font-weight: 600; color: var(--text-primary); font-size: 12px;">${escapeHtml(item.cve_id)}</td>
                        <td><span class="badge ${cvssBadge}" style="font-size: 10px;">${cvss !== null ? cvss.toFixed(1) : '—'}</span></td>
                        <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-secondary);">${epssPct}</td>
                        <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">${pubDate}</td>
                        <td style="text-align: right;">
                            <button class="btn btn-ghost btn-sm analyst-triage-btn" data-cve="${escapeHtml(item.cve_id)}" type="button" style="padding: 2px 8px; font-size: 11px;">
                                Prioritize
                            </button>
                        </td>
                    </tr>
                `;
            }).join('');

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
            kevTbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 16px;">Unable to load KEV records.</td></tr>`;
        }
    }

    // Load Recent History from localStorage
    const historyContainer = containerEl.querySelector('#analyst-recent-history-container');
    try {
        const recentStr = localStorage.getItem('wdl_recent_cves');
        const recentItems = recentStr ? JSON.parse(recentStr) : [];
        if (recentItems.length === 0) {
            historyContainer.innerHTML = `
                <div style="font-size: 12px; color: var(--text-muted); background: var(--bg-muted); padding: 16px; border-radius: var(--radius-sm); text-align: center;">
                    No recent vulnerability detail inspections. Click any CVE in the Explorer to inspect details.
                </div>
            `;
        } else {
            historyContainer.innerHTML = `
                <div style="display: flex; flex-direction: column; gap: 8px;">
                    ${recentItems.slice(0, 5).map(r => `
                        <div style="display: flex; justify-content: space-between; align-items: center; background: var(--bg-muted); padding: 10px 12px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
                            <div>
                                <span style="font-family: var(--font-mono); font-size: 12px; font-weight: 600; color: var(--text-primary);">${escapeHtml(r.cve_id)}</span>
                                <span style="font-size: 11px; color: var(--text-secondary); margin-left: 8px;">CVSS: ${r.cvss !== null ? r.cvss : '—'}</span>
                            </div>
                            <button class="btn btn-ghost btn-sm history-open-btn" data-cve="${escapeHtml(r.cve_id)}" type="button" style="padding: 2px 8px; font-size: 11px;">Inspect</button>
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
        historyContainer.innerHTML = `<div style="font-size: 12px; color: var(--text-muted);">No history available.</div>`;
    }
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
