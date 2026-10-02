/**
 * Vulnerability Detail Slide-Over Drawer Component
 * Visual Direction: Structured, editorial, research-grade contextual inspection
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { state } from '../state.js';

export function renderDetailModal(containerEl) {
    containerEl.innerHTML = `
        <div class="drawer-backdrop" id="detail-backdrop" role="dialog" aria-modal="true" aria-labelledby="drawer-cve-id">
            <div class="drawer-panel">
                <div class="drawer-header">
                    <div class="drawer-title-group">
                        <div class="drawer-title" id="drawer-cve-id">CVE Detail</div>
                        <div class="drawer-subtitle" id="drawer-pub-date">Published Date</div>
                    </div>
                    <div style="display: flex; gap: 8px;">
                        <button class="btn btn-outline btn-sm" id="btn-print-report" title="Generate printable vulnerability triage report">
                            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>
                            Print Report
                        </button>
                        <button class="btn btn-outline btn-sm" id="btn-close-drawer" aria-label="Close drawer">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                            Close
                        </button>
                    </div>
                </div>
                <div class="drawer-body" id="drawer-body-content">
                    <!-- Loaded dynamically -->
                </div>
            </div>
        </div>
    `;

    const backdrop = containerEl.querySelector('#detail-backdrop');
    const closeBtn = containerEl.querySelector('#btn-close-drawer');
    const printBtn = containerEl.querySelector('#btn-print-report');

    const closeDrawer = () => {
        state.setState({ selectedCveId: null, cveDetail: null });
    };

    closeBtn.addEventListener('click', closeDrawer);
    printBtn.addEventListener('click', () => {
        const d = state.getState().cveDetail;
        if (d) printVulnerabilityReport(d);
    });
    backdrop.addEventListener('click', (e) => {
        if (e.target === backdrop) closeDrawer();
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && state.getState().selectedCveId) {
            closeDrawer();
        }
    });

    state.subscribe(s => {
        if (s.selectedCveId) {
            backdrop.classList.add('open');
            renderDrawerBody(containerEl, s);
        } else {
            backdrop.classList.remove('open');
        }
    });
}

function renderDrawerBody(containerEl, s) {
    const cveTitle = containerEl.querySelector('#drawer-cve-id');
    const pubDate = containerEl.querySelector('#drawer-pub-date');
    const body = containerEl.querySelector('#drawer-body-content');

    if (!body) return;

    if (s.isDetailLoading) {
        body.innerHTML = `
            <div style="padding: 40px; text-align: center;">
                <span class="loading-spinner"></span>
                <p style="margin-top: 12px; font-size: 13px; color: var(--text-secondary);">
                    Retrieving canonical record for ${escapeHtml(s.selectedCveId)}...
                </p>
            </div>
        `;
        return;
    }

    if (s.detailError) {
        body.innerHTML = `
            <div class="error-banner">
                <strong>Error fetching details:</strong> ${escapeHtml(s.detailError)}
            </div>
        `;
        return;
    }

    const d = s.cveDetail;
    if (!d) return;

    saveRecentCveToLocalStorage(d);

    cveTitle.textContent = d.cve_id;
    pubDate.textContent = `Published: ${d.published ? d.published.substring(0, 10) : 'Unknown'}`;

    // CVSS Badge & Class
    const cvssVal = d.authoritative_cvss_v31_base_score;
    let cvssBadgeClass = 'badge-low';
    if (cvssVal >= 9.0) cvssBadgeClass = 'badge-critical';
    else if (cvssVal >= 7.0) cvssBadgeClass = 'badge-high';
    else if (cvssVal >= 4.0) cvssBadgeClass = 'badge-medium';
    else if (cvssVal === null) cvssBadgeClass = 'badge-neutral';

    const cvssDisplay = cvssVal !== null ? `${cvssVal.toFixed(1)} ${d.cvss_v31_base_severity || ''}` : 'Unscored';
    const epssDisplay = d.epss 
        ? `${(d.epss.epss_score * 100).toFixed(2)}% (Percentile: ${(d.epss.epss_percentile * 100).toFixed(0)}th)` 
        : 'N/A';

    // KEV Callout
    let kevHtml = '';
    if (d.is_kev) {
        kevHtml = `
            <div class="callout-box callout-scarlet">
                <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 4px;">
                    <strong>CISA Known Exploited Vulnerability</strong>
                    <span style="font-family: var(--font-mono); font-size: 11px;">Added: ${d.kev_date_added || 'N/A'}</span>
                </div>
                <div style="margin-bottom: 4px; font-weight: 600;">${escapeHtml(d.kev_vulnerability_name || d.cve_id)}</div>
                <div style="margin-bottom: 6px;">${escapeHtml(d.kev_short_description || '')}</div>
                <div><strong>Action Required:</strong> ${escapeHtml(d.kev_required_action || 'Remediate per CISA directive.')}</div>
                ${d.kev_ransomware_campaign_use === 'Known' 
                    ? '<div style="margin-top: 6px; font-weight: 700; font-family: var(--font-mono); font-size: 11px;">[!] KNOWN RANSOMWARE CAMPAIGN USE</div>' 
                    : ''}
            </div>
        `;
    }

    // CWE Badges
    const cweBadges = d.cwes && d.cwes.length > 0
        ? d.cwes.map(c => `<span class="badge ${c.is_semantic_cwe ? 'badge-high' : 'badge-neutral'}">${c.cwe_id}</span>`).join(' ')
        : '<span style="color:var(--text-muted); font-size:12px;">No CWE taxonomy classified</span>';

    // CPE Applicability Rows
    const cpeListHtml = d.cpes && d.cpes.length > 0
        ? d.cpes.map(c => `
            <tr>
                <td style="font-family: var(--font-mono);">${c.part || '—'}</td>
                <td>${escapeHtml(c.vendor || '—')}</td>
                <td>${escapeHtml(c.product || '—')}</td>
                <td style="font-family: var(--font-mono);">${escapeHtml(c.version || '*')}</td>
            </tr>
        `).join('')
        : '<tr><td colspan="4" style="color:var(--text-muted); text-align:center;">No structured CPE applicability nodes</td></tr>';

    body.innerHTML = `
        <!-- Threat & Severity Status Strip -->
        <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px;">
            <div style="background-color: var(--bg-elevated); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: 10px;">
                <div class="input-label">CVSS v3.1</div>
                <div style="margin-top: 4px;"><span class="badge ${cvssBadgeClass}">${cvssDisplay}</span></div>
            </div>
            <div style="background-color: var(--bg-elevated); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: 10px;">
                <div class="input-label">EPSS Snapshot</div>
                <div style="font-family: var(--font-mono); font-size: 13px; font-weight: 600; margin-top: 4px;">
                    ${d.epss ? (d.epss.epss_score * 100).toFixed(2) + '%' : 'N/A'}
                </div>
            </div>
            <div style="background-color: var(--bg-elevated); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: 10px;">
                <div class="input-label">KEV Catalog</div>
                <div style="margin-top: 4px;">
                    ${d.is_kev ? '<span class="badge badge-kev">Active Exploit</span>' : '<span class="badge badge-neutral">Not Listed</span>'}
                </div>
            </div>
        </div>

        ${kevHtml}

        <!-- Description Group -->
        <div class="drawer-section">
            <div class="drawer-section-title">Description</div>
            <div style="font-size: 13px; color: var(--text-primary); line-height: 1.55;">
                ${escapeHtml(d.description_en || 'No description recorded in NVD.')}
            </div>
        </div>

        <!-- Technical Score Details -->
        <div class="drawer-section">
            <div class="drawer-section-title">Authoritative Scoring Details</div>
            <div style="display: flex; flex-direction: column; gap: 6px; font-size: 12px;">
                ${d.cvss_v31_vector ? `
                    <div style="display: flex; gap: 8px; align-items: baseline;">
                        <span style="color: var(--text-secondary); width: 80px; flex-shrink: 0;">Vector String:</span>
                        <code style="background: var(--bg-muted); padding: 2px 6px; border-radius: var(--radius-xs); border: 1px solid var(--border-subtle);">${escapeHtml(d.cvss_v31_vector)}</code>
                    </div>
                ` : ''}
                ${d.epss ? `
                    <div style="display: flex; gap: 8px; align-items: baseline;">
                        <span style="color: var(--text-secondary); width: 80px; flex-shrink: 0;">EPSS Model:</span>
                        <span style="font-family: var(--font-mono); font-size: 11px;">${d.epss.model_version} (Snapshot: ${d.epss.snapshot_date.substring(0, 10)})</span>
                    </div>
                ` : ''}
            </div>
            ${d.epss ? `
                <div style="font-size: 11px; color: var(--text-muted); margin-top: 8px; font-style: italic;">
                    Temporal Note: Static EPSS snapshot was not available at historical publication time.
                </div>
            ` : ''}
        </div>

        <!-- Weaknesses (CWE) -->
        <div class="drawer-section">
            <div class="drawer-section-title">Weakness Taxonomy (CWE)</div>
            <div style="display: flex; flex-wrap: wrap; gap: 6px;">
                ${cweBadges}
            </div>
        </div>

        <!-- Affected Software Configurations (CPE) Disclosure -->
        <details class="disclosure">
            <summary>
                <span>Affected Software Configurations (${d.cpes ? d.cpes.length : 0} nodes)</span>
            </summary>
            <div class="disclosure-content" style="padding: 0;">
                <div class="table-container" style="border: none; border-radius: 0;">
                    <table class="data-table" style="font-size: 11px;">
                        <thead>
                            <tr>
                                <th>Part</th>
                                <th>Vendor</th>
                                <th>Product</th>
                                <th>Version</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${cpeListHtml}
                        </tbody>
                    </table>
                </div>
            </div>
        </details>
    `;
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function saveRecentCveToLocalStorage(d) {
    try {
        const recentStr = localStorage.getItem('wdl_recent_cves');
        let list = recentStr ? JSON.parse(recentStr) : [];
        list = list.filter(item => item.cve_id !== d.cve_id);
        list.unshift({
            cve_id: d.cve_id,
            cvss: d.authoritative_cvss_v31_base_score,
            is_kev: d.is_kev,
            timestamp: new Date().toISOString()
        });
        localStorage.setItem('wdl_recent_cves', JSON.stringify(list.slice(0, 10)));
    } catch (e) {
        // Ignore local storage quota errors
    }
}

function printVulnerabilityReport(d) {
    const printWin = window.open('', '_blank', 'width=850,height=900');
    if (!printWin) {
        alert('Please allow popup windows to generate the printable triage report.');
        return;
    }

    const cvssDisplay = d.authoritative_cvss_v31_base_score !== null
        ? `${d.authoritative_cvss_v31_base_score.toFixed(1)} (${d.cvss_v31_base_severity || 'Unspecified'})`
        : 'None / Unscored';

    const epssDisplay = d.epss
        ? `${(d.epss.epss_score * 100).toFixed(2)}% (Percentile: ${(d.epss.epss_percentile * 100).toFixed(0)}th, Model: ${d.epss.model_version})`
        : 'N/A';

    const cweDisplay = d.cwes && d.cwes.length > 0
        ? d.cwes.map(c => c.cwe_id).join(', ')
        : 'None classified';

    const reportHtml = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Vulnerability Triage Report — ${d.cve_id}</title>
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.5; color: #292723; padding: 32px; background: #fff; font-size: 13px; }
                .report-header { border-bottom: 2px solid #45403A; padding-bottom: 14px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: flex-start; }
                .title { font-size: 22px; font-weight: 700; color: #292723; margin: 0; font-family: monospace; }
                .sub { font-size: 12px; color: #625E56; margin-top: 3px; }
                .badge { display: inline-block; padding: 2px 8px; font-size: 11px; font-weight: 600; border-radius: 3px; background: #EAE7E0; color: #292723; border: 1px solid #DED9CF; font-family: monospace; }
                .badge-critical { background: #F5E5E2; color: #A83B3B; border-color: #E8B4B4; }
                .badge-kev { background: #F5E5E2; color: #A83B3B; border-color: #E8B4B4; font-weight: 700; }
                .section { margin-bottom: 18px; border: 1px solid #DED9CF; border-radius: 4px; padding: 14px; background: #FCFBF8; }
                .sec-title { font-size: 11px; font-weight: 700; color: #625E56; margin-top: 0; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.04em; font-family: monospace; }
                .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; font-size: 12px; }
                .disclaimer-box { font-size: 11px; color: #625E56; background: #F5F3EE; border: 1px solid #DED9CF; border-radius: 4px; padding: 10px; margin-top: 24px; line-height: 1.5; }
                @media print { body { padding: 0; } }
            </style>
        </head>
        <body>
            <div class="report-header">
                <div>
                    <h1 class="title">${d.cve_id}</h1>
                    <div class="sub">Vulnerability Prioritization & Triage System • Operational Report</div>
                </div>
                <div style="text-align: right;">
                    <span class="badge ${d.is_kev ? 'badge-kev' : 'badge-critical'}">${cvssDisplay}</span>
                    <div style="font-size: 11px; color: #625E56; margin-top: 4px;">Published: ${d.published ? d.published.substring(0, 10) : 'N/A'}</div>
                </div>
            </div>

            <div class="section">
                <div class="sec-title">Description</div>
                <div>${escapeHtml(d.description_en || 'No description recorded.')}</div>
            </div>

            <div class="section">
                <div class="sec-title">Threat Signals & Exploitation Status</div>
                <div class="grid">
                    <div><strong>CISA KEV Status:</strong> ${d.is_kev ? 'Confirmed In-The-Wild Exploitation' : 'Not listed in KEV catalog'}</div>
                    <div><strong>EPSS Probability:</strong> ${epssDisplay}</div>
                    <div><strong>CVSS v3.1 Vector:</strong> <code>${d.cvss_v31_vector || 'N/A'}</code></div>
                    <div><strong>Weaknesses:</strong> ${cweDisplay}</div>
                </div>
            </div>

            ${d.is_kev ? `
                <div class="section" style="border-left: 3px solid #A83B3B;">
                    <div class="sec-title" style="color: #A83B3B;">CISA KEV Catalog Remediation Directives</div>
                    <div><strong>Vulnerability Name:</strong> ${escapeHtml(d.kev_vulnerability_name || d.cve_id)}</div>
                    <div><strong>Required Action:</strong> ${escapeHtml(d.kev_required_action || 'Remediate per CISA directive.')}</div>
                    <div><strong>Action Due Date:</strong> ${d.kev_due_date || 'N/A'}</div>
                </div>
            ` : ''}

            <div class="disclaimer-box">
                <strong>Academic Research Disclaimer:</strong>
                This report was generated by the Vulnerability Prioritization & Triage System research prototype (Repository: seucra/vulnarability-prioritization-triage-system).
                Prioritization metrics are decision-support outputs based on frozen snapshot data (Freeze Date: 2026-07-26; EPSS: 2026-07-16) and must not replace organizational security policy.
            </div>
        </body>
        </html>
    `;

    printWin.document.write(reportHtml);
    printWin.document.close();
    printWin.focus();
}
