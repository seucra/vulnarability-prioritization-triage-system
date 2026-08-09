/**
 * Vulnerability Detail Slide-Over Drawer Component
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { state } from '../state.js';

export function renderDetailModal(containerEl) {
    containerEl.innerHTML = `
        <div class="drawer-backdrop" id="detail-backdrop">
            <div class="drawer-panel">
                <div class="drawer-header">
                    <div>
                        <div class="drawer-title" id="drawer-cve-id">CVE Detail</div>
                        <div style="font-size: 12px; color: var(--text-sub);" id="drawer-pub-date">Published Date</div>
                    </div>
                    <div style="display: flex; gap: 8px;">
                        <button class="btn btn-outline btn-sm" id="btn-print-report" title="Generate printable vulnerability triage report">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>
                            Print Report
                        </button>
                        <button class="btn btn-outline btn-sm" id="btn-close-drawer">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                            Close
                        </button>
                    </div>
                </div>
                <div class="drawer-body" id="drawer-body-content">
                    <!-- Dynamic content -->
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
                <p style="margin-top: 12px; color: var(--text-sub);">Retrieving canonical record for ${s.selectedCveId}...</p>
            </div>
        `;
        return;
    }

    if (s.detailError) {
        body.innerHTML = `
            <div class="error-banner">
                <strong>Error fetching details:</strong> ${s.detailError}
            </div>
        `;
        return;
    }

    const d = s.cveDetail;
    if (!d) return;

    // Save inspected CVE to local triage history
    saveRecentCveToLocalStorage(d);

    cveTitle.textContent = d.cve_id;
    pubDate.textContent = `Published: ${new Date(d.published).toLocaleString()}`;

    // EPSS Snapshot Callout (Non-historical warning)
    let epssHtml = '';
    if (d.epss) {
        epssHtml = `
            <div class="epss-snapshot-callout">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 4px;">
                    <strong>Current EPSS Snapshot (${d.epss.snapshot_date.substring(0, 10)})</strong>
                    <span class="badge badge-epss">Score: ${(d.epss.epss_score * 100).toFixed(2)}% | ${(d.epss.epss_percentile * 100).toFixed(0)}th %tile</span>
                </div>
                <div>Model Version: ${d.epss.model_version}</div>
                <div style="margin-top: 4px; color: var(--text-muted); font-style: italic;">
                    Warning: EPSS score is a present-day static snapshot (2026-07-16) and was NOT available at historical publication triage time.
                </div>
            </div>
        `;
    }

    // KEV Callout
    let kevHtml = '';
    if (d.is_kev) {
        kevHtml = `
            <div style="background-color: #fef2f2; border: 1px solid #fca5a5; border-radius: var(--radius-md); padding: 14px; margin-bottom: 20px;">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
                    <span class="badge badge-kev">CISA Known Exploited Vulnerabilities Catalog</span>
                    <span style="font-size: 11px; color: var(--error); font-family: var(--font-mono);">Date Added: ${d.kev_date_added || 'N/A'}</span>
                </div>
                <div style="font-weight: 600; color: #991b1b; margin-bottom: 4px;">${escapeHtml(d.kev_vulnerability_name || d.cve_id)}</div>
                <div style="font-size: 12px; color: var(--text-main); margin-bottom: 6px;">${escapeHtml(d.kev_short_description || '')}</div>
                <div style="font-size: 12px; color: #991b1b; font-weight: 600;">Required Action: ${escapeHtml(d.kev_required_action || 'Remediate per CISA directive.')}</div>
                ${d.kev_ransomware_campaign_use === 'Known' ? '<div style="margin-top:4px; font-weight:700; color:var(--error); font-size:11px;">WARNING: KNOWN RANSOMWARE CAMPAIGN USE</div>' : ''}
            </div>
        `;
    }

    // Authoritative CVSS
    const cvssVal = d.authoritative_cvss_v31_base_score;
    let cvssDisplay = 'None / Unscored';
    if (cvssVal !== null) {
        cvssDisplay = `${cvssVal.toFixed(1)} (${d.cvss_v31_base_severity || 'Unspecified'})`;
    }

    // CWE list
    const cweBadges = d.cwes.length > 0
        ? d.cwes.map(c => `<span class="badge ${c.is_semantic_cwe ? 'badge-high' : 'badge-secondary'}">${c.cwe_id}</span>`).join(' ')
        : '<span style="color:var(--text-muted);">No CWE classification</span>';

    // CPE List
    const cpeListHtml = d.cpes.length > 0
        ? d.cpes.map(c => `
            <tr style="font-family: var(--font-mono); font-size: 11px;">
                <td>${c.part || '-'}</td>
                <td>${escapeHtml(c.vendor || '-')}</td>
                <td>${escapeHtml(c.product || '-')}</td>
                <td>${escapeHtml(c.version || '*')}</td>
            </tr>
        `).join('')
        : '<tr><td colspan="4" style="color:var(--text-muted);">No structured CPE applicability nodes</td></tr>';

    body.innerHTML = `
        ${epssHtml}
        ${kevHtml}

        <div class="card" style="padding: 16px; margin-bottom: 16px;">
            <div class="input-label" style="margin-bottom: 6px;">Description</div>
            <div style="font-size: 13px; color: var(--text-main); leading: 1.6;">${escapeHtml(d.description_en)}</div>
        </div>

        <div class="card" style="padding: 16px; margin-bottom: 16px;">
            <div class="input-label" style="margin-bottom: 8px;">Authoritative NVD CVSS v3.1 Score</div>
            <div style="font-family: var(--font-mono); font-size: 24px; font-weight: 700; color: var(--primary); margin-bottom: 6px;">
                ${cvssDisplay}
            </div>
            ${d.cvss_v31_vector ? `<div style="font-family: var(--font-mono); font-size: 11px; color: var(--text-sub); background: var(--bg-surface-low); padding: 6px; border-radius: var(--radius-sm); border: 1px solid var(--border-color);">${d.cvss_v31_vector}</div>` : ''}
        </div>

        <div class="card" style="padding: 16px; margin-bottom: 16px;">
            <div class="input-label" style="margin-bottom: 8px;">Associated CWE Weaknesses</div>
            <div>${cweBadges}</div>
        </div>

        <div class="card" style="padding: 16px;">
            <div class="input-label" style="margin-bottom: 8px;">CPE Applicability (Top 20 Nodes)</div>
            <table class="data-table" style="font-size: 11px;">
                <thead>
                    <tr><th>Part</th><th>Vendor</th><th>Product</th><th>Version</th></tr>
                </thead>
                <tbody>${cpeListHtml}</tbody>
            </table>
        </div>
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
        // Ignore quota/storage errors
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
        ? `${(d.epss.epss_score * 100).toFixed(2)}% (Percentile: ${(d.epss.epss_percentile * 100).toFixed(0)}th %tile, Model: ${d.epss.model_version})`
        : 'N/A';

    const cweDisplay = d.cwes && d.cwes.length > 0
        ? d.cwes.map(c => c.cwe_id).join(', ')
        : 'None listed';

    const reportHtml = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Vulnerability Triage Report — ${d.cve_id}</title>
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.5; color: #1e293b; padding: 32px; background: #fff; }
                .report-header { border-bottom: 2px solid #0f172a; padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: flex-start; }
                .title { font-size: 24px; font-weight: 700; color: #0f172a; margin: 0; }
                .sub { font-size: 13px; color: #64748b; margin-top: 4px; }
                .badge { display: inline-block; padding: 4px 10px; font-size: 12px; font-weight: 600; border-radius: 4px; background: #e2e8f0; color: #0f172a; }
                .badge-high { background: #fee2e2; color: #991b1b; }
                .badge-kev { background: #fef2f2; border: 1px solid #fca5a5; color: #991b1b; }
                .section { margin-bottom: 24px; border: 1px solid #e2e8f0; border-radius: 6px; padding: 16px; background: #f8fafc; }
                .sec-title { font-size: 14px; font-weight: 700; color: #0f172a; margin-top: 0; margin-bottom: 10px; border-bottom: 1px solid #cbd5e1; padding-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; }
                .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; font-size: 13px; }
                .disclaimer-box { font-size: 11px; color: #475569; background: #f1f5f9; border: 1px solid #cbd5e1; border-radius: 6px; padding: 12px; margin-top: 32px; line-height: 1.6; }
                @media print { body { padding: 0; } }
            </style>
        </head>
        <body>
            <div class="report-header">
                <div>
                    <h1 class="title">Vulnerability Triage Report</h1>
                    <div class="sub">Generated on ${new Date().toLocaleString()} • Web Design Lab Research Prototype</div>
                </div>
                <div style="text-align: right;">
                    <div style="font-family: monospace; font-size: 18px; font-weight: 700; color: #2563eb;">${d.cve_id}</div>
                    <div class="sub">Published: ${new Date(d.published).toLocaleDateString()}</div>
                </div>
            </div>

            <!-- Authoritative NVD CVSS Section -->
            <div class="section">
                <h2 class="sec-title">1. Authoritative Vulnerability Metadata (NVD)</h2>
                <div class="grid">
                    <div><strong>CVSS v3.1 Score:</strong> ${cvssDisplay}</div>
                    <div><strong>Associated CWEs:</strong> ${cweDisplay}</div>
                    <div style="grid-column: 1 / -1; margin-top: 6px;">
                        <strong>Description:</strong><br>
                        <span style="font-size: 12px; color: #334155;">${d.description_en || 'No text description available.'}</span>
                    </div>
                    ${d.cvss_v31_vector ? `<div style="grid-column: 1 / -1; font-family: monospace; font-size: 11px; color: #475569; background: #e2e8f0; padding: 6px; border-radius: 4px;">Vector: ${d.cvss_v31_vector}</div>` : ''}
                </div>
            </div>

            <!-- Threat Intelligence & Retrospective EPSS Section -->
            <div class="section">
                <h2 class="sec-title">2. Threat Intelligence Context</h2>
                <div class="grid">
                    <div><strong>CISA KEV Listing Status:</strong> ${d.is_kev ? '<span class="badge badge-kev">CISA KEV Listed</span>' : 'Not listed in CISA KEV'}</div>
                    <div><strong>Current EPSS Snapshot Score:</strong> ${epssDisplay}</div>
                    ${d.is_kev ? `<div style="grid-column: 1 / -1; color: #991b1b; font-weight: 600;">KEV Required Action: ${d.kev_required_action || 'Remediate per CISA directive.'}</div>` : ''}
                </div>
                <div style="font-size: 11px; color: #64748b; margin-top: 8px; font-style: italic;">
                    Notice: The EPSS score above reflects a present-day static snapshot dated 2026-07-16T12:03:48Z and was NOT available at historical publication triage time.
                </div>
            </div>

            <!-- Academic Disclaimer Footer -->
            <div class="disclaimer-box">
                <strong>Academic Prototype Disclaimer:</strong><br>
                This report clearly distinguishes Authoritative NVD/CISA Data from Predictive Model Inference and Decision-Support Prioritization. This document was generated by the Vulnerability Prioritization & Triage System (seucra/vulnarability-prioritization-triage-system) for research demonstration purposes.
            </div>

            <script>
                window.onload = function() {
                    window.print();
                };
            </script>
        </body>
        </html>
    `;

    printWin.document.write(reportHtml);
    printWin.document.close();
}
