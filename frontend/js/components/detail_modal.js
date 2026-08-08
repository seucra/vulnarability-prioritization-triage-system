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
                    <button class="btn btn-outline btn-sm" id="btn-close-drawer">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                        Close
                    </button>
                </div>
                <div class="drawer-body" id="drawer-body-content">
                    <!-- Dynamic content -->
                </div>
            </div>
        </div>
    `;

    const backdrop = containerEl.querySelector('#detail-backdrop');
    const closeBtn = containerEl.querySelector('#btn-close-drawer');

    const closeDrawer = () => {
        state.setState({ selectedCveId: null, cveDetail: null });
    };

    closeBtn.addEventListener('click', closeDrawer);
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
