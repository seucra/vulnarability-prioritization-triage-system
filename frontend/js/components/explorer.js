/**
 * Vulnerability Explorer & Triage Component Controller
 * Visual Direction: Restrained, high-density, academic research table
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { api } from '../api.js';
import { state } from '../state.js';

export function renderExplorer(containerEl) {
    containerEl.innerHTML = `
        <div class="section-header">
            <div class="section-header-content">
                <div class="section-eyebrow">Canonical Dataset Query Engine</div>
                <h1 class="section-title">Vulnerability Triage Explorer</h1>
                <p class="section-desc">
                    Query 366,547 canonical NVD CVE records across official CVSS base scores, static EPSS exploitation likelihood, and CISA Known Exploited Vulnerabilities (KEV) listings.
                </p>
            </div>
            <div class="section-actions">
                <button class="btn btn-outline btn-sm" id="btn-export-csv" title="Export current page items to CSV">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                    CSV
                </button>
                <button class="btn btn-outline btn-sm" id="btn-export-json" title="Export current page items to JSON">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                    JSON
                </button>
            </div>
        </div>

        <!-- Search & Filter Console -->
        <div class="card" style="padding: 14px 16px; margin-bottom: 16px;">
            <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
                <div style="flex: 2; min-width: 240px;">
                    <input type="text" id="input-search-q" class="input-control" style="width: 100%;" placeholder="Search vulnerability descriptions (e.g. 'remote code execution')...">
                </div>
                <div style="width: 160px; min-width: 140px;">
                    <input type="text" id="input-search-cve" class="input-control" style="width: 100%;" placeholder="CVE-YYYY-NNNN">
                </div>
                <div style="width: 150px;">
                    <select id="filter-is-kev" class="input-control" style="width: 100%;">
                        <option value="">All Vulnerabilities</option>
                        <option value="true">KEV Catalog Only</option>
                        <option value="false">Non-KEV Only</option>
                    </select>
                </div>
                <button class="btn btn-primary" id="btn-search">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                    Search
                </button>
                <button class="btn btn-outline" id="btn-toggle-filters">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>
                    Filters
                </button>
            </div>

            <!-- Secondary Advanced Filters (Collapsible) -->
            <div id="filter-grid" style="display: none; grid-template-columns: repeat(auto-fill, minmax(170px, 1fr)); gap: 10px; margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--border-subtle);">
                <div class="input-group">
                    <label class="input-label">CWE Weakness</label>
                    <input type="text" id="filter-cwe" class="input-control" placeholder="e.g. CWE-79">
                </div>
                <div class="input-group">
                    <label class="input-label">CPE Vendor</label>
                    <input type="text" id="filter-vendor" class="input-control" placeholder="e.g. apache">
                </div>
                <div class="input-group">
                    <label class="input-label">CPE Product</label>
                    <input type="text" id="filter-product" class="input-control" placeholder="e.g. log4j">
                </div>
                <div class="input-group">
                    <label class="input-label">Min CVSS</label>
                    <input type="number" id="filter-min-cvss" class="input-control" min="0" max="10" step="0.5" placeholder="0.0">
                </div>
                <div class="input-group">
                    <label class="input-label">Max CVSS</label>
                    <input type="number" id="filter-max-cvss" class="input-control" min="0" max="10" step="0.5" placeholder="10.0">
                </div>
                <div class="input-group">
                    <label class="input-label">Min EPSS</label>
                    <input type="number" id="filter-min-epss" class="input-control" min="0" max="1" step="0.05" placeholder="0.00">
                </div>
                <div class="input-group">
                    <label class="input-label">Pub Year</label>
                    <input type="number" id="filter-pub-year" class="input-control" min="2002" max="2026" placeholder="2021">
                </div>
                <div class="input-group" style="justify-content: flex-end;">
                    <button class="btn btn-secondary btn-sm" id="btn-reset-filters" style="margin-top: 18px;">
                        Reset Filters
                    </button>
                </div>
            </div>
        </div>

        <!-- Explorer Status Container (Loading / Error) -->
        <div id="explorer-status-container"></div>

        <!-- High-Density Analytical Table -->
        <div class="table-container">
            <table class="data-table">
                <thead>
                    <tr>
                        <th style="width: 140px;">CVE ID</th>
                        <th style="width: 100px;">Published</th>
                        <th>Description Summary</th>
                        <th style="width: 130px;">CVSS v3.1</th>
                        <th style="width: 140px;">EPSS Snapshot</th>
                        <th style="width: 110px;">KEV Status</th>
                        <th style="width: 80px; text-align: right;">Action</th>
                    </tr>
                </thead>
                <tbody id="triage-table-body">
                    <!-- Dynamic Rows -->
                </tbody>
            </table>
        </div>

        <!-- Pagination Bar -->
        <div class="pagination-row">
            <div id="pagination-summary" style="font-family: var(--font-mono); font-size: 11px; color: var(--text-secondary);">
                Showing 0 results
            </div>
            <div class="pagination-controls">
                <button class="btn btn-secondary btn-sm" id="btn-prev-page" disabled>Previous</button>
                <span id="page-num-display" style="font-family: var(--font-mono); font-size: 11px; padding: 0 4px;">Page 1 of 1</span>
                <button class="btn btn-secondary btn-sm" id="btn-next-page" disabled>Next</button>
            </div>
        </div>
    `;

    // Filter toggle
    const btnToggle = containerEl.querySelector('#btn-toggle-filters');
    const filterGrid = containerEl.querySelector('#filter-grid');
    btnToggle.addEventListener('click', () => {
        const isHidden = filterGrid.style.display === 'none';
        filterGrid.style.display = isHidden ? 'grid' : 'none';
        btnToggle.classList.toggle('btn-secondary', isHidden);
    });

    // Reset filters
    const btnReset = containerEl.querySelector('#btn-reset-filters');
    if (btnReset) {
        btnReset.addEventListener('click', () => {
            containerEl.querySelector('#input-search-q').value = '';
            containerEl.querySelector('#input-search-cve').value = '';
            containerEl.querySelector('#filter-is-kev').value = '';
            containerEl.querySelector('#filter-cwe').value = '';
            containerEl.querySelector('#filter-vendor').value = '';
            containerEl.querySelector('#filter-product').value = '';
            containerEl.querySelector('#filter-min-cvss').value = '';
            containerEl.querySelector('#filter-max-cvss').value = '';
            containerEl.querySelector('#filter-min-epss').value = '';
            containerEl.querySelector('#filter-pub-year').value = '';
            triggerSearch();
        });
    }

    // Export Listeners
    containerEl.querySelector('#btn-export-csv').addEventListener('click', () => exportCurrentPageCsv());
    containerEl.querySelector('#btn-export-json').addEventListener('click', () => exportCurrentPageJson());

    // Search Trigger
    const triggerSearch = () => {
        const currentParams = state.getState().searchParams;
        const newParams = {
            ...currentParams,
            q: containerEl.querySelector('#input-search-q').value.trim(),
            cve_id: containerEl.querySelector('#input-search-cve').value.trim(),
            cwe_id: containerEl.querySelector('#filter-cwe').value.trim(),
            vendor: containerEl.querySelector('#filter-vendor').value.trim(),
            product: containerEl.querySelector('#filter-product').value.trim(),
            min_cvss: containerEl.querySelector('#filter-min-cvss').value,
            max_cvss: containerEl.querySelector('#filter-max-cvss').value,
            is_kev: containerEl.querySelector('#filter-is-kev').value,
            min_epss: containerEl.querySelector('#filter-min-epss').value,
            publication_year: containerEl.querySelector('#filter-pub-year').value,
            page: 1,
        };
        fetchSearchResults(newParams);
    };

    containerEl.querySelector('#btn-search').addEventListener('click', triggerSearch);
    containerEl.querySelector('#input-search-q').addEventListener('keyup', (e) => {
        if (e.key === 'Enter') triggerSearch();
    });
    containerEl.querySelector('#input-search-cve').addEventListener('keyup', (e) => {
        if (e.key === 'Enter') triggerSearch();
    });
    containerEl.querySelector('#filter-is-kev').addEventListener('change', triggerSearch);

    // Pagination
    containerEl.querySelector('#btn-prev-page').addEventListener('click', () => {
        const p = state.getState().searchParams;
        if (p.page > 1) {
            fetchSearchResults({ ...p, page: p.page - 1 });
        }
    });

    containerEl.querySelector('#btn-next-page').addEventListener('click', () => {
        const p = state.getState().searchParams;
        const totalPages = state.getState().vulnerabilityResults?.total_pages || 1;
        if (p.page < totalPages) {
            fetchSearchResults({ ...p, page: p.page + 1 });
        }
    });

    // Reactive table rendering
    state.subscribe(s => {
        renderTableBody(containerEl, s);
    });

    // Initial search query
    fetchSearchResults(state.getState().searchParams);
}

async function fetchSearchResults(params) {
    state.setState({ isExplorerLoading: true, explorerError: null, searchParams: params });
    try {
        const results = await api.searchVulnerabilities(params);
        state.setState({ vulnerabilityResults: results, isExplorerLoading: false });
    } catch (err) {
        state.setState({ explorerError: err.message, isExplorerLoading: false });
    }
}

function renderTableBody(containerEl, s) {
    const tbody = containerEl.querySelector('#triage-table-body');
    const statusContainer = containerEl.querySelector('#explorer-status-container');
    const prevBtn = containerEl.querySelector('#btn-prev-page');
    const nextBtn = containerEl.querySelector('#btn-next-page');
    const summaryEl = containerEl.querySelector('#pagination-summary');
    const pageNumEl = containerEl.querySelector('#page-num-display');

    if (!tbody) return;

    if (s.isExplorerLoading) {
        statusContainer.innerHTML = `
            <div style="padding: 24px; text-align: center;">
                <span class="loading-spinner"></span>
                <span style="margin-left: 8px; font-size: 13px; color: var(--text-secondary);">Querying canonical vulnerability index...</span>
            </div>
        `;
        return;
    }

    if (s.explorerError) {
        statusContainer.innerHTML = `
            <div class="error-banner">
                <strong>Query Error:</strong> ${escapeHtml(s.explorerError)}
            </div>
        `;
        tbody.innerHTML = '';
        return;
    }

    statusContainer.innerHTML = '';
    const res = s.vulnerabilityResults;
    if (!res || !res.items || res.items.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7">
                    <div class="empty-state">
                        <p>No vulnerabilities match your search query or filter parameters.</p>
                    </div>
                </td>
            </tr>
        `;
        summaryEl.textContent = 'Showing 0 results';
        pageNumEl.textContent = 'Page 1 of 1';
        prevBtn.disabled = true;
        nextBtn.disabled = true;
        return;
    }

    // Render table rows
    tbody.innerHTML = res.items.map(item => {
        const cvssVal = item.cvss_v31_base_score;
        let cvssBadgeClass = 'badge-low';
        if (cvssVal >= 9.0) cvssBadgeClass = 'badge-critical';
        else if (cvssVal >= 7.0) cvssBadgeClass = 'badge-high';
        else if (cvssVal >= 4.0) cvssBadgeClass = 'badge-medium';
        else if (cvssVal === null) cvssBadgeClass = 'badge-neutral';

        const cvssDisplay = cvssVal !== null ? `${cvssVal.toFixed(1)} ${item.cvss_v31_base_severity || ''}` : 'Unscored';
        const epssDisplay = item.epss ? `${(item.epss.epss_score * 100).toFixed(2)}% <span style="color:var(--text-muted); font-size:10px;">(${(item.epss.epss_percentile * 100).toFixed(0)}%)</span>` : '<span style="color:var(--text-muted);">N/A</span>';
        const pubDate = item.published ? item.published.substring(0, 10) : '—';

        return `
            <tr data-cve="${item.cve_id}">
                <td class="cve-id-cell">${item.cve_id}</td>
                <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-secondary);">${pubDate}</td>
                <td class="description-snippet" title="${escapeHtml(item.description_en || '')}">${escapeHtml(item.description_en || 'No description available')}</td>
                <td><span class="badge ${cvssBadgeClass}">${cvssDisplay}</span></td>
                <td style="font-family: var(--font-mono); font-size: 11px;">${epssDisplay}</td>
                <td>
                    ${item.is_kev 
                        ? '<span class="badge badge-kev">KEV Active</span>' 
                        : '<span style="color:var(--text-muted); font-family:var(--font-mono); font-size:11px;">—</span>'}
                </td>
                <td style="text-align: right;">
                    <button class="btn btn-outline btn-sm btn-inspect-cve" data-cve="${item.cve_id}">
                        Inspect
                    </button>
                </td>
            </tr>
        `;
    }).join('');

    // Attach click listeners to rows and buttons
    tbody.querySelectorAll('.btn-inspect-cve').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const cveId = btn.getAttribute('data-cve');
            openCveDetail(cveId);
        });
    });

    tbody.querySelectorAll('tr[data-cve]').forEach(tr => {
        tr.addEventListener('click', () => {
            const cveId = tr.getAttribute('data-cve');
            openCveDetail(cveId);
        });
    });

    // Pagination update
    const page = res.page;
    const totalPages = res.total_pages;
    const startIdx = (page - 1) * res.page_size + 1;
    const endIdx = Math.min(page * res.page_size, res.total);

    summaryEl.textContent = `Showing ${startIdx.toLocaleString()}–${endIdx.toLocaleString()} of ${res.total.toLocaleString()} records`;
    pageNumEl.textContent = `Page ${page} of ${totalPages.toLocaleString()}`;

    prevBtn.disabled = page <= 1;
    nextBtn.disabled = page >= totalPages;
}

function openCveDetail(cveId) {
    state.setState({ selectedCveId: cveId, isDetailLoading: true, detailError: null });
    api.getVulnerabilityDetail(cveId)
        .then(detail => {
            state.setState({ cveDetail: detail, isDetailLoading: false });
        })
        .catch(err => {
            state.setState({ detailError: err.message, isDetailLoading: false });
        });
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function exportCurrentPageCsv() {
    const res = state.getState().vulnerabilityResults;
    if (!res || !res.items || res.items.length === 0) {
        alert('No vulnerability items available on current page to export.');
        return;
    }

    const headers = ['CVE ID', 'Published Date', 'Authoritative CVSS v3.1 Score', 'Severity', 'CISA KEV Listed', 'EPSS Score (%)', 'Description'];
    const rows = res.items.map(item => [
        `"${item.cve_id}"`,
        `"${item.published ? item.published.split('T')[0] : ''}"`,
        `"${item.cvss_v31_base_score !== null ? item.cvss_v31_base_score : ''}"`,
        `"${item.cvss_v31_base_severity || ''}"`,
        `"${item.is_kev ? 'TRUE' : 'FALSE'}"`,
        `"${item.epss ? (item.epss.epss_score * 100).toFixed(2) : ''}"`,
        `"${(item.description_en || '').replace(/"/g, '""')}"`
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `vuln_triage_export_page_${res.page || 1}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

function exportCurrentPageJson() {
    const res = state.getState().vulnerabilityResults;
    if (!res || !res.items || res.items.length === 0) {
        alert('No vulnerability items available on current page to export.');
        return;
    }

    const jsonString = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(res.items, null, 2));
    const link = document.createElement('a');
    link.setAttribute("href", jsonString);
    link.setAttribute("download", `vuln_triage_export_page_${res.page || 1}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}
