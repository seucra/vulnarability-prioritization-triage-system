/**
 * Vulnerability Explorer & Triage Component Controller
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { api } from '../api.js';
import { state } from '../state.js';

export function renderExplorer(containerEl) {
    containerEl.innerHTML = `
        <div class="section-header">
            <div>
                <h2 class="section-title">Vulnerability Triage Explorer</h2>
                <p class="section-desc">Search, filter, and triage 366,547 canonical CVE records across official NVD CVSS scores, CISA KEV listing status, and static EPSS snapshots.</p>
            </div>
            <button class="btn btn-outline btn-sm" id="btn-toggle-filters">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>
                Advanced Filters
            </button>
        </div>

        <!-- Search Controls Card -->
        <div class="card">
            <div class="search-bar-row">
                <div class="input-group">
                    <input type="text" id="input-search-q" class="input-control" placeholder="Search vulnerability description keywords (e.g. 'remote code execution')...">
                </div>
                <div class="input-group" style="width: 180px;">
                    <input type="text" id="input-search-cve" class="input-control" placeholder="CVE ID (e.g. 2021-44228)...">
                </div>
                <button class="btn btn-primary" id="btn-search">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                    Search
                </button>
            </div>

            <!-- Advanced Filter Accordion -->
            <div class="filter-grid" id="filter-grid" style="display: none;">
                <div class="input-group">
                    <label class="input-label">CWE Weakness ID</label>
                    <input type="text" id="filter-cwe" class="input-control" placeholder="CWE-79">
                </div>
                <div class="input-group">
                    <label class="input-label">CPE Vendor</label>
                    <input type="text" id="filter-vendor" class="input-control" placeholder="apache">
                </div>
                <div class="input-group">
                    <label class="input-label">CPE Product</label>
                    <input type="text" id="filter-product" class="input-control" placeholder="log4j">
                </div>
                <div class="input-group">
                    <label class="input-label">Min CVSS v3.1 Score</label>
                    <input type="number" id="filter-min-cvss" class="input-control" min="0" max="10" step="0.5" placeholder="0.0">
                </div>
                <div class="input-group">
                    <label class="input-label">Max CVSS v3.1 Score</label>
                    <input type="number" id="filter-max-cvss" class="input-control" min="0" max="10" step="0.5" placeholder="10.0">
                </div>
                <div class="input-group">
                    <label class="input-label">CISA KEV Status</label>
                    <select id="filter-is-kev" class="input-control">
                        <option value="">All Vulnerabilities</option>
                        <option value="true">KEV Listed Only</option>
                        <option value="false">Non-KEV Only</option>
                    </select>
                </div>
                <div class="input-group">
                    <label class="input-label">Min EPSS Score</label>
                    <input type="number" id="filter-min-epss" class="input-control" min="0" max="1" step="0.05" placeholder="0.0">
                </div>
                <div class="input-group">
                    <label class="input-label">Publication Year</label>
                    <input type="number" id="filter-pub-year" class="input-control" min="2002" max="2026" placeholder="2021">
                </div>
            </div>
        </div>

        <!-- Error & Loading Container -->
        <div id="explorer-status-container"></div>

        <!-- Table Container -->
        <div class="table-container">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>CVE Identifier</th>
                        <th>Published Date</th>
                        <th>Description Summary</th>
                        <th>Authoritative CVSS v3.1</th>
                        <th>EPSS Snapshot</th>
                        <th>KEV Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="triage-table-body">
                    <!-- Dynamic rows inserted here -->
                </tbody>
            </table>
        </div>

        <!-- Pagination Controls -->
        <div class="pagination-row">
            <div id="pagination-summary">Showing 0 results</div>
            <div class="pagination-controls">
                <button class="btn btn-secondary btn-sm" id="btn-prev-page" disabled>Previous</button>
                <span id="page-num-display" style="font-weight: 600; font-family: var(--font-mono);">Page 1 of 1</span>
                <button class="btn btn-secondary btn-sm" id="btn-next-page" disabled>Next</button>
            </div>
        </div>
    `;

    // Filter toggle listener
    const btnToggle = containerEl.querySelector('#btn-toggle-filters');
    const filterGrid = containerEl.querySelector('#filter-grid');
    btnToggle.addEventListener('click', () => {
        const isHidden = filterGrid.style.display === 'none';
        filterGrid.style.display = isHidden ? 'grid' : 'none';
        btnToggle.classList.toggle('btn-secondary', isHidden);
    });

    // Execute Search Listener
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
            page: 1, // Reset to page 1 on new search
        };
        fetchSearchResults(newParams);
    };

    containerEl.querySelector('#btn-search').addEventListener('click', triggerSearch);
    containerEl.querySelector('#input-search-q').addEventListener('keyup', (e) => {
        if (e.key === 'Enter') triggerSearch();
    });

    // Pagination Listeners
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

    // Subscribe to state changes to update table UI
    state.subscribe(s => {
        renderTableBody(containerEl, s);
    });

    // Initial fetch
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
            <div style="padding: 20px; text-align: center;">
                <span class="loading-spinner"></span>
                <span style="margin-left: 8px; color: var(--text-sub);">Loading canonical vulnerabilities dataset...</span>
            </div>
        `;
        return;
    }

    if (s.explorerError) {
        statusContainer.innerHTML = `
            <div class="error-banner">
                <strong>Error loading dataset:</strong> ${s.explorerError}
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

        const cvssDisplay = cvssVal !== null ? `${cvssVal.toFixed(1)} ${item.cvss_v31_base_severity || ''}` : 'N/A';
        const epssDisplay = item.epss ? `${(item.epss.epss_score * 100).toFixed(2)}% (${(item.epss.epss_percentile * 100).toFixed(0)}th %tile)` : 'N/A';
        const pubDate = new Date(item.published).toLocaleDateString();

        return `
            <tr data-cve="${item.cve_id}">
                <td class="cve-id-cell">${item.cve_id}</td>
                <td>${pubDate}</td>
                <td class="description-snippet" title="${escapeHtml(item.description_en || '')}">${escapeHtml(item.description_en || 'No description available')}</td>
                <td><span class="badge ${cvssBadgeClass}">${cvssDisplay}</span></td>
                <td><span class="badge badge-epss">${epssDisplay}</span></td>
                <td>${item.is_kev ? '<span class="badge badge-kev">CISA KEV</span>' : '<span style="color:var(--text-muted);">No</span>'}</td>
                <td>
                    <button class="btn btn-secondary btn-sm btn-inspect-cve" data-cve="${item.cve_id}">
                        Inspect Detail
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

    tbody.querySelectorAll('tr').forEach(tr => {
        tr.addEventListener('click', () => {
            const cveId = tr.getAttribute('data-cve');
            openCveDetail(cveId);
        });
    });

    // Pagination controls state
    const page = res.page;
    const totalPages = res.total_pages;
    const startIdx = (page - 1) * res.page_size + 1;
    const endIdx = Math.min(page * res.page_size, res.total);

    summaryEl.textContent = `Showing ${startIdx.toLocaleString()}–${endIdx.toLocaleString()} of ${res.total.toLocaleString()} vulnerabilities`;
    pageNumEl.textContent = `Page ${page} of ${totalPages}`;

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
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
