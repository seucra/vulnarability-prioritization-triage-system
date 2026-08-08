/**
 * Integrated Documentation Index & Reader Component Controller
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

export function renderDocsView(containerEl) {
    const docs = [
        {
            id: "api-spec",
            title: "REST API Endpoint Specification",
            path: "docs/architecture/API.md",
            category: "API & Integration",
            status: "Available",
            description: "Complete REST API reference for /api/v1 endpoints including vulnerabilities search, CVE detail, ML predictions, prioritization scoring, SHAP explainability, and provenance.",
            summary: `
                <h4>Key Endpoints Documented:</h4>
                <ul>
                    <li><code>GET /health</code>: System health and freeze metadata</li>
                    <li><code>GET /api/v1/vulnerabilities</code>: Multi-parameter search & pagination over 366,547 CVEs</li>
                    <li><code>GET /api/v1/vulnerabilities/{cve_id}</code>: Full CVE record with isolated EPSS snapshot</li>
                    <li><code>POST /api/v1/predict/cvss</code>: Pre-scoring CVSS estimation (EXP-A1)</li>
                    <li><code>POST /api/v1/predict/kev</code>: Publication-time KEV risk prediction (EXP-B2)</li>
                    <li><code>POST /api/v1/prioritize</code>: Dual-mode prioritization scoring (Mode 1 & Mode 2)</li>
                    <li><code>POST /api/v1/explain/cvss</code> & <code>/kev</code>: Local SHAP TreeExplainer attributions</li>
                    <li><code>GET /api/v1/provenance</code>: Academic freeze manifest & experiment benchmarks</li>
                </ul>
            `
        },
        {
            id: "backend-arch",
            title: "Phase 4 Backend System Architecture",
            path: "docs/architecture/PHASE_4_BACKEND_ARCHITECTURE.md",
            category: "System Architecture",
            status: "Available",
            description: "Detailed architecture overview of the FastAPI application layer, DuckDB read-only query engine, serialized XGBoost model loading, Pydantic validation, and service boundaries.",
            summary: `
                <h4>Architecture Components:</h4>
                <ul>
                    <li><strong>FastAPI Main Entrypoint:</strong> Handles CORS, static SPA mounting, and 422 exception mapping.</li>
                    <li><strong>DuckDB Query Engine:</strong> Executes high-performance read-only queries over <code>data/processed/*.parquet</code>.</li>
                    <li><strong>Model Re-serialization:</strong> EXP-A1 Regressor & EXP-B2 Classifier loaded deterministically with 0.00000000 prediction error match against Phase 3 test outputs.</li>
                    <li><strong>Feature Boundary Guard:</strong> Strictly rejects post-publication EPSS/CVSS inputs on publication-time KEV prediction endpoints.</li>
                </ul>
            `
        },
        {
            id: "data-schema",
            title: "Processed Parquet Dataset Schema",
            path: "docs/research/PROCESSED_DATA_SCHEMA.md",
            category: "Data Engineering",
            status: "Available",
            description: "Field-level schema specifications for canonical processed Parquet files: vulnerabilities.parquet, epss.parquet, kev.parquet, cve_cwe.parquet, cve_cpe.parquet, and vendor_statements.parquet.",
            summary: `
                <h4>Schema Highlights:</h4>
                <ul>
                    <li><code>vulnerabilities.parquet</code>: 366,547 rows (1 row per CVE, 2002–2026).</li>
                    <li><code>epss.parquet</code>: 348,900 rows (epss score, percentile, snapshot date 2026-07-16).</li>
                    <li><code>kev.parquet</code>: 1,647 CISA catalog entries with action deadlines and ransomware flags.</li>
                    <li><code>cve_cwe.parquet</code> & <code>cve_cpe.parquet</code>: Normalized multi-CWE and multi-CPE child tables.</li>
                </ul>
            `
        },
        {
            id: "research-reports",
            title: "Phase 0–3 Academic Research Reports",
            path: "docs/research/PHASE_3_EXPERIMENT_REPORT.md",
            category: "Research Methodology",
            status: "Available",
            description: "Full research documentation covering Phase 0 raw data verification, Phase 1 deterministic ETL, Phase 2 experimental protocol, and Phase 3 experiment execution & SHAP analysis.",
            summary: `
                <h4>Experimental Protocol Summary:</h4>
                <ul>
                    <li><strong>Temporal Split Discipline:</strong> Train (2002–2022), Validation (2023–2024), Test (2025–2026). Zero cross-year reshuffling.</li>
                    <li><strong>EXP-A1 Benchmark:</strong> XGBoost Regressor CVSS v3.1 Estimation (MAE = 0.9750).</li>
                    <li><strong>EXP-B2 Benchmark:</strong> XGBoost Classifier KEV Prediction (PR-AUC = 0.02884, 8.96x Uplift vs Random).</li>
                    <li><strong>EXP-C1 Prioritization:</strong> Mode 1 Linear Equal Weights vs Mode 2 Nonlinear Interactive Surface.</li>
                </ul>
            `
        },
        {
            id: "raw-manifest",
            title: "Raw Dataset Manifest & SHA-256 Checksums",
            path: "docs/research/DATA_MANIFEST.md",
            category: "Data Engineering",
            status: "Available",
            description: "Immutability manifest documenting raw dataset download sources, sizes, record counts, and verified SHA-256 cryptographic hashes.",
            summary: `
                <h4>Verified Raw Files:</h4>
                <ul>
                    <li><code>known_exploited_vulnerabilities.csv</code> (CISA KEV)</li>
                    <li><code>epss_scores-2026-07-16.csv.gz</code> (FIRST EPSS Snapshot)</li>
                    <li><code>nvdcve-2.0-*.json.gz</code> (Official NVD Data Feeds 2002–2026)</li>
                    <li><code>vendorstatements.xml.gz</code> (NVD Vendor Statements)</li>
                </ul>
            `
        },
        {
            id: "srs-spec",
            title: "Software Requirements Specification (SRS)",
            path: "docs/SRS.md",
            category: "System Specification",
            status: "Available",
            description: "Functional requirements, non-functional performance bounds, data engineering constraints, and system design specifications.",
            summary: `
                <h4>SRS Sections:</h4>
                <ul>
                    <li><strong>Functional Requirements:</strong> Dataset search, CVE analyst detail, pre-scoring inference, prioritization scoring, SHAP attributions, provenance API.</li>
                    <li><strong>Non-Functional Bounds:</strong> Sub-100ms DuckDB query latency, deterministic model reproduction, zero raw dataset modification.</li>
                </ul>
            `
        },
        {
            id: "user-manual",
            title: "User Analyst & Triage Manual",
            path: "docs/USER_MANUAL.md",
            category: "User Documentation",
            status: "Forthcoming (WDL-6)",
            description: "Comprehensive step-by-step user guide for security analysts, vulnerability managers, and academic researchers navigating the triage workflow.",
            summary: "<p>Comprehensive user manual will be compiled during Phase WDL-6 deployment finalization.</p>"
        },
        {
            id: "sys-reqs",
            title: "System Hardware & Software Requirements",
            path: "docs/SYSTEM_REQUIREMENTS.md",
            category: "System Documentation",
            status: "Forthcoming (WDL-6)",
            description: "Detailed computing resource requirements, operating system support, Python dependencies, and memory footprint specifications.",
            summary: "<p>Detailed system requirements specification will be compiled during Phase WDL-6 deployment finalization.</p>"
        },
        {
            id: "deployment-guide",
            title: "Public Demonstration Deployment & Tunnel Setup",
            path: "docs/DEPLOYMENT.md",
            category: "Deployment Documentation",
            status: "Forthcoming (WDL-6)",
            description: "Docker containerization instructions, Uvicorn service configuration, and Cloudflare Tunnel setup for vuln-triage.seucra.tech.",
            summary: "<p>Public deployment documentation will be produced during Phase WDL-6 deployment finalization.</p>"
        }
    ];

    containerEl.innerHTML = `
        <div class="section-header">
            <div>
                <h2 class="section-title">System & Research Documentation Index</h2>
                <p class="section-desc">In-app access to system specifications, API references, architecture guides, dataset schemas, and academic research logs.</p>
            </div>
            <a href="http://localhost:8000/api/v1/docs" target="_blank" class="btn btn-outline btn-sm">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
                Open FastAPI Swagger Docs
            </a>
        </div>

        <div class="workspace-grid">
            <!-- Documentation Index List -->
            <div class="card" style="margin-bottom: 0;">
                <h3 class="card-title">Documentation Index</h3>
                <div style="display: flex; flex-direction: column; gap: 10px;" id="docs-list-container">
                    ${docs.map((doc, idx) => `
                        <div class="doc-item-row ${idx === 0 ? 'selected' : ''}" data-doc-id="${doc.id}" style="padding: 12px; border-radius: var(--radius-md); border: 1px solid var(--border-color); background: var(--bg-surface-low); cursor: pointer; transition: all var(--transition-fast);">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                                <strong style="font-size: 13px; color: var(--text-main);">${doc.title}</strong>
                                <span class="badge ${doc.status === 'Available' ? 'badge-low' : 'badge-medium'}">${doc.status}</span>
                            </div>
                            <div style="font-size: 11px; color: var(--text-sub);">${doc.category} • <code>${doc.path}</code></div>
                        </div>
                    `).join('')}
                </div>
            </div>

            <!-- Selected Document Preview Box -->
            <div class="card" style="margin-bottom: 0;">
                <h3 class="card-title" id="doc-detail-title">${docs[0].title}</h3>
                <div id="doc-detail-body">
                    <!-- Loaded dynamically -->
                </div>
            </div>
        </div>
    `;

    const listContainer = containerEl.querySelector('#docs-list-container');
    const detailTitle = containerEl.querySelector('#doc-detail-title');
    const detailBody = containerEl.querySelector('#doc-detail-body');

    const renderDocDetail = (doc) => {
        detailTitle.textContent = doc.title;
        detailBody.innerHTML = `
            <div style="margin-bottom: 16px;">
                <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 8px;">
                    <span class="badge ${doc.status === 'Available' ? 'badge-low' : 'badge-medium'}">${doc.status}</span>
                    <span class="repo-badge">${doc.category}</span>
                </div>
                <div style="font-family: var(--font-mono); font-size: 11px; color: var(--text-sub); background: var(--bg-surface-low); padding: 6px 10px; border-radius: var(--radius-sm); border: 1px solid var(--border-color);">
                    File Location: ${doc.path}
                </div>
            </div>

            <div style="font-size: 13px; color: var(--text-main); line-height: 1.6; margin-bottom: 16px;">
                ${doc.description}
            </div>

            <div style="background: var(--bg-surface-low); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 14px; font-size: 12px; line-height: 1.6;">
                ${doc.summary}
            </div>
        `;
    };

    // Render initial document
    renderDocDetail(docs[0]);

    // Attach click listeners to rows
    listContainer.querySelectorAll('.doc-item-row').forEach(row => {
        row.addEventListener('click', () => {
            listContainer.querySelectorAll('.doc-item-row').forEach(r => r.style.borderColor = 'var(--border-color)');
            row.style.borderColor = 'var(--primary)';
            const docId = row.getAttribute('data-doc-id');
            const found = docs.find(d => d.id === docId);
            if (found) {
                renderDocDetail(found);
            }
        });
    });
}
