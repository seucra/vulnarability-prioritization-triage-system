/**
 * Integrated Documentation Center Component
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

export function renderDocsView(containerEl) {
    const docs = [
        {
            id: "user-manual",
            title: "User & Triage Workflow Manual",
            path: "docs/USER_MANUAL.md",
            category: "User Documentation",
            status: "Available",
            description: "Complete guide covering user registration, role selection, authentication, dashboard views, vulnerability explorer, predictions, asset prioritization, SHAP explainability, research provenance, and report exporting.",
            summary: `
                <h4>User Workflow Summary:</h4>
                <ul>
                    <li><strong>Account & Roles:</strong> Self-register as Security Analyst or Researcher; sign in as Administrator using pre-seeded credentials.</li>
                    <li><strong>Explorer:</strong> Search 366,547 CVEs using vendor, product, CWE weakness, CVSS range, and CISA KEV filters. Export results page to CSV/JSON.</li>
                    <li><strong>Predictions:</strong> Run EXP-A1 CVSS base score regressor or EXP-B2 publication-time KEV risk classifier on custom vulnerability descriptions.</li>
                    <li><strong>Prioritization:</strong> Simulate asset criticality tiers ($A \\in \\{0.25, 0.50, 0.75, 1.00\\}$) using Mode 1 Linear ($S_{\\text{linear}}$) or Mode 2 Surface ($S_{\\text{nonlinear}}$).</li>
                    <li><strong>Explainability:</strong> Decompose predictions into Shapley feature attributions with causal disclaimers.</li>
                    <li><strong>Printable Report:</strong> Generate clean printable triage reports directly from any inspected CVE drawer.</li>
                </ul>
            `
        },
        {
            id: "api-spec",
            title: "REST API Endpoint Specification",
            path: "docs/architecture/API.md",
            category: "API & Integration",
            status: "Available",
            description: "Complete REST API reference for /api/v1 endpoints including authentication, vulnerabilities search, CVE detail, ML predictions, prioritization scoring, SHAP explainability, and provenance.",
            summary: `
                <h4>Key Endpoints Documented:</h4>
                <ul>
                    <li><code>GET /health</code>: System health and freeze metadata</li>
                    <li><code>POST /api/v1/auth/login</code>: Authentication & HMAC token issuance</li>
                    <li><code>GET /api/v1/auth/users</code>: Admin user accounts directory</li>
                    <li><code>GET /api/v1/vulnerabilities</code>: Multi-parameter search over 366,547 CVEs</li>
                    <li><code>POST /api/v1/predict/cvss</code>: Pre-scoring CVSS estimation (EXP-A1)</li>
                    <li><code>POST /api/v1/predict/kev</code>: Publication-time KEV risk prediction (EXP-B2)</li>
                    <li><code>POST /api/v1/prioritize</code>: Dual-mode prioritization scoring (Mode 1 & Mode 2)</li>
                    <li><code>POST /api/v1/explain/cvss</code>: Local SHAP TreeExplainer attributions</li>
                    <li><code>GET /api/v1/provenance</code>: Academic freeze manifest & experiment benchmarks</li>
                </ul>
            `
        },
        {
            id: "sys-reqs",
            title: "System Requirements & Constraints",
            path: "docs/SYSTEM_REQUIREMENTS.md",
            category: "System Specifications",
            status: "Available",
            description: "Functional requirements, non-functional performance bounds, data engineering constraints, hardware prerequisites, and system design specifications.",
            summary: `
                <h4>Requirements & Bounds:</h4>
                <ul>
                    <li><strong>Operating Environment:</strong> Linux / macOS / Windows with Python 3.10+ standard library.</li>
                    <li><strong>Query Engine Latency:</strong> Sub-100ms DuckDB SQL query execution over <code>data/processed/*.parquet</code>.</li>
                    <li><strong>Model Re-serialization:</strong> Zero prediction error drift ($0.00000000$) between serialized Phase 4 binaries and Phase 3 research artifacts.</li>
                    <li><strong>Feature Boundary Guard:</strong> Strict server-side rejection of post-publication EPSS/CVSS features during publication-time KEV inference.</li>
                </ul>
            `
        },
        {
            id: "backend-arch",
            title: "System Architecture & Data Layer",
            path: "docs/architecture/PHASE_4_BACKEND_ARCHITECTURE.md",
            category: "System Architecture",
            status: "Available",
            description: "Detailed architecture overview of the FastAPI application layer, DuckDB read-only query engine, serialized XGBoost model loading, SQLite auth database, and Vanilla JS SPA frontend.",
            summary: `
                <h4>Architecture Stack:</h4>
                <ul>
                    <li><strong>FastAPI Application Layer:</strong> Pydantic validation, CORS middleware, JWT-compatible auth dependencies.</li>
                    <li><strong>DuckDB Read-Only Layer:</strong> High-performance columnar SQL queries over 6 Parquet tables.</li>
                    <li><strong>SQLite User Store:</strong> Local user account persistence with PBKDF2-HMAC-SHA256 password hashing.</li>
                    <li><strong>Vanilla JS SPA:</strong> Zero-dependency frontend architecture with hash routing and role-aware navigation.</li>
                </ul>
            `
        },
        {
            id: "setup-guide",
            title: "Setup & Installation Guide",
            path: "docs/SETUP.md",
            category: "Deployment & Operations",
            status: "Available",
            description: "Step-by-step setup instructions for virtual environment creation, dependency installation, backend Uvicorn startup, and testing execution.",
            summary: `
                <h4>Quickstart Commands:</h4>
                <ul>
                    <li><code>python -m venv .venv && source .venv/bin/activate</code></li>
                    <li><code>pip install -r requirements.txt</code></li>
                    <li><code>PYTHONPATH=. uvicorn backend.app.main:app --port 8000</code></li>
                    <li><code>pytest tests/test_auth_rbac.py tests/test_backend_api.py tests/test_etl_invariants.py</code></li>
                </ul>
            `
        },
        {
            id: "testing-spec",
            title: "Testing & Quality Assurance",
            path: "docs/TESTING.md",
            category: "Quality Assurance",
            status: "Available",
            description: "Automated test suite documentation covering Auth & RBAC security tests, REST API endpoints, ETL invariants, and browser E2E workflows.",
            summary: `
                <h4>Test Categories (39 Passing Tests):</h4>
                <ul>
                    <li><strong>Auth & RBAC (15 Tests):</strong> Registration, authentication, token claims, role authorization, privilege escalation prevention, account disabling.</li>
                    <li><strong>REST API (9 Tests):</strong> Search, detail, predictions, prioritization, SHAP explainability, provenance.</li>
                    <li><strong>ETL Invariants (15 Tests):</strong> Parquet row counts, non-null primary keys, CVSS bounds, timestamp consistency.</li>
                </ul>
            `
        },
        {
            id: "limitations-future",
            title: "Research Limitations & Future Scope",
            path: "docs/LIMITATIONS_AND_FUTURE_SCOPE.md",
            category: "Research Methodology",
            status: "Available",
            description: "Explicit documentation of dataset boundaries, static snapshot constraints, research assumptions, and future engineering/research extensions.",
            summary: `
                <h4>Limitations & Future Extensions:</h4>
                <ul>
                    <li><strong>Dataset Freeze Boundary:</strong> Canonical dataset frozen at 366,547 CVEs (2002–2026).</li>
                    <li><strong>Static EPSS Snapshot:</strong> EPSS scores reflect a static snapshot dated <code>2026-07-16</code>.</li>
                    <li><strong>Synthetic Asset Tiers:</strong> Asset criticality is evaluated in 4 synthetic tiers ($A \\in \\{0.25, 0.50, 0.75, 1.00\\}$).</li>
                    <li><strong>Future Scope:</strong> Dynamic CMDB telemetry integration, live EPSS feed sync, multi-tenant RBAC.</li>
                </ul>
            `
        }
    ];

    containerEl.innerHTML = `
        <div class="section-header">
            <div>
                <h2 class="section-title">System & Research Documentation Center</h2>
                <p class="section-desc">In-app access to system specifications, API references, architecture guides, dataset schemas, user manuals, and academic research logs.</p>
            </div>
            <a href="http://localhost:8000/api/v1/docs" target="_blank" class="btn btn-outline btn-sm">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
                Open FastAPI Swagger Specs
            </a>
        </div>

        <div class="workspace-grid">
            <!-- Documentation Index List -->
            <div class="card" style="margin-bottom: 0;">
                <h3 class="card-title">Documentation Index</h3>
                <div style="display: flex; flex-direction: column; gap: 10px;" id="docs-list-container">
                    ${docs.map((doc, idx) => `
                        <div class="doc-item-row ${idx === 0 ? 'selected' : ''}" data-doc-id="${doc.id}" style="padding: 12px; border-radius: var(--radius-md); border: 1px solid ${idx === 0 ? 'var(--primary)' : 'var(--border-color)'}; background: var(--bg-surface-low); cursor: pointer; transition: all var(--transition-fast);">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                                <strong style="font-size: 13px; color: var(--text-main);">${doc.title}</strong>
                                <span class="badge badge-low">${doc.status}</span>
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
                    <span class="badge badge-low">${doc.status}</span>
                    <span class="repo-badge">${doc.category}</span>
                </div>
                <div style="font-family: var(--font-mono); font-size: 11px; color: var(--text-sub); background: var(--bg-surface-low); padding: 6px 10px; border-radius: var(--radius-sm); border: 1px solid var(--border-color);">
                    Documentation Path: ${doc.path}
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
