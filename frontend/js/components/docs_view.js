import { CONFIG } from '../config.js';

export function renderDocsView(containerEl) {
    const docs = [
        {
            id: "api-spec",
            title: "REST API Endpoint Specification",
            path: "docs/API.md",
            category: "Integration & Schema",
            status: "Production Ready",
            description: "Complete REST API reference for /api/v1 endpoints including authentication, dataset search, vulnerability detail, machine learning predictions, prioritization scoring, SHAP explainability, and research provenance.",
            summary: `
                <div style="font-family: var(--font-mono); font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-muted); margin-bottom: 8px;">Key Endpoints:</div>
                <ul style="padding-left: 18px; margin: 0; line-height: 1.6; color: var(--text-secondary);">
                    <li><code style="color: var(--text-primary);">GET /health</code>: System operational status and dataset freeze timestamp.</li>
                    <li><code style="color: var(--text-primary);">POST /api/v1/auth/login</code>: Analyst / Researcher authentication and token issuance.</li>
                    <li><code style="color: var(--text-primary);">GET /api/v1/vulnerabilities</code>: Multi-parameter search across 366,547 canonical CVEs with DuckDB backend.</li>
                    <li><code style="color: var(--text-primary);">POST /api/v1/predict/cvss</code>: Pre-scoring CVSS estimation (EXP-A1) using frozen gradient boosted trees.</li>
                    <li><code style="color: var(--text-primary);">POST /api/v1/predict/kev</code>: Publication-time KEV risk prediction (EXP-B2) under strict temporal boundaries.</li>
                    <li><code style="color: var(--text-primary);">POST /api/v1/prioritize</code>: Dual-mode prioritization comparison (Mode 1 Linear vs Mode 2 Nonlinear Surface).</li>
                    <li><code style="color: var(--text-primary);">POST /api/v1/explain/cvss</code>: TreeExplainer Shapley feature contributions.</li>
                    <li><code style="color: var(--text-primary);">GET /api/v1/provenance</code>: Canonical dataset manifest, temporal partitions, and benchmark ledger.</li>
                </ul>
            `
        },
        {
            id: "backend-arch",
            title: "System Architecture & Data Layer",
            path: "docs/ARCHITECTURE.md",
            category: "System Architecture",
            status: "Implemented",
            description: "Detailed architecture overview of the FastAPI application layer, read-only DuckDB analytical engine, serialized XGBoost model registry, SQLite authentication store, and Vanilla JS SPA client.",
            summary: `
                <div style="font-family: var(--font-mono); font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-muted); margin-bottom: 8px;">Architectural Highlights:</div>
                <ul style="padding-left: 18px; margin: 0; line-height: 1.6; color: var(--text-secondary);">
                    <li><strong>FastAPI Core:</strong> High-throughput asynchronous endpoints with strict Pydantic v2 validation.</li>
                    <li><strong>DuckDB Engine:</strong> Sub-50ms columnar SQL query execution directly on 6 partitioned Parquet tables.</li>
                    <li><strong>Model Isolation:</strong> Pre-compiled scikit-learn and XGBoost pipelines with zero prediction drift.</li>
                    <li><strong>Zero-Build Frontend:</strong> Modern Vanilla JavaScript ES modules with responsive, restrained styling.</li>
                </ul>
            `
        },
        {
            id: "data-manifest",
            title: "Dataset Freeze Manifest & Lineage",
            path: "docs/research/DATA_MANIFEST.md",
            category: "Research Provenance",
            status: "Canonical",
            description: "Complete inventory of the canonical research corpus frozen on 2026-07-26, covering NVD CVE JSON 2.0 feeds, CISA KEV catalog, and FIRST EPSS static snapshots.",
            summary: `
                <div style="font-family: var(--font-mono); font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-muted); margin-bottom: 8px;">Manifest Inventory:</div>
                <ul style="padding-left: 18px; margin: 0; line-height: 1.6; color: var(--text-secondary);">
                    <li><strong>Total CVEs:</strong> 366,547 deduplicated canonical records spanning 2002 through 2026.</li>
                    <li><strong>CISA KEV:</strong> 1,647 verified in-the-wild exploited CVEs (positive label ground truth).</li>
                    <li><strong>EPSS Snapshot:</strong> 348,900 vulnerability records dated 2026-07-16.</li>
                    <li><strong>Partition Scheme:</strong> Train (2002–2022), Validation (2023–2024), Held-out Test (2025–2026).</li>
                </ul>
            `
        },
        {
            id: "experimental-protocol",
            title: "Experimental Protocol & Results",
            path: "docs/research/EXPERIMENTAL_PROTOCOL_AND_RESULTS.md",
            category: "Empirical Benchmarks",
            status: "Evaluated",
            description: "Rigorous temporal experimental protocols and benchmark evaluations across EXP-A1, EXP-B1, EXP-B2, and EXP-C1.",
            summary: `
                <div style="font-family: var(--font-mono); font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-muted); margin-bottom: 8px;">Experimental Findings:</div>
                <ul style="padding-left: 18px; margin: 0; line-height: 1.6; color: var(--text-secondary);">
                    <li><strong>EXP-A1 (CVSS Estimation):</strong> XGBoost regressor achieves MAE 0.9750 vs Ridge baseline 1.0954 (+11.0% improvement).</li>
                    <li><strong>EXP-B2 (Publication-Time KEV):</strong> PR-AUC 0.02884 vs LogReg 0.02077 (~5.5× uplift over 0.0052 random baseline).</li>
                    <li><strong>EXP-B1 (Leakage Audit):</strong> Exposing retrospective EPSS inflates test PR-AUC to 0.33153, illustrating substantial look-ahead effect.</li>
                    <li><strong>EXP-C1 (Prioritization Overlap):</strong> Top-100 Jaccard overlap between Mode 1 and Mode 2 is only 0.005, proving severe divergence under non-additive interaction.</li>
                </ul>
            `
        },
        {
            id: "research-limitations",
            title: "Methodological Limitations & Research Boundaries",
            path: "docs/research/RESEARCH_LIMITATIONS.md",
            category: "Academic Integrity",
            status: "Audited",
            description: "Formal documentation of dataset bounds, static snapshot constraints, absence of live telemetry, and boundaries of empirical evaluation.",
            summary: `
                <div style="font-family: var(--font-mono); font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-muted); margin-bottom: 8px;">Research Boundaries:</div>
                <ul style="padding-left: 18px; margin: 0; line-height: 1.6; color: var(--text-secondary);">
                    <li><strong>Static Snapshot:</strong> EPSS scores represent a static historical point and do not reflect subsequent daily recalibrations.</li>
                    <li><strong>Synthetic Asset Criticality:</strong> Evaluated using controlled discrete scalar tiers ($A \\in \\{0.25, 0.50, 0.75, 1.00\\}$) rather than dynamic CMDB configurations.</li>
                    <li><strong>Inference Interpretation:</strong> Predictions and SHAP values reflect statistical correlations learned from historical data, not physical exploit guarantees.</li>
                </ul>
            `
        },
        {
            id: "system-design",
            title: "Product Requirements & System Design",
            path: "docs/DESIGN.md",
            category: "Specifications",
            status: "Documented",
            description: "Comprehensive functional requirements, non-functional latency bounds, UI design language, security posture, and compliance criteria.",
            summary: `
                <div style="font-family: var(--font-mono); font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-muted); margin-bottom: 8px;">Design Principles:</div>
                <ul style="padding-left: 18px; margin: 0; line-height: 1.6; color: var(--text-secondary);">
                    <li><strong>Minimalist Aesthetic:</strong> Restrained warm industrial palette (warm off-white, charcoal, subtle scarlet, rare gold).</li>
                    <li><strong>Progressive Disclosure:</strong> High-frequency analytical data upfront; deep mathematical derivations inside disclosures.</li>
                    <li><strong>Deterministic Execution:</strong> Reproducible scoring rules with zero stochastic variance.</li>
                </ul>
            `
        }
    ];

    containerEl.innerHTML = `
        <div class="section-header">
            <div>
                <h2 class="section-title">Documentation & Research Specifications</h2>
                <p class="section-desc">Technical architecture references, REST API endpoint contracts, canonical data lineage manifests, and empirical research logs.</p>
            </div>
            <a href="${CONFIG.API_BASE_URL}/docs" target="_blank" rel="noopener noreferrer" class="btn btn-secondary btn-sm" style="display: inline-flex; align-items: center; gap: 6px;">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
                FastAPI Swagger Spec
            </a>
        </div>

        <div class="workspace-grid" style="grid-template-columns: 320px 1fr; gap: 24px; align-items: start;">
            <!-- Document Index Sidebar -->
            <div class="card" style="padding: 16px;">
                <div style="font-family: var(--font-mono); font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-muted); margin-bottom: 12px;">
                    INDEX MANIFEST
                </div>
                <div style="display: flex; flex-direction: column; gap: 8px;" id="docs-list-container">
                    ${docs.map((doc, idx) => `
                        <div class="doc-item-row ${idx === 0 ? 'selected' : ''}" data-doc-id="${doc.id}" style="padding: 12px 14px; border-radius: var(--radius-sm); border: 1px solid ${idx === 0 ? 'var(--border-strong)' : 'var(--border-subtle)'}; background: ${idx === 0 ? 'var(--bg-elevated)' : 'var(--bg-surface)'}; cursor: pointer; transition: all var(--transition-fast);">
                            <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 4px;">
                                <strong style="font-size: 13px; color: var(--text-primary);">${doc.title}</strong>
                            </div>
                            <div style="font-size: 11px; color: var(--text-secondary);">${doc.category}</div>
                            <div style="font-family: var(--font-mono); font-size: 10px; color: var(--text-muted); margin-top: 4px;">${doc.path}</div>
                        </div>
                    `).join('')}
                </div>
            </div>

            <!-- Selected Document Preview Card -->
            <div class="card" style="padding: 24px;">
                <div class="card-header" style="padding-bottom: 14px; margin-bottom: 18px; border-bottom: 1px solid var(--border-subtle);">
                    <h3 class="card-title" id="doc-detail-title" style="font-size: 17px; margin: 0;">${docs[0].title}</h3>
                </div>
                <div id="doc-detail-body">
                    <!-- Populated dynamically -->
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
            <div style="margin-bottom: 18px; display: flex; flex-wrap: wrap; gap: 8px; align-items: center;">
                <span class="badge badge-neutral">${escapeHtml(doc.status)}</span>
                <span class="badge badge-gold">${escapeHtml(doc.category)}</span>
                <span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); background: var(--bg-muted); padding: 4px 8px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
                    ${escapeHtml(doc.path)}
                </span>
            </div>

            <div style="font-size: 13px; color: var(--text-primary); line-height: 1.6; margin-bottom: 20px;">
                ${escapeHtml(doc.description)}
            </div>

            <div style="background: var(--bg-muted); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: 18px; font-size: 12px; line-height: 1.6;">
                ${doc.summary}
            </div>
        `;
    };

    // Render initial document
    renderDocDetail(docs[0]);

    // Attach click listeners to rows
    listContainer.querySelectorAll('.doc-item-row').forEach(row => {
        row.addEventListener('click', () => {
            listContainer.querySelectorAll('.doc-item-row').forEach(r => {
                r.style.borderColor = 'var(--border-subtle)';
                r.style.background = 'var(--bg-surface)';
            });
            row.style.borderColor = 'var(--border-strong)';
            row.style.background = 'var(--bg-elevated)';

            const docId = row.getAttribute('data-doc-id');
            const found = docs.find(d => d.id === docId);
            if (found) {
                renderDocDetail(found);
            }
        });
    });
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
