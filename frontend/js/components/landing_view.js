/**
 * Overview / Landing View Component Controller
 * Visual Direction: Warm industrial minimalism meets academic security research
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { api } from '../api.js';

export function renderLandingView(containerEl) {
    containerEl.innerHTML = `
        <div class="section-header">
            <div class="section-header-content">
                <div class="section-eyebrow">Academic Research Prototype</div>
                <h1 class="section-title">Vulnerability Prioritization & Triage System</h1>
                <p class="section-desc">
                    A decision-support research instrument evaluating machine-learned CVSS pre-scoring, publication-time exploitation likelihood, and multi-criteria risk surfaces on 366k canonical vulnerabilities.
                </p>
            </div>
            <div class="section-actions">
                <button class="btn btn-primary" onclick="window.location.hash='explorer'">
                    Open Explorer
                </button>
                <button class="btn btn-outline" onclick="window.location.hash='provenance'">
                    Research Provenance
                </button>
            </div>
        </div>

        <!-- Dynamic Snapshot Strip -->
        <div class="snapshot-strip" id="overview-snapshot-strip">
            <div class="snapshot-item">
                <div class="snapshot-label">Canonical Dataset</div>
                <div class="snapshot-val" id="ov-cve-count">366,547</div>
                <div class="snapshot-sub">Disclosed CVEs (2002–2026)</div>
            </div>
            <div class="snapshot-item">
                <div class="snapshot-label">Dataset Freeze Date</div>
                <div class="snapshot-val" id="ov-freeze-date">2026-07-26</div>
                <div class="snapshot-sub">Bit-for-bit reproducible</div>
            </div>
            <div class="snapshot-item">
                <div class="snapshot-label">Exploitation Signals</div>
                <div class="snapshot-val" style="color: var(--accent-scarlet);" id="ov-kev-count">1,647</div>
                <div class="snapshot-sub">CISA KEV active exploits</div>
            </div>
            <div class="snapshot-item">
                <div class="snapshot-label">EPSS Snapshot Date</div>
                <div class="snapshot-val" id="ov-epss-date">2026-07-16</div>
                <div class="snapshot-sub">Model v2026.06.15</div>
            </div>
        </div>

        <!-- Principal Workflows & Benchmarks Grid -->
        <div class="workspace-grid" style="align-items: start;">
            <!-- Left: Principal Application Workflows -->
            <div class="card" style="margin-bottom: 0;">
                <div class="card-header">
                    <span class="card-title">
                        <svg class="card-title-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
                        Principal Workflows
                    </span>
                    <span style="font-size: 11px; font-family: var(--font-mono); color: var(--text-muted);">Interactive Tools</span>
                </div>

                <div style="display: flex; flex-direction: column; gap: 12px;">
                    <!-- 1. Explorer -->
                    <div style="padding: 12px; border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); background-color: var(--bg-surface);">
                        <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 4px;">
                            <strong style="font-size: 13px; color: var(--text-primary);">Vulnerability Explorer</strong>
                            <button class="btn btn-outline btn-sm" onclick="window.location.hash='explorer'">Explore &rarr;</button>
                        </div>
                        <p style="font-size: 12px; color: var(--text-secondary); line-height: 1.45; margin: 0;">
                            Multi-parameter queries over 366k CVE records across CVSS v3.1 base score bounds, CWE weaknesses, CPE products, and CISA KEV membership.
                        </p>
                    </div>

                    <!-- 2. Predict -->
                    <div style="padding: 12px; border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); background-color: var(--bg-surface);">
                        <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 4px;">
                            <strong style="font-size: 13px; color: var(--text-primary);">Predictive Workspaces</strong>
                            <button class="btn btn-outline btn-sm" onclick="window.location.hash='predict'">Predict &rarr;</button>
                        </div>
                        <p style="font-size: 12px; color: var(--text-secondary); line-height: 1.45; margin: 0;">
                            Evaluate disclosure-time CVSS estimation (EXP-A1) and publication-time KEV risk prediction (EXP-B2) under strict temporal-boundary rules.
                        </p>
                    </div>

                    <!-- 3. Prioritize -->
                    <div style="padding: 12px; border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); background-color: var(--bg-surface);">
                        <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 4px;">
                            <strong style="font-size: 13px; color: var(--text-primary);">Prioritization Sandbox</strong>
                            <button class="btn btn-outline btn-sm" onclick="window.location.hash='prioritize'">Sandbox &rarr;</button>
                        </div>
                        <p style="font-size: 12px; color: var(--text-secondary); line-height: 1.45; margin: 0;">
                            Simulate asset criticality tiers ($x_4 \\in \\{0.25, 0.50, 0.75, 1.00\\}$) and compare Mode 1 Linear ($S_{\\text{linear}}$) against Mode 2 Surface ($S_{\\text{nonlinear}}$).
                        </p>
                    </div>

                    <!-- 4. Batch Triage -->
                    <div style="padding: 12px; border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); background-color: var(--bg-surface);">
                        <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 4px;">
                            <strong style="font-size: 13px; color: var(--text-primary);">Batch Triage Queue</strong>
                            <button class="btn btn-outline btn-sm" onclick="window.location.hash='triage'">Batch Queue &rarr;</button>
                        </div>
                        <p style="font-size: 12px; color: var(--text-secondary); line-height: 1.45; margin: 0;">
                            Paste up to 100 CVE IDs for deterministic priority ranking, asset scaling, and analyst report exporting (CSV/JSON/Print).
                        </p>
                    </div>
                </div>
            </div>

            <!-- Right: Empirical Benchmarks -->
            <div class="card" style="margin-bottom: 0;">
                <div class="card-header">
                    <span class="card-title">
                        <svg class="card-title-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                        Empirical Research Benchmarks
                    </span>
                    <a href="#provenance" style="font-size: 11px; font-family: var(--font-mono); color: var(--accent-scarlet); text-decoration: none; font-weight: 500;">
                        Full Provenance &rarr;
                    </a>
                </div>

                <div class="table-container" style="border: none;">
                    <table class="data-table" style="font-size: 12px;">
                        <thead>
                            <tr>
                                <th>Experiment</th>
                                <th>Objective</th>
                                <th>Test Benchmark</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>
                                    <span class="cve-id-cell">EXP-A1</span>
                                    <div style="font-size: 10px; color: var(--text-muted);">Pre-Scoring</div>
                                </td>
                                <td>CVSS v3.1 Base Score Regression</td>
                                <td>
                                    <span style="font-family: var(--font-mono); font-weight: 600;">MAE: 0.9750</span>
                                    <div style="font-size: 10px; color: var(--sev-low);">-10.99% error vs Ridge 1.0954</div>
                                </td>
                            </tr>
                            <tr>
                                <td>
                                    <span class="cve-id-cell">EXP-B2</span>
                                    <div style="font-size: 10px; color: var(--text-muted);">Pub-Time</div>
                                </td>
                                <td>CISA KEV Exploitation Classification</td>
                                <td>
                                    <span style="font-family: var(--font-mono); font-weight: 600; color: var(--accent-scarlet);">PR-AUC: 0.02884</span>
                                    <div style="font-size: 10px; color: var(--text-muted);">8.96x vs Random (0.00322)</div>
                                </td>
                            </tr>
                            <tr>
                                <td>
                                    <span class="cve-id-cell">EXP-B1</span>
                                    <div style="font-size: 10px; color: var(--text-muted);">Retrospective</div>
                                </td>
                                <td>EPSS Sensitivity & Leakage Audit</td>
                                <td>
                                    <span style="font-family: var(--font-mono); font-weight: 600;">PR-AUC: 0.33153</span>
                                    <div style="font-size: 10px; color: var(--text-muted);">11.49x look-ahead inflation</div>
                                </td>
                            </tr>
                            <tr>
                                <td>
                                    <span class="cve-id-cell">EXP-C1</span>
                                    <div style="font-size: 10px; color: var(--text-muted);">Simulation</div>
                                </td>
                                <td>Multi-Criteria Surface Comparison</td>
                                <td>
                                    <span style="font-family: var(--font-mono); font-weight: 600;">Top-100 Jaccard: 0.005</span>
                                    <div style="font-size: 10px; color: var(--text-muted);">0.5% agreement (Disrupts ceiling)</div>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>

                <div class="callout-box" style="margin-top: 14px; font-size: 11px;">
                    <strong>Methodological Boundary:</strong>
                    EXP-B2 evaluates strictly on publication-time text and metadata. Post-publication signals (EPSS snapshot scores & CVSS vector metrics) are excluded to prevent retrospective look-ahead bias.
                </div>
            </div>
        </div>
    `;

    // Load live metadata dynamically from provenance endpoint
    loadProvenanceStats(containerEl);
}

async function loadProvenanceStats(containerEl) {
    try {
        const prov = await api.getProvenance();
        if (prov && prov.dataset_freeze_manifest) {
            const m = prov.dataset_freeze_manifest;
            const cveEl = containerEl.querySelector('#ov-cve-count');
            const dateEl = containerEl.querySelector('#ov-freeze-date');
            const kevEl = containerEl.querySelector('#ov-kev-count');
            const epssEl = containerEl.querySelector('#ov-epss-date');

            if (cveEl && m.total_canonical_cves) cveEl.textContent = m.total_canonical_cves.toLocaleString();
            if (dateEl && m.freeze_date) dateEl.textContent = m.freeze_date;
            if (kevEl && m.cisa_kev_cves) kevEl.textContent = m.cisa_kev_cves.toLocaleString();
            if (epssEl && prov.epss_snapshot_metadata && prov.epss_snapshot_metadata.snapshot_date) {
                epssEl.textContent = prov.epss_snapshot_metadata.snapshot_date.substring(0, 10);
            }
        }
    } catch (e) {
        // Fallbacks remain in static markup
    }
}
