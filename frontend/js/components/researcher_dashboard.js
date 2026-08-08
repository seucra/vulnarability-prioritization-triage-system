/**
 * Academic Researcher Role Dashboard Component
 * Purpose: Research Methodology, Model Evaluation, & Provenance Inspection
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { api } from '../api.js';
import { state } from '../state.js';

export function renderResearcherDashboard(containerEl) {
    containerEl.innerHTML = `
        <div class="section-header">
            <div>
                <h2 class="section-title">Academic Research & Methodology Dashboard</h2>
                <p class="section-desc">Temporal evaluation partitions, experiment benchmark metrics, SHAP feature attributions, and dataset provenance manifests.</p>
            </div>
            <span class="badge badge-medium" style="font-size: 12px; padding: 6px 12px;">Active Role: Researcher</span>
        </div>

        <div id="researcher-status-container"></div>

        <!-- Temporal Evaluation Protocol & Dataset Summary -->
        <div class="provenance-grid" style="margin-bottom: 24px;">
            <div class="provenance-stat-box">
                <div class="provenance-stat-label">Total Canonical Disclosures</div>
                <div class="provenance-stat-val" id="res-stat-cves">366,547</div>
                <div style="font-size: 11px; color: var(--text-sub); margin-top: 4px;">NVD CVE Dataset (2002–2026)</div>
            </div>

            <div class="provenance-stat-box">
                <div class="provenance-stat-label">Train Partition (2002–2022)</div>
                <div class="provenance-stat-val" style="font-size: 18px; color: var(--primary);">208,602 CVEs</div>
                <div style="font-size: 11px; color: var(--text-sub); margin-top: 4px;">Model Parameter Training</div>
            </div>

            <div class="provenance-stat-box">
                <div class="provenance-stat-label">Validation Partition (2023–2024)</div>
                <div class="provenance-stat-val" style="font-size: 18px; color: var(--tertiary);">71,061 CVEs</div>
                <div style="font-size: 11px; color: var(--text-sub); margin-top: 4px;">Hyperparameter Tuning Only</div>
            </div>

            <div class="provenance-stat-box" style="border-left: 4px solid var(--success);">
                <div class="provenance-stat-label">Test Partition (2025–2026)</div>
                <div class="provenance-stat-val" style="font-size: 18px; color: var(--success);">86,884 CVEs</div>
                <div style="font-size: 11px; color: var(--success); font-weight: 600; margin-top: 4px;">Held-Out Test Evaluation</div>
            </div>
        </div>

        <!-- Researcher Guided Workflow Cards -->
        <h3 class="section-title" style="font-size: 16px; margin-bottom: 12px;">Research & Methodology Workspaces</h3>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 14px; margin-bottom: 24px;">
            <div class="card" style="margin-bottom: 0; cursor: pointer; border-left: 3px solid var(--primary);" onclick="window.location.hash='provenance'">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <strong style="font-size: 13px; color: var(--primary);">1. Research Provenance</strong>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
                </div>
                <p style="font-size: 12px; color: var(--text-sub);">Inspect canonical dataset freeze manifest (2026-07-26) and experiment logs.</p>
            </div>

            <div class="card" style="margin-bottom: 0; cursor: pointer; border-left: 3px solid var(--tertiary);" onclick="window.location.hash='explain'">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <strong style="font-size: 13px; color: var(--tertiary);">2. SHAP Explainability</strong>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
                </div>
                <p style="font-size: 12px; color: var(--text-sub);">Decompose model predictions into Shapley feature attributions with causal disclaimers.</p>
            </div>

            <div class="card" style="margin-bottom: 0; cursor: pointer; border-left: 3px solid var(--success);" onclick="window.location.hash='docs'">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <strong style="font-size: 13px; color: var(--success);">3. Documentation & Schemas</strong>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
                </div>
                <p style="font-size: 12px; color: var(--text-sub);">Review Parquet dataset schemas, API endpoint specs, and phase research reports.</p>
            </div>

            <div class="card" style="margin-bottom: 0; cursor: pointer; border-left: 3px solid var(--primary);" onclick="window.location.hash='explorer'">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <strong style="font-size: 13px; color: var(--primary);">4. Vulnerability Dataset</strong>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"/></svg>
                </div>
                <p style="font-size: 12px; color: var(--text-sub);">Search and query canonical vulnerability records, CWE classifications, and CPE nodes.</p>
            </div>
        </div>

        <!-- Experiment Benchmarks Matrix -->
        <div class="card" style="margin-bottom: 24px;">
            <h3 class="card-title">Phase 3 Machine Learning Experiment Benchmarks</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-top: 12px;">
                <div style="background: var(--bg-surface-low); padding: 14px; border-radius: var(--radius-md); border: 1px solid var(--border-color);">
                    <div class="input-label" style="font-size: 11px;">EXP-A1 Pre-Scoring CVSS Regressor</div>
                    <div style="font-family: var(--font-mono); font-size: 24px; font-weight: 700; color: var(--primary); margin: 4px 0;">MAE 0.9750</div>
                    <div style="font-size: 11px; color: var(--text-sub);">XGBoost Regressor on initial text description + metadata TF-IDF features.</div>
                </div>

                <div style="background: var(--bg-surface-low); padding: 14px; border-radius: var(--radius-md); border: 1px solid var(--border-color);">
                    <div class="input-label" style="font-size: 11px;">EXP-B2 Publication-Time KEV Classifier</div>
                    <div style="font-family: var(--font-mono); font-size: 24px; font-weight: 700; color: var(--primary); margin: 4px 0;">PR-AUC 0.02884</div>
                    <div style="font-size: 11px; color: var(--success); font-weight: 600;">8.96x Precision Uplift over Random (0.00322)</div>
                </div>

                <div style="background: var(--bg-surface-low); padding: 14px; border-radius: var(--radius-md); border: 1px solid var(--border-color);">
                    <div class="input-label" style="font-size: 11px;">EXP-B1 Data Leakage Finding</div>
                    <div style="font-family: var(--font-mono); font-size: 24px; font-weight: 700; color: var(--warning); margin: 4px 0;">Boundary Enforced</div>
                    <div style="font-size: 11px; color: var(--text-sub);">Post-publication EPSS & CVSS features strictly excluded at publication-time.</div>
                </div>
            </div>
        </div>

        <!-- Research Limitations & Methodological Discipline -->
        <div class="card" style="border-left: 4px solid var(--warning); background-color: var(--bg-surface-low);">
            <h4 style="font-size: 14px; font-weight: 600; color: var(--text-main); margin-bottom: 8px;">
                Methodological Discipline & Known Research Limitations
            </h4>
            <ul style="padding-left: 20px; font-size: 12px; color: var(--text-sub); line-height: 1.6;">
                <li><strong>Static EPSS Snapshot:</strong> EPSS scores represent a static snapshot dated <code>2026-07-16T12:03:48Z</code> and were not historical publication-time inputs.</li>
                <li><strong>Controlled Asset Criticality Tiers:</strong> Enterprise asset context is modeled using 4 controlled synthetic tiers ($A \\in \\{0.25, 0.50, 0.75, 1.00\\}$) rather than dynamic CMDB telemetry.</li>
                <li><strong>SHAP Attribution Scope:</strong> Shapley values indicate model decision weights based on training distributions and do not establish physical software execution mechanisms.</li>
            </ul>
        </div>
    `;

    loadResearcherDashboardData(containerEl);
}

async function loadResearcherDashboardData(containerEl) {
    try {
        const provData = await api.getProvenance();
        if (provData && provData.dataset_freeze_manifest) {
            const m = provData.dataset_freeze_manifest;
            const elCves = containerEl.querySelector('#res-stat-cves');
            if (elCves) elCves.textContent = (m.total_canonical_cves || m.total_cves || 366547).toLocaleString();
        }
    } catch (e) {
        // Fallback to static metrics
    }
}
