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
                <h2 class="section-title">Academic Researcher Workspace</h2>
                <p class="section-desc">Temporal evaluation partitions, empirical benchmark metrics, SHAP feature attributions, and canonical dataset provenance.</p>
            </div>
            <span class="badge badge-neutral" style="font-size: 11px;">Role: Researcher</span>
        </div>

        <div id="researcher-status-container"></div>

        <!-- Temporal Evaluation Protocol & Partition Summary -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 14px; margin-bottom: 24px;">
            <div class="card" style="padding: 14px 16px; margin-bottom: 0;">
                <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em;">Canonical Disclosures</div>
                <div style="font-family: var(--font-mono); font-size: 22px; font-weight: 700; color: var(--text-primary); margin-top: 4px;" id="res-stat-cves">366,547</div>
                <div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px;">NVD Corpus (2002–2026)</div>
            </div>

            <div class="card" style="padding: 14px 16px; margin-bottom: 0;">
                <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em;">Train Partition</div>
                <div style="font-family: var(--font-mono); font-size: 18px; font-weight: 700; color: var(--text-primary); margin-top: 6px;">203,652 CVEs</div>
                <div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px;">2002–2022 (1,029 KEV pos)</div>
            </div>

            <div class="card" style="padding: 14px 16px; margin-bottom: 0;">
                <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em;">Validation Partition</div>
                <div style="font-family: var(--font-mono); font-size: 18px; font-weight: 700; color: var(--text-primary); margin-top: 6px;">71,653 CVEs</div>
                <div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px;">2023–2024 (324 KEV pos)</div>
            </div>

            <div class="card" style="padding: 14px 16px; margin-bottom: 0; border-top: 3px solid var(--accent-scarlet);">
                <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--accent-scarlet); letter-spacing: 0.04em;">Held-Out Test Partition</div>
                <div style="font-family: var(--font-mono); font-size: 18px; font-weight: 700; color: var(--text-primary); margin-top: 6px;">91,242 CVEs</div>
                <div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px;">2025–2026 (294 KEV pos)</div>
            </div>
        </div>

        <!-- Research Guided Workflow Cards -->
        <div style="margin-bottom: 24px;">
            <div style="font-family: var(--font-mono); font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-muted); margin-bottom: 12px;">
                RESEARCH WORKFLOWS
            </div>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px;">
                <div class="card" style="margin-bottom: 0; cursor: pointer; padding: 16px; transition: all var(--transition-fast);" onclick="window.location.hash='provenance'">
                    <div style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 4px;">1. Research Provenance &rarr;</div>
                    <div style="font-size: 12px; color: var(--text-secondary); line-height: 1.5;">Inspect canonical dataset freeze manifest (2026-07-26) and audit logs.</div>
                </div>

                <div class="card" style="margin-bottom: 0; cursor: pointer; padding: 16px; transition: all var(--transition-fast);" onclick="window.location.hash='explain'">
                    <div style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 4px;">2. SHAP Explainability &rarr;</div>
                    <div style="font-size: 12px; color: var(--text-secondary); line-height: 1.5;">Decompose model predictions into Shapley feature attributions.</div>
                </div>

                <div class="card" style="margin-bottom: 0; cursor: pointer; padding: 16px; transition: all var(--transition-fast);" onclick="window.location.hash='docs'">
                    <div style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 4px;">3. Documentation & Schemas &rarr;</div>
                    <div style="font-size: 12px; color: var(--text-secondary); line-height: 1.5;">Review Parquet schemas, API specs, and experimental protocols.</div>
                </div>

                <div class="card" style="margin-bottom: 0; cursor: pointer; padding: 16px; transition: all var(--transition-fast);" onclick="window.location.hash='explorer'">
                    <div style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 4px;">4. Vulnerability Explorer &rarr;</div>
                    <div style="font-size: 12px; color: var(--text-secondary); line-height: 1.5;">Query canonical vulnerability records, CWE taxonomies, and CPE configurations.</div>
                </div>
            </div>
        </div>

        <!-- Experiment Benchmarks Matrix -->
        <div class="card" style="margin-bottom: 24px;">
            <div class="card-header" style="padding-bottom: 12px; margin-bottom: 16px; border-bottom: 1px solid var(--border-subtle);">
                <h3 class="card-title" style="font-size: 15px; margin: 0;">Phase 3 Empirical Benchmark Summary</h3>
            </div>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 14px;">
                <div style="background: var(--bg-muted); padding: 14px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
                    <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em;">EXP-A1 · CVSS REGRESSOR</div>
                    <div style="font-family: var(--font-mono); font-size: 24px; font-weight: 700; color: var(--text-primary); margin: 6px 0 2px 0;">MAE 0.9750</div>
                    <div style="font-size: 11px; color: var(--text-secondary);">vs Ridge baseline 1.0954 (+11.0% relative improvement).</div>
                </div>

                <div style="background: var(--bg-muted); padding: 14px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
                    <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em;">EXP-B2 · PUBLICATION-TIME KEV</div>
                    <div style="font-family: var(--font-mono); font-size: 24px; font-weight: 700; color: var(--accent-scarlet); margin: 6px 0 2px 0;">PR-AUC 0.02884</div>
                    <div style="font-size: 11px; color: var(--text-secondary);">vs LogReg 0.02077 (~5.5× uplift over random baseline).</div>
                </div>

                <div style="background: var(--bg-muted); padding: 14px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
                    <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em;">EXP-B1 · LEAKAGE AUDIT</div>
                    <div style="font-family: var(--font-mono); font-size: 24px; font-weight: 700; color: var(--accent-gold); margin: 6px 0 2px 0;">PR-AUC 0.33153</div>
                    <div style="font-size: 11px; color: var(--text-secondary);">Retrospective look-ahead effect; excluded from B2 pipeline.</div>
                </div>

                <div style="background: var(--bg-muted); padding: 14px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
                    <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em;">EXP-C1 · QUEUE DIVERGENCE</div>
                    <div style="font-family: var(--font-mono); font-size: 24px; font-weight: 700; color: var(--text-primary); margin: 6px 0 2px 0;">Jaccard 0.005</div>
                    <div style="font-size: 11px; color: var(--text-secondary);">Top-100 queue overlap between linear and nonlinear surfaces.</div>
                </div>
            </div>
        </div>

        <!-- Research Limitations & Methodological Discipline -->
        <div style="background: var(--bg-muted); border: 1px solid var(--border-subtle); border-left: 3px solid var(--accent-gold); border-radius: var(--radius-sm); padding: 16px; font-size: 12px; line-height: 1.6;">
            <div style="font-family: var(--font-mono); font-size: 11px; font-weight: 600; color: var(--text-primary); margin-bottom: 6px; letter-spacing: 0.04em;">
                METHODOLOGICAL DISCIPLINE & EVALUATION BOUNDARIES
            </div>
            <ul style="padding-left: 18px; margin: 0; color: var(--text-secondary);">
                <li><strong>Static EPSS Snapshot:</strong> EPSS scores represent a static snapshot dated <code>2026-07-16T12:03:48Z</code> and were not historical publication-time inputs.</li>
                <li><strong>Controlled Asset Criticality Tiers:</strong> Enterprise asset context is modeled using 4 controlled synthetic tiers ($A \\in \\{0.25, 0.50, 0.75, 1.00\\}$) rather than dynamic CMDB telemetry.</li>
                <li><strong>SHAP Attribution Scope:</strong> Shapley values indicate model decision weights based on training distributions and do not establish physical execution mechanisms.</li>
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
            if (elCves) elCves.textContent = (m.total_canonical_cves || 366547).toLocaleString();
        }
    } catch (e) {
        // Fallback to static metrics
    }
}
