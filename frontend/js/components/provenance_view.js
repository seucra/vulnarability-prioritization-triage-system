/**
 * Research Provenance & Methodology Component Controller
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { api } from '../api.js';
import { state } from '../state.js';

export function renderProvenanceView(containerEl) {
    containerEl.innerHTML = `
        <div class="section-header">
            <div>
                <h2 class="section-title">Research Provenance & Dataset Manifest</h2>
                <p class="section-desc">Academic provenance, canonical dataset freeze manifest, temporal partition discipline, empirical benchmark ledger, and methodological limitations.</p>
            </div>
            <button class="btn btn-secondary btn-sm" id="btn-refresh-provenance" type="button">
                Refresh Manifest
            </button>
        </div>

        <div id="provenance-content-body">
            <div style="padding: 48px 24px; text-align: center;">
                <span class="loading-spinner"></span>
                <p style="margin-top: 14px; font-size: 13px; color: var(--text-secondary);">Querying provenance and benchmark manifest from /api/v1/provenance...</p>
            </div>
        </div>
    `;

    const btnRefresh = containerEl.querySelector('#btn-refresh-provenance');
    btnRefresh.addEventListener('click', () => fetchProvenance(containerEl));

    fetchProvenance(containerEl);
}

async function fetchProvenance(containerEl) {
    const body = containerEl.querySelector('#provenance-content-body');
    state.setState({ isProvenanceLoading: true, provenanceError: null });

    try {
        const data = await api.getProvenance();
        state.setState({ provenanceData: data, isProvenanceLoading: false });
        renderProvenanceContent(body, data);
    } catch (err) {
        state.setState({ provenanceError: err.message, isProvenanceLoading: false });
        body.innerHTML = `
            <div style="background: var(--bg-muted); border: 1px solid var(--accent-scarlet); border-radius: var(--radius-sm); padding: 16px;">
                <div style="font-family: var(--font-mono); font-size: 12px; font-weight: 600; color: var(--accent-scarlet);">PROVENANCE ERROR</div>
                <div style="margin-top: 6px; font-size: 13px; color: var(--text-primary);">${escapeHtml(err.message)}</div>
            </div>
        `;
    }
}

function renderProvenanceContent(containerEl, data) {
    const manifest = data.dataset_freeze_manifest;
    const partitions = data.temporal_partitions;
    const epssMeta = data.epss_snapshot_metadata;
    const experiments = data.phase_3_experiments || [];
    const limitations = data.research_limitations || [];

    const expRowsHtml = experiments.map(exp => `
        <tr>
            <td style="font-family: var(--font-mono); font-weight: 700; color: var(--text-primary); font-size: 12px;">
                ${escapeHtml(exp.experiment_id)}
            </td>
            <td style="font-size: 12px; color: var(--text-primary);">
                ${escapeHtml(exp.target_variable)}
            </td>
            <td>
                <span class="badge badge-neutral" style="font-size: 10px;">${escapeHtml(exp.prediction_point)}</span>
            </td>
            <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-secondary);">
                ${escapeHtml(exp.primary_metric)}
            </td>
            <td style="font-family: var(--font-mono); font-size: 12px; color: var(--text-secondary);">
                ${escapeHtml(exp.baseline_performance)}
            </td>
            <td style="font-family: var(--font-mono); font-size: 12px; font-weight: 700; color: var(--text-primary);">
                ${escapeHtml(exp.nonlinear_performance)}
            </td>
            <td style="font-family: var(--font-mono); font-size: 11px; font-weight: 600; color: var(--accent-scarlet);">
                ${escapeHtml(exp.relative_improvement)}
            </td>
        </tr>
    `).join('');

    const limitListHtml = limitations.map(lim => `
        <li style="margin-bottom: 8px; font-size: 13px; color: var(--text-secondary); line-height: 1.6;">
            ${escapeHtml(lim)}
        </li>
    `).join('');

    containerEl.innerHTML = `
        <!-- 1. Dataset Freeze Manifest -->
        <div style="margin-bottom: 32px;">
            <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 14px;">
                <h3 style="font-size: 16px; font-weight: 600; color: var(--text-primary); margin: 0;">1. Canonical Dataset Manifest</h3>
                <span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">FREEZE DATE: ${escapeHtml(manifest.freeze_date)}</span>
            </div>

            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 14px; margin-bottom: 16px;">
                <div class="card" style="padding: 14px 16px; margin-bottom: 0;">
                    <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em;">Canonical CVEs</div>
                    <div style="font-family: var(--font-mono); font-size: 22px; font-weight: 700; color: var(--text-primary); margin-top: 4px;">
                        ${manifest.total_canonical_cves.toLocaleString()}
                    </div>
                </div>
                <div class="card" style="padding: 14px 16px; margin-bottom: 0;">
                    <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em;">CISA KEV Positives</div>
                    <div style="font-family: var(--font-mono); font-size: 22px; font-weight: 700; color: var(--accent-scarlet); margin-top: 4px;">
                        ${manifest.cisa_kev_cves.toLocaleString()}
                    </div>
                </div>
                <div class="card" style="padding: 14px 16px; margin-bottom: 0;">
                    <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em;">EPSS Records</div>
                    <div style="font-family: var(--font-mono); font-size: 22px; font-weight: 700; color: var(--text-primary); margin-top: 4px;">
                        ${manifest.epss_records.toLocaleString()}
                    </div>
                </div>
                <div class="card" style="padding: 14px 16px; margin-bottom: 0;">
                    <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em;">CVSS v3.1 Scored</div>
                    <div style="font-family: var(--font-mono); font-size: 22px; font-weight: 700; color: var(--text-primary); margin-top: 4px;">
                        ${manifest.cvss_v31_scored_cves.toLocaleString()}
                    </div>
                </div>
            </div>

            <!-- EPSS Snapshot Metadata & Leakage Card -->
            <div style="background: var(--bg-muted); border: 1px solid var(--border-subtle); border-left: 3px solid var(--accent-gold); border-radius: var(--radius-sm); padding: 14px 16px; font-size: 12px; line-height: 1.6;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; flex-wrap: wrap; gap: 8px;">
                    <strong style="color: var(--text-primary); font-family: var(--font-mono); font-size: 11px; letter-spacing: 0.04em;">
                        EPSS SNAPSHOT PROVENANCE & LEAKAGE AUDIT
                    </strong>
                    <span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-secondary);">
                        Snapshot: ${escapeHtml(epssMeta.snapshot_date)} · Model: ${escapeHtml(epssMeta.model_version)}
                    </span>
                </div>
                <div style="color: var(--text-secondary);">
                    ${escapeHtml(epssMeta.retrospective_leakage_warning)}
                </div>
            </div>
        </div>

        <!-- 2. Empirical Benchmark Matrix -->
        <div style="margin-bottom: 32px;">
            <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 14px;">
                <h3 style="font-size: 16px; font-weight: 600; color: var(--text-primary); margin: 0;">2. Phase 3 Empirical Benchmark Ledger</h3>
                <span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">HELD-OUT TEST SET EVALUATION</span>
            </div>

            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Experiment</th>
                            <th>Target Variable</th>
                            <th>Prediction Point</th>
                            <th>Primary Metric</th>
                            <th>Linear Baseline</th>
                            <th>Nonlinear Model</th>
                            <th>Improvement / Gain</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${expRowsHtml}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- 3. Temporal Partition Discipline -->
        <div style="margin-bottom: 32px;">
            <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 14px;">
                <h3 style="font-size: 16px; font-weight: 600; color: var(--text-primary); margin: 0;">3. Temporal Partition Discipline</h3>
                <span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">STRICT PUBLICATION-YEAR SPLIT</span>
            </div>

            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 14px; margin-bottom: 14px;">
                <div class="card" style="padding: 16px; margin-bottom: 0;">
                    <div style="font-family: var(--font-mono); font-size: 11px; text-transform: uppercase; color: var(--text-muted); margin-bottom: 4px;">TRAIN PARTITION</div>
                    <div style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 4px;">
                        ${escapeHtml(partitions.train_period)}
                    </div>
                    <div style="font-size: 11px; color: var(--text-secondary);">
                        Model training and feature representation pipeline.
                    </div>
                </div>
                <div class="card" style="padding: 16px; margin-bottom: 0;">
                    <div style="font-family: var(--font-mono); font-size: 11px; text-transform: uppercase; color: var(--text-muted); margin-bottom: 4px;">VALIDATION PARTITION</div>
                    <div style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 4px;">
                        ${escapeHtml(partitions.validation_period)}
                    </div>
                    <div style="font-size: 11px; color: var(--text-secondary);">
                        Hyperparameter tuning and decision threshold selection.
                    </div>
                </div>
                <div class="card" style="padding: 16px; margin-bottom: 0; border-top: 3px solid var(--accent-scarlet);">
                    <div style="font-family: var(--font-mono); font-size: 11px; text-transform: uppercase; color: var(--accent-scarlet); margin-bottom: 4px;">HELD-OUT TEST PARTITION</div>
                    <div style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 4px;">
                        ${escapeHtml(partitions.test_period)}
                    </div>
                    <div style="font-size: 11px; color: var(--text-secondary);">
                        Strictly held-out; untouched during model selection.
                    </div>
                </div>
            </div>

            <div style="font-size: 11px; color: var(--text-muted); line-height: 1.5; border-left: 2px solid var(--border-strong); padding-left: 10px;">
                ${escapeHtml(partitions.partition_discipline)}
            </div>
        </div>

        <!-- 4. Methodological Limitations -->
        <div class="card" style="background: var(--bg-surface); padding: 20px;">
            <h3 style="font-size: 15px; font-weight: 600; color: var(--text-primary); margin-top: 0; margin-bottom: 14px;">
                4. Methodological Limitations & Research Boundaries
            </h3>
            <ul style="padding-left: 18px; margin: 0;">
                ${limitListHtml}
            </ul>
        </div>
    `;
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
