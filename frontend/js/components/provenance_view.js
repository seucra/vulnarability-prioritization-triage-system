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
                <p class="section-desc">Academic provenance, canonical dataset freeze manifest, temporal partition discipline, Phase 3 experiment benchmarks, and research limitations.</p>
            </div>
            <button class="btn btn-outline btn-sm" id="btn-refresh-provenance">
                Refresh Provenance
            </button>
        </div>

        <div id="provenance-content-body">
            <div style="padding:40px; text-align:center;">
                <span class="loading-spinner"></span>
                <p style="margin-top:12px; color:var(--text-sub);">Loading research provenance from backend API (/api/v1/provenance)...</p>
            </div>
        </div>
    `;

    const btnRefresh = containerEl.querySelector('#btn-refresh-provenance');
    btnRefresh.addEventListener('click', () => fetchProvenance(containerEl));

    // Fetch initial provenance
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
            <div class="error-banner">
                <strong>Failed to load research provenance:</strong> ${err.message}
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

    const expCardsHtml = experiments.map(exp => `
        <div class="card" style="margin-bottom:16px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                <h4 style="font-size:15px; font-weight:700; color:var(--primary); font-family:var(--font-mono);">${exp.experiment_id}</h4>
                <span class="badge badge-epss">${exp.prediction_point}</span>
            </div>
            <div style="font-size:12px; color:var(--text-sub); margin-bottom:12px;">Target Variable: <strong style="color:var(--text-main);">${exp.target_variable}</strong></div>
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; background:var(--bg-surface-low); padding:10px; border-radius:var(--radius-md); font-size:12px; border:1px solid var(--border-color);">
                <div>
                    <span style="color:var(--text-muted); font-size:11px;">BASELINE (${exp.primary_metric}):</span>
                    <div style="font-family:var(--font-mono); font-weight:600;">${exp.baseline_performance}</div>
                </div>
                <div>
                    <span style="color:var(--text-muted); font-size:11px;">NONLINEAR XGBOOST:</span>
                    <div style="font-family:var(--font-mono); font-weight:700; color:var(--primary);">${exp.nonlinear_performance}</div>
                </div>
            </div>
            <div style="margin-top:8px; font-size:11px; font-weight:600; color:var(--success);">
                ${exp.relative_improvement}
            </div>
        </div>
    `).join('');

    const limitListHtml = limitations.map(lim => `<li style="margin-bottom:6px;">${lim}</li>`).join('');

    containerEl.innerHTML = `
        <!-- Top Metadata Grid -->
        <div class="provenance-grid" style="margin-bottom:24px;">
            <div class="provenance-stat-box">
                <div class="provenance-stat-label">Repository Identity</div>
                <div class="provenance-stat-val" style="font-size:16px;">${data.repository_name}</div>
            </div>
            <div class="provenance-stat-box">
                <div class="provenance-stat-label">Dataset Freeze Date</div>
                <div class="provenance-stat-val">${manifest.freeze_date}</div>
            </div>
            <div class="provenance-stat-box">
                <div class="provenance-stat-label">Total Canonical CVEs</div>
                <div class="provenance-stat-val">${manifest.total_canonical_cves.toLocaleString()}</div>
            </div>
            <div class="provenance-stat-box">
                <div class="provenance-stat-label">CISA KEV Records</div>
                <div class="provenance-stat-val" style="color:var(--error);">${manifest.cisa_kev_cves.toLocaleString()}</div>
            </div>
        </div>

        <!-- EPSS Snapshot Metadata Card -->
        <div class="card" style="border-left:4px solid var(--primary); margin-bottom:24px;">
            <h3 class="card-title">EPSS Snapshot Provenance & Leakage Audit</h3>
            <div style="font-size:13px; color:var(--text-sub); line-height:1.6;">
                <div><strong>Static EPSS Snapshot Date:</strong> ${epssMeta.snapshot_date}</div>
                <div><strong>EPSS Model Version:</strong> ${epssMeta.model_version}</div>
                <div style="margin-top:8px; color:var(--error); font-weight:600;">
                    ${epssMeta.retrospective_leakage_warning}
                </div>
            </div>
        </div>

        <!-- Temporal Partitions Card -->
        <div class="card" style="margin-bottom:24px;">
            <h3 class="card-title">Temporal Partitions (Zero Cross-Year Shuffling)</h3>
            <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:16px; font-size:12px; margin-bottom:12px;">
                <div style="background:var(--bg-surface-low); padding:12px; border-radius:var(--radius-md); border:1px solid var(--border-color);">
                    <strong style="color:var(--text-main);">TRAIN Partition</strong>
                    <div>${partitions.train_period}</div>
                </div>
                <div style="background:var(--bg-surface-low); padding:12px; border-radius:var(--radius-md); border:1px solid var(--border-color);">
                    <strong style="color:var(--text-main);">VALIDATION Partition</strong>
                    <div>${partitions.validation_period}</div>
                </div>
                <div style="background:var(--bg-surface-low); padding:12px; border-radius:var(--radius-md); border:1px solid var(--border-color);">
                    <strong style="color:var(--primary);">TEST Partition (Untouched)</strong>
                    <div>${partitions.test_period}</div>
                </div>
            </div>
            <div style="font-size:11px; color:var(--text-muted); font-style:italic;">
                ${partitions.partition_discipline}
            </div>
        </div>

        <!-- Phase 3 Experiment Benchmarks -->
        <div style="margin-bottom:24px;">
            <h3 class="section-title" style="font-size:16px; margin-bottom:12px;">Phase 3 Research Experiment Benchmarks</h3>
            ${expCardsHtml}
        </div>

        <!-- Research Limitations Card -->
        <div class="card" style="background-color: var(--bg-surface-low);">
            <h3 class="card-title">Methodological & Academic Limitations</h3>
            <ul style="padding-left:20px; font-size:13px; color:var(--text-sub); line-height:1.6;">
                ${limitListHtml}
            </ul>
        </div>
    `;
}
