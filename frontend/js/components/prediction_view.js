/**
 * Predictive Analysis Workspace Component Controller (EXP-A1 & EXP-B2)
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { api } from '../api.js';
import { state } from '../state.js';

export function renderPredictionView(containerEl) {
    containerEl.innerHTML = `
        <div class="section-header">
            <div>
                <h2 class="section-title">Predictive Machine Learning Workspace</h2>
                <p class="section-desc">Inference workspace for frozen temporal models: pre-scoring CVSS estimation prior to NVD analyst review (EXP-A1) and publication-time CISA KEV exploitation classification (EXP-B2).</p>
            </div>
            <div class="segmented-control" id="pred-mode-toggle" style="align-self: flex-start;">
                <button class="segmented-item active" id="tab-pred-cvss" type="button">EXP-A1 · CVSS Regression</button>
                <button class="segmented-item" id="tab-pred-kev" type="button">EXP-B2 · KEV Risk Classification</button>
            </div>
        </div>

        <div class="workspace-grid" style="grid-template-columns: 1.1fr 0.9fr; gap: 24px; align-items: start;">
            <!-- Input Form Card -->
            <div class="card">
                <div class="card-header" style="padding-bottom: 12px; margin-bottom: 18px; border-bottom: 1px solid var(--border-subtle);">
                    <div>
                        <h3 class="card-title" id="pred-form-title" style="font-size: 15px;">EXP-A1 Pre-Scoring CVSS Estimation</h3>
                        <p id="pred-form-subtitle" style="font-size: 12px; color: var(--text-secondary); margin-top: 2px;">
                            Estimates CVSS v3.1 base score from raw disclosure text and initial structural metadata.
                        </p>
                    </div>
                </div>
                
                <div class="form-group" style="margin-bottom: 16px;">
                    <label class="form-label" for="pred-description">Vulnerability Description Text <span style="color: var(--accent-scarlet);">*</span></label>
                    <textarea id="pred-description" class="form-textarea" rows="4" placeholder="Enter vulnerability disclosure description text (minimum 10 characters)...">An unauthenticated remote code execution vulnerability in Apache Log4j2 JNDI feature allows full system takeover.</textarea>
                    <span class="form-hint">Provide primary technical description available at publication time.</span>
                </div>

                <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 12px; margin-bottom: 16px;">
                    <div class="form-group">
                        <label class="form-label" for="pred-cwes">CWE Weaknesses</label>
                        <input type="text" id="pred-cwes" class="form-input" value="CWE-502, CWE-400" placeholder="e.g. CWE-502, CWE-400">
                        <span class="form-hint">Comma-separated identifiers.</span>
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="pred-month">Pub Month</label>
                        <input type="number" id="pred-month" class="form-input" min="1" max="12" value="12">
                        <span class="form-hint">1–12 calendar month.</span>
                    </div>
                </div>

                <!-- Progressive Disclosure for Structural & Stack Features -->
                <details class="disclosure" style="margin-bottom: 20px;">
                    <summary class="disclosure-summary">
                        <span>Structural & Software Stack Features (Optional)</span>
                    </summary>
                    <div style="padding-top: 14px;">
                        <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; margin-bottom: 14px;">
                            <div class="form-group">
                                <label class="form-label" for="pred-cpe-count">Total CPEs</label>
                                <input type="number" id="pred-cpe-count" class="form-input" min="0" value="5">
                            </div>
                            <div class="form-group">
                                <label class="form-label" for="pred-cpe-a">App CPEs (a)</label>
                                <input type="number" id="pred-cpe-a" class="form-input" min="0" value="5">
                            </div>
                            <div class="form-group">
                                <label class="form-label" for="pred-cpe-o">OS CPEs (o)</label>
                                <input type="number" id="pred-cpe-o" class="form-input" min="0" value="0">
                            </div>
                        </div>

                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                            <div class="form-group">
                                <label class="form-label" for="pred-vendor-count">Unique Vendors</label>
                                <input type="number" id="pred-vendor-count" class="form-input" min="0" value="1">
                            </div>
                            <div class="form-group">
                                <label class="form-label" for="pred-product-count">Unique Products</label>
                                <input type="number" id="pred-product-count" class="form-input" min="0" value="1">
                            </div>
                        </div>
                    </div>
                </details>

                <!-- Publication-Time Feature Boundary Notice for EXP-B2 -->
                <div id="b2-boundary-warning-box" style="display: none; background: var(--bg-muted); border: 1px solid var(--border-subtle); border-left: 3px solid var(--accent-scarlet); padding: 12px 14px; border-radius: var(--radius-sm); margin-bottom: 20px; font-size: 12px; color: var(--text-secondary); line-height: 1.5;">
                    <strong style="color: var(--text-primary); font-family: var(--font-mono); font-size: 11px; letter-spacing: 0.04em;">TEMPORAL BOUNDARY DISCIPLINE:</strong>
                    Post-disclosure features (retrospective EPSS snapshots and authoritative CVSS base vectors) are strictly prohibited in the EXP-B2 publication-time pipeline to maintain valid non-leaking evaluation.
                </div>

                <button class="btn btn-primary" id="btn-run-prediction" type="button" style="width: 100%; justify-content: center; height: 38px;">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 6px;"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                    Run Model Inference
                </button>
            </div>

            <!-- Results Card -->
            <div>
                <div class="card" id="prediction-result-card">
                    <div class="card-header" style="padding-bottom: 12px; margin-bottom: 18px; border-bottom: 1px solid var(--border-subtle);">
                        <h3 class="card-title" style="font-size: 15px;">Inference Result</h3>
                    </div>
                    <div id="prediction-output-body">
                        <div class="empty-state" style="padding: 48px 24px;">
                            <div style="font-family: var(--font-mono); font-size: 12px; color: var(--text-muted); margin-bottom: 8px;">AWAITING INPUT</div>
                            <p style="margin: 0; font-size: 13px; color: var(--text-secondary); max-width: 320px; margin-left: auto; margin-right: auto;">
                                Configure disclosure description and parameters, then execute inference to evaluate frozen Phase 3 models.
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;

    const tabCvss = containerEl.querySelector('#tab-pred-cvss');
    const tabKev = containerEl.querySelector('#tab-pred-kev');
    const formTitle = containerEl.querySelector('#pred-form-title');
    const formSubtitle = containerEl.querySelector('#pred-form-subtitle');
    const boundaryBox = containerEl.querySelector('#b2-boundary-warning-box');
    const btnRun = containerEl.querySelector('#btn-run-prediction');

    let currentMode = 'cvss'; // 'cvss' | 'kev'

    tabCvss.addEventListener('click', () => {
        currentMode = 'cvss';
        tabCvss.classList.add('active');
        tabKev.classList.remove('active');
        formTitle.textContent = 'EXP-A1 Pre-Scoring CVSS Estimation';
        formSubtitle.textContent = 'Estimates CVSS v3.1 base score from raw disclosure text and initial structural metadata.';
        boundaryBox.style.display = 'none';
    });

    tabKev.addEventListener('click', () => {
        currentMode = 'kev';
        tabKev.classList.add('active');
        tabCvss.classList.remove('active');
        formTitle.textContent = 'EXP-B2 Publication-Time KEV Risk Prediction';
        formSubtitle.textContent = 'Classifies probability of future inclusion in CISA KEV catalog under strict temporal isolation.';
        boundaryBox.style.display = 'block';
    });

    btnRun.addEventListener('click', async () => {
        const desc = containerEl.querySelector('#pred-description').value.trim();
        if (desc.length < 10) {
            alert('Vulnerability description must be at least 10 characters.');
            return;
        }

        const cwesRaw = containerEl.querySelector('#pred-cwes').value;
        const cweIds = cwesRaw.split(',').map(s => s.trim()).filter(Boolean);
        
        const payload = {
            description_en: desc,
            cwe_ids: cweIds,
            pub_month: parseInt(containerEl.querySelector('#pred-month').value, 10) || 1,
            cpe_count: parseInt(containerEl.querySelector('#pred-cpe-count').value, 10) || 0,
            cpe_part_a_count: parseInt(containerEl.querySelector('#pred-cpe-a').value, 10) || 0,
            cpe_part_o_count: parseInt(containerEl.querySelector('#pred-cpe-o').value, 10) || 0,
            cpe_part_h_count: 0,
            vendor_count: parseInt(containerEl.querySelector('#pred-vendor-count').value, 10) || 0,
            product_count: parseInt(containerEl.querySelector('#pred-product-count').value, 10) || 0,
        };

        const outputBody = containerEl.querySelector('#prediction-output-body');
        outputBody.innerHTML = `
            <div style="padding: 48px 24px; text-align: center;">
                <span class="loading-spinner"></span>
                <p style="margin-top: 14px; font-size: 13px; color: var(--text-secondary);">Executing frozen ${currentMode.toUpperCase()} inference pipeline...</p>
            </div>
        `;

        try {
            if (currentMode === 'cvss') {
                const res = await api.predictCVSS(payload);
                renderCvssResult(outputBody, res);
            } else {
                const res = await api.predictKEV(payload);
                renderKevResult(outputBody, res);
            }
        } catch (err) {
            outputBody.innerHTML = `
                <div style="background: var(--bg-muted); border: 1px solid var(--accent-scarlet); border-radius: var(--radius-sm); padding: 16px;">
                    <div style="font-family: var(--font-mono); font-size: 12px; font-weight: 600; color: var(--accent-scarlet);">
                        INFERENCE ERROR (${err.status || 500})
                    </div>
                    <div style="margin-top: 6px; font-size: 13px; color: var(--text-primary); line-height: 1.5;">
                        ${escapeHtml(err.message)}
                    </div>
                </div>
            `;
        }
    });
}

function renderCvssResult(containerEl, res) {
    const scoreVal = res.predicted_cvss_v31_base_score !== undefined ? res.predicted_cvss_v31_base_score.toFixed(2) : '—';
    const authoritative = res.authoritative_cvss_v31_base_score !== undefined && res.authoritative_cvss_v31_base_score !== null;

    containerEl.innerHTML = `
        <div style="margin-bottom: 20px; padding: 20px; background: var(--bg-muted); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); text-align: center;">
            <div style="font-family: var(--font-mono); font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-secondary); margin-bottom: 6px;">
                ${escapeHtml(res.prediction_label || 'Estimated CVSS v3.1 Base Score')}
            </div>
            <div style="font-family: var(--font-mono); font-size: 48px; font-weight: 700; color: var(--text-primary); line-height: 1;">
                ${scoreVal}
            </div>
            <div style="margin-top: 8px; font-size: 12px; color: var(--text-muted);">
                Scale 0.0 – 10.0 · Pre-scoring evaluation
            </div>
        </div>

        <div style="border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); overflow: hidden; margin-bottom: 16px;">
            <div style="display: grid; grid-template-columns: 1fr 1fr; border-bottom: 1px solid var(--border-subtle);">
                <div style="padding: 10px 14px; background: var(--bg-surface); border-right: 1px solid var(--border-subtle);">
                    <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em;">Model Architecture</div>
                    <div style="font-family: var(--font-mono); font-size: 13px; font-weight: 600; color: var(--text-primary); margin-top: 2px;">${escapeHtml(res.model_name)}</div>
                </div>
                <div style="padding: 10px 14px; background: var(--bg-surface);">
                    <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em;">Test Benchmark MAE</div>
                    <div style="font-family: var(--font-mono); font-size: 13px; font-weight: 600; color: var(--text-primary); margin-top: 2px;">${res.mae_test_benchmark} pts</div>
                </div>
            </div>
            ${authoritative ? `
                <div style="padding: 10px 14px; background: var(--bg-elevated); display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-size: 12px; color: var(--text-secondary);">Authoritative NVD Analyst Score</span>
                    <span style="font-family: var(--font-mono); font-size: 14px; font-weight: 700; color: var(--accent-scarlet);">${res.authoritative_cvss_v31_base_score.toFixed(1)}</span>
                </div>
            ` : ''}
        </div>

        <div style="font-size: 11px; color: var(--text-muted); line-height: 1.5; border-left: 2px solid var(--border-strong); padding-left: 10px;">
            ${escapeHtml(res.disclaimer || 'Model prediction generated by frozen Phase 3 EXP-A1 pipeline for research estimation.')}
        </div>
    `;
}

function renderKevResult(containerEl, res) {
    let riskBadgeClass = 'badge-neutral';
    if (res.risk_classification === 'HIGH_RISK') riskBadgeClass = 'badge-scarlet';
    else if (res.risk_classification === 'ELEVATED_RISK') riskBadgeClass = 'badge-gold';

    const pct = (res.predicted_kev_probability * 100).toFixed(2);

    containerEl.innerHTML = `
        <div style="margin-bottom: 20px; padding: 20px; background: var(--bg-muted); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); text-align: center;">
            <div style="font-family: var(--font-mono); font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-secondary); margin-bottom: 6px;">
                Predicted KEV Inclusion Probability
            </div>
            <div style="display: flex; align-items: center; justify-content: center; gap: 14px; margin-top: 4px;">
                <div style="font-family: var(--font-mono); font-size: 44px; font-weight: 700; color: var(--text-primary); line-height: 1;">
                    ${pct}%
                </div>
                <span class="badge ${riskBadgeClass}">${escapeHtml(res.risk_classification)}</span>
            </div>
            <div style="margin-top: 8px; font-size: 12px; color: var(--text-muted);">
                Phase 3 publication-time temporal classifier
            </div>
        </div>

        <div style="border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); overflow: hidden; margin-bottom: 16px;">
            <div style="display: grid; grid-template-columns: 1fr 1fr; border-bottom: 1px solid var(--border-subtle);">
                <div style="padding: 10px 14px; background: var(--bg-surface); border-right: 1px solid var(--border-subtle);">
                    <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em;">Prediction Horizon</div>
                    <div style="font-size: 12px; font-weight: 500; color: var(--text-primary); margin-top: 2px;">${escapeHtml(res.prediction_point)}</div>
                </div>
                <div style="padding: 10px 14px; background: var(--bg-surface);">
                    <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em;">Model Architecture</div>
                    <div style="font-family: var(--font-mono); font-size: 12px; font-weight: 600; color: var(--text-primary); margin-top: 2px;">${escapeHtml(res.model_name)}</div>
                </div>
            </div>
            <div style="display: grid; grid-template-columns: 1fr 1fr;">
                <div style="padding: 10px 14px; background: var(--bg-surface); border-right: 1px solid var(--border-subtle);">
                    <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em;">Benchmark PR-AUC</div>
                    <div style="font-family: var(--font-mono); font-size: 13px; font-weight: 600; color: var(--text-primary); margin-top: 2px;">${res.pr_auc_test_benchmark}</div>
                </div>
                <div style="padding: 10px 14px; background: var(--bg-surface);">
                    <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em;">Uplift vs Random</div>
                    <div style="font-family: var(--font-mono); font-size: 13px; font-weight: 600; color: var(--accent-scarlet); margin-top: 2px;">${escapeHtml(res.uplift_vs_random)}</div>
                </div>
            </div>
        </div>

        <div style="font-size: 11px; color: var(--text-muted); line-height: 1.5; border-left: 2px solid var(--border-strong); padding-left: 10px;">
            Target Definition: ${escapeHtml(res.target_definition)}. Post-publication EPSS scores and CVSS vectors are strictly excluded at publication time.
        </div>
    `;
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
