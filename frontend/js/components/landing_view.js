/**
 * Public Landing Page Component Controller
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { state } from '../state.js';

export function renderLandingView(containerEl) {
    containerEl.innerHTML = `
        <!-- Hero Section -->
        <div class="card hero-card" style="background: linear-gradient(135deg, #ffffff 0%, var(--bg-surface-low) 100%); padding: 36px; margin-bottom: 24px; border-left: 6px solid var(--primary);">
            <div style="max-width: 900px;">
                <div class="repo-badge" style="display: inline-block; margin-bottom: 12px; font-weight: 600; color: var(--primary);">
                    Academic Research Prototype • seucra/vulnarability-prioritization-triage-system
                </div>
                <h1 style="font-size: 32px; font-weight: 700; color: var(--text-main); margin-bottom: 12px; letter-spacing: -0.02em;">
                    Vulnerability Prioritization & Triage System
                </h1>
                <p style="font-size: 16px; color: var(--text-sub); line-height: 1.6; margin-bottom: 24px;">
                    An explainable risk-based vulnerability triage platform integrating CVSS severity, static EPSS exploitation likelihood, CISA Known Exploited Vulnerabilities (KEV) signals, and controlled asset criticality signals.
                </p>
                <div style="display: flex; gap: 12px; align-items: center; flex-wrap: wrap;">
                    <button class="btn btn-primary" id="hero-btn-launch" style="padding: 12px 24px; font-size: 14px;">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                        Launch System Dashboard
                    </button>
                    <button class="btn btn-outline" id="hero-btn-explorer" style="padding: 12px 20px; font-size: 14px;">
                        Explore Vulnerability Dataset (366k CVEs)
                    </button>
                    <button class="btn btn-secondary" id="hero-btn-about" style="padding: 12px 20px; font-size: 14px;">
                        View Research Basis
                    </button>
                </div>
            </div>
        </div>

        <!-- Problem Statement & Research Motivation Grid -->
        <div class="workspace-grid" style="margin-bottom: 24px;">
            <div class="card">
                <h3 class="card-title" style="color: var(--error);">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 6px;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                    The Vulnerability Triage Dilemma
                </h3>
                <p style="font-size: 13px; color: var(--text-sub); line-height: 1.6; margin-bottom: 12px;">
                    Enterprise security teams face tens of thousands of disclosed CVEs annually, far exceeding available remediation bandwidth. 
                    Relying strictly on <strong>NVD CVSS Base Scores</strong> produces severe triage friction: over 60% of vulnerabilities are categorized as High or Critical, yet less than 4% are ever actively exploited in the wild.
                </p>
                <p style="font-size: 13px; color: var(--text-sub); line-height: 1.6;">
                    Furthermore, standard CVSS scores are often delayed by days or weeks post-disclosure, leaving security analysts without immediate risk indicators during initial triage windows.
                </p>
            </div>

            <div class="card">
                <h3 class="card-title" style="color: var(--primary);">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 6px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    Research Objective & Approach
                </h3>
                <p style="font-size: 13px; color: var(--text-sub); line-height: 1.6; margin-bottom: 12px;">
                    This research investigates a hybrid decision-support architecture that unifies public threat intelligence signals (CVSS, EPSS snapshot scores, CISA KEV catalog presence) with controlled asset criticality tiers ($A \\in \\{0.25, 0.50, 0.75, 1.00\\}$).
                </p>
                <p style="font-size: 13px; color: var(--text-sub); line-height: 1.6;">
                    The system evaluates pre-scoring CVSS estimation (EXP-A1), publication-time KEV prediction (EXP-B2), transparent SHAP TreeExplainer attributions, and dual-mode prioritization surface comparisons ($S_{\\text{linear}}$ vs $S_{\\text{nonlinear}}$).
                </p>
            </div>
        </div>

        <!-- Data Classification Discipline Banner -->
        <div class="card" style="border-left: 4px solid var(--primary); background-color: var(--bg-surface-low); margin-bottom: 24px; padding: 16px 20px;">
            <h4 style="font-size: 14px; font-weight: 600; color: var(--text-main); margin-bottom: 8px;">
                Data Signal Classification Discipline
            </h4>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; font-size: 12px;">
                <div style="background: var(--bg-surface); padding: 12px; border-radius: var(--radius-md); border: 1px solid var(--border-color);">
                    <strong style="color: var(--primary);">1. Authoritative Vulnerability Data</strong>
                    <div style="color: var(--text-sub); margin-top: 4px;">Official NVD CVSS v2/v3/v4 scores, vector strings, CWE taxonomy classifications, CPE applicability nodes, vendor statements, and CISA KEV catalog membership dates.</div>
                </div>
                <div style="background: var(--bg-surface); padding: 12px; border-radius: var(--radius-md); border: 1px solid var(--border-color);">
                    <strong style="color: var(--tertiary);">2. Machine Learning Predictions</strong>
                    <div style="color: var(--text-sub); margin-top: 4px;">Pre-scoring CVSS v3.1 estimation (EXP-A1 XGBoost Regressor) and publication-time CISA KEV catalog inclusion probability (EXP-B2 XGBoost Classifier).</div>
                </div>
                <div style="background: var(--bg-surface); padding: 12px; border-radius: var(--radius-md); border: 1px solid var(--border-color);">
                    <strong style="color: var(--success);">3. Decision-Support Prioritization</strong>
                    <div style="color: var(--text-sub); margin-top: 4px;">Transparent Mode 1 Linear baseline ($S_{\\text{linear}}$) and Mode 2 Nonlinear interactive risk surfaces ($S_{\\text{nonlinear}}$) scaled across controlled Asset Criticality Tiers 1–4.</div>
                </div>
            </div>
        </div>

        <!-- Core System Capabilities Grid -->
        <h3 class="section-title" style="font-size: 18px; margin-bottom: 16px;">Core Research Capabilities</h3>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; margin-bottom: 24px;">
            <div class="card" style="margin-bottom: 0;">
                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px;">
                    <div style="background: var(--bg-surface-container); padding: 8px; border-radius: var(--radius-md); color: var(--primary);">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                    </div>
                    <h4 style="font-size: 15px; font-weight: 600;">Canonical Dataset Triage Explorer</h4>
                </div>
                <p style="font-size: 12px; color: var(--text-sub); line-height: 1.5; margin-bottom: 12px;">
                    Search and filter 366,547 canonical NVD CVE records with real-time multi-parameter queries (CWE, CPE vendor/product, CVSS score bounds, KEV status, EPSS score range, publication year).
                </p>
                <button class="btn btn-outline btn-sm card-nav-btn" data-target="explorer">Launch Explorer &rarr;</button>
            </div>

            <div class="card" style="margin-bottom: 0;">
                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px;">
                    <div style="background: var(--bg-surface-container); padding: 8px; border-radius: var(--radius-md); color: var(--primary);">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                    </div>
                    <h4 style="font-size: 15px; font-weight: 600;">Predictive ML Workspaces (A1 & B2)</h4>
                </div>
                <p style="font-size: 12px; color: var(--text-sub); line-height: 1.5; margin-bottom: 12px;">
                    Evaluate pre-scoring CVSS estimation before official NVD publication, and predict publication-time KEV exploitation likelihood under strict temporal feature boundary rules.
                </p>
                <button class="btn btn-outline btn-sm card-nav-btn" data-target="predict">Run Predictions &rarr;</button>
            </div>

            <div class="card" style="margin-bottom: 0;">
                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px;">
                    <div style="background: var(--bg-surface-container); padding: 8px; border-radius: var(--radius-md); color: var(--primary);">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
                    </div>
                    <h4 style="font-size: 15px; font-weight: 600;">Dual-Mode Prioritization Sandbox</h4>
                </div>
                <p style="font-size: 12px; color: var(--text-sub); line-height: 1.5; margin-bottom: 12px;">
                    Compare project-controlled linear baseline scores ($S_{\\text{linear}}$) against nonlinear interactive risk surfaces ($S_{\\text{nonlinear}}$) across controlled Asset Criticality Tiers (0.25 to 1.00).
                </p>
                <button class="btn btn-outline btn-sm card-nav-btn" data-target="prioritize">Open Prioritization Sandbox &rarr;</button>
            </div>

            <div class="card" style="margin-bottom: 0;">
                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px;">
                    <div style="background: var(--bg-surface-container); padding: 8px; border-radius: var(--radius-md); color: var(--primary);">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
                    </div>
                    <h4 style="font-size: 15px; font-weight: 600;">SHAP Model Explainability</h4>
                </div>
                <p style="font-size: 12px; color: var(--text-sub); line-height: 1.5; margin-bottom: 12px;">
                    Inspect local TreeExplainer feature attributions for EXP-A1 and EXP-B2 predictions to understand exact textual and metadata signal contributions with causal disclaimers.
                </p>
                <button class="btn btn-outline btn-sm card-nav-btn" data-target="explain">Inspect SHAP Values &rarr;</button>
            </div>

            <div class="card" style="margin-bottom: 0;">
                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px;">
                    <div style="background: var(--bg-surface-container); padding: 8px; border-radius: var(--radius-md); color: var(--primary);">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                    </div>
                    <h4 style="font-size: 15px; font-weight: 600;">Academic Research Provenance</h4>
                </div>
                <p style="font-size: 12px; color: var(--text-sub); line-height: 1.5; margin-bottom: 12px;">
                    Review canonical dataset freeze manifests (2026-07-26), strict temporal partition discipline (Train 2002–22, Val 2023–24, Test 2025–26), and experiment benchmarks.
                </p>
                <button class="btn btn-outline btn-sm card-nav-btn" data-target="provenance">View Research Manifest &rarr;</button>
            </div>

            <div class="card" style="margin-bottom: 0;">
                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px;">
                    <div style="background: var(--bg-surface-container); padding: 8px; border-radius: var(--radius-md); color: var(--primary);">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>
                    </div>
                    <h4 style="font-size: 15px; font-weight: 600;">Integrated Documentation</h4>
                </div>
                <p style="font-size: 12px; color: var(--text-sub); line-height: 1.5; margin-bottom: 12px;">
                    Access system architecture documents, API endpoint specifications, research phase logs, dataset schema manifests, and system requirements.
                </p>
                <button class="btn btn-outline btn-sm card-nav-btn" data-target="docs">Open Documentation &rarr;</button>
            </div>
        </div>

        <!-- Technology Stack Summary Footer -->
        <div class="card" style="background-color: var(--bg-surface-low); padding: 20px; font-size: 12px;">
            <div style="font-weight: 600; color: var(--text-main); margin-bottom: 8px;">System Technology Stack</div>
            <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                <span class="repo-badge">Python 3.14</span>
                <span class="repo-badge">FastAPI</span>
                <span class="repo-badge">DuckDB</span>
                <span class="repo-badge">Apache Parquet</span>
                <span class="repo-badge">XGBoost</span>
                <span class="repo-badge">SHAP TreeExplainer</span>
                <span class="repo-badge">Vanilla JS (ES Modules)</span>
                <span class="repo-badge">Vanilla CSS Tokens</span>
                <span class="repo-badge">Pydantic v2</span>
            </div>
        </div>
    `;

    // Button event handlers
    const btnLaunch = containerEl.querySelector('#hero-btn-launch');
    const btnExplorer = containerEl.querySelector('#hero-btn-explorer');
    const btnAbout = containerEl.querySelector('#hero-btn-about');

    if (btnLaunch) {
        btnLaunch.addEventListener('click', () => {
            window.location.hash = 'dashboard';
        });
    }

    if (btnExplorer) {
        btnExplorer.addEventListener('click', () => {
            window.location.hash = 'explorer';
        });
    }

    if (btnAbout) {
        btnAbout.addEventListener('click', () => {
            window.location.hash = 'about';
        });
    }

    containerEl.querySelectorAll('.card-nav-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const target = btn.getAttribute('data-target');
            if (target) {
                window.location.hash = target;
            }
        });
    });
}
