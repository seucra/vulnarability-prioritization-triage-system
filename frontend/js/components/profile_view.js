/**
 * User Profile Component Controller
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { api } from '../api.js';
import { state } from '../state.js';

export function renderProfileView(containerEl) {
    const s = state.getState();
    const user = s.currentUser;

    if (!user) {
        containerEl.innerHTML = `
            <div style="max-width: 440px; margin: 40px auto; text-align: center;">
                <div class="card" style="padding: 28px;">
                    <div style="font-family: var(--font-mono); font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--accent-scarlet); margin-bottom: 6px;">UNAUTHENTICATED</div>
                    <h3 style="font-size: 16px; margin: 0 0 10px 0; color: var(--text-primary);">No Active Session</h3>
                    <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 20px;">You are not currently signed into an active user session.</p>
                    <button class="btn btn-primary" type="button" onclick="window.location.hash='login'">Sign In</button>
                </div>
            </div>
        `;
        return;
    }

    const roleBadgeClass = user.role === 'admin' ? 'badge-scarlet' : user.role === 'analyst' ? 'badge-gold' : 'badge-neutral';
    const roleTitle = user.role === 'admin' ? 'Administrator' : user.role === 'analyst' ? 'Security Analyst' : 'Academic Researcher';

    containerEl.innerHTML = `
        <div class="section-header">
            <div>
                <h2 class="section-title">User Account Profile</h2>
                <p class="section-desc">Authenticated session details, role authorization matrix, and session termination.</p>
            </div>
            <button class="btn btn-secondary btn-sm" id="btn-profile-logout" type="button" style="color: var(--accent-scarlet);">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right: 4px;"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
                Sign Out
            </button>
        </div>

        <div class="workspace-grid" style="grid-template-columns: 1fr 1fr; gap: 24px; align-items: start;">
            <!-- User Identity Card -->
            <div class="card">
                <div class="card-header" style="padding-bottom: 12px; margin-bottom: 18px; border-bottom: 1px solid var(--border-subtle); display: flex; align-items: center; gap: 14px;">
                    <div style="background: var(--surface-dark); color: var(--bg-base); width: 44px; height: 44px; border-radius: var(--radius-sm); display: flex; align-items: center; justify-content: center; font-family: var(--font-mono); font-size: 18px; font-weight: 700;">
                        ${escapeHtml(user.name.charAt(0).toUpperCase())}
                    </div>
                    <div>
                        <h3 class="card-title" style="font-size: 16px; margin: 0;">${escapeHtml(user.name)}</h3>
                        <div style="font-size: 12px; color: var(--text-secondary); margin-top: 2px;">${escapeHtml(user.email)}</div>
                    </div>
                </div>

                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 16px;">
                    <div style="background: var(--bg-muted); padding: 12px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
                        <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em;">Assigned Role</div>
                        <div style="margin-top: 4px;">
                            <span class="badge ${roleBadgeClass}">${roleTitle}</span>
                        </div>
                    </div>
                    <div style="background: var(--bg-muted); padding: 12px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
                        <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em;">Session Status</div>
                        <div style="font-family: var(--font-mono); font-size: 12px; font-weight: 600; color: var(--text-primary); margin-top: 6px;">Active · Authenticated</div>
                    </div>
                </div>

                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                    <div style="background: var(--bg-muted); padding: 12px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
                        <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em;">User ID</div>
                        <div style="font-family: var(--font-mono); font-size: 12px; font-weight: 600; color: var(--text-primary); margin-top: 4px;">#${user.id}</div>
                    </div>
                    <div style="background: var(--bg-muted); padding: 12px; border-radius: var(--radius-sm); border: 1px solid var(--border-subtle);">
                        <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em;">Created Date</div>
                        <div style="font-family: var(--font-mono); font-size: 12px; color: var(--text-secondary); margin-top: 4px;">${new Date(user.created_at).toLocaleDateString()}</div>
                    </div>
                </div>
            </div>

            <!-- Role Permissions Matrix Card -->
            <div class="card">
                <div class="card-header" style="padding-bottom: 12px; margin-bottom: 16px; border-bottom: 1px solid var(--border-subtle);">
                    <h3 class="card-title" style="font-size: 15px; margin: 0;">Role Authorization Scope</h3>
                    <p style="font-size: 12px; color: var(--text-secondary); margin: 2px 0 0 0;">
                        Server-enforced REST API endpoints for: <strong>${roleTitle}</strong>
                    </p>
                </div>

                <div style="display: flex; flex-direction: column; gap: 8px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px 12px; background: var(--bg-muted); border-radius: var(--radius-sm); border: 1px solid var(--border-subtle); font-size: 12px;">
                        <span style="color: var(--text-primary);">Vulnerability Dataset Explorer & Detail Inspection</span>
                        <span class="badge badge-neutral" style="font-size: 10px;">Permitted</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px 12px; background: var(--bg-muted); border-radius: var(--radius-sm); border: 1px solid var(--border-subtle); font-size: 12px;">
                        <span style="color: var(--text-primary);">Pre-Scoring CVSS & KEV Predictions (A1 / B2)</span>
                        <span class="badge badge-neutral" style="font-size: 10px;">Permitted</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px 12px; background: var(--bg-muted); border-radius: var(--radius-sm); border: 1px solid var(--border-subtle); font-size: 12px;">
                        <span style="color: var(--text-primary);">Asset Prioritization Sandbox & Batch Triage Queue</span>
                        <span class="badge ${user.role === 'researcher' ? 'badge-neutral' : 'badge-gold'}" style="font-size: 10px;">
                            ${user.role === 'researcher' ? 'Read-Only' : 'Permitted'}
                        </span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px 12px; background: var(--bg-muted); border-radius: var(--radius-sm); border: 1px solid var(--border-subtle); font-size: 12px;">
                        <span style="color: var(--text-primary);">Local SHAP TreeExplainer Attributions</span>
                        <span class="badge badge-neutral" style="font-size: 10px;">Permitted</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px 12px; background: var(--bg-muted); border-radius: var(--radius-sm); border: 1px solid var(--border-subtle); font-size: 12px;">
                        <span style="color: var(--text-primary);">User & System Administration</span>
                        <span class="badge ${user.role === 'admin' ? 'badge-scarlet' : 'badge-neutral'}" style="font-size: 10px;">
                            ${user.role === 'admin' ? 'Authorized' : 'Restricted'}
                        </span>
                    </div>
                </div>
            </div>
        </div>
    `;

    containerEl.querySelector('#btn-profile-logout').addEventListener('click', () => {
        state.clearAuth();
        window.location.hash = 'landing';
    });
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
