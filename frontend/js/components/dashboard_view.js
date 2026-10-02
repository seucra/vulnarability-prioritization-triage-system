/**
 * Shared System Dashboard Router Shell
 * Purpose: Determines authenticated user role and renders role-specific dashboard component
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { state } from '../state.js';
import { renderAnalystDashboard } from './analyst_dashboard.js';
import { renderResearcherDashboard } from './researcher_dashboard.js';
import { renderAdminDashboard } from './admin_dashboard.js';

export function renderDashboardView(containerEl) {
    const isAuth = state.isAuthenticated();
    const user = state.getState().currentUser;

    if (!isAuth || !user) {
        containerEl.innerHTML = `
            <div style="max-width: 500px; margin: 40px auto; text-align: center;">
                <div class="card" style="padding: 32px;">
                    <div style="font-family: var(--font-mono); font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--accent-gold); margin-bottom: 6px;">
                        ROLE-SPECIFIC WORKSPACE
                    </div>
                    <h3 style="font-size: 18px; font-weight: 700; color: var(--text-primary); margin: 0 0 10px 0;">Authentication Required</h3>
                    <p style="font-size: 13px; color: var(--text-secondary); line-height: 1.6; margin-bottom: 24px;">
                        The dashboard tailors operational triage queues, empirical research benchmarks, and system administration tools based on your authenticated role (Security Analyst, Researcher, or Administrator).
                    </p>
                    <div style="display: flex; gap: 12px; justify-content: center;">
                        <button class="btn btn-primary" type="button" onclick="window.location.hash='login'">
                            Sign In to Access Dashboard
                        </button>
                        <button class="btn btn-secondary" type="button" onclick="window.location.hash='register'">
                            Register Demo Account
                        </button>
                    </div>
                </div>
            </div>
        `;
        return;
    }

    // Role-based routing to specific dashboard components
    if (user.role === 'analyst') {
        renderAnalystDashboard(containerEl);
    } else if (user.role === 'researcher') {
        renderResearcherDashboard(containerEl);
    } else if (user.role === 'admin') {
        renderAdminDashboard(containerEl);
    } else {
        renderAnalystDashboard(containerEl);
    }
}
