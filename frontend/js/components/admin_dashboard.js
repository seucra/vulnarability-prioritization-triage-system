/**
 * Administrator Role Dashboard Component
 * Purpose: Application/System Administration, User Account Management, & Health Monitoring
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { api } from '../api.js';
import { state } from '../state.js';

export function renderAdminDashboard(containerEl) {
    containerEl.innerHTML = `
        <div class="section-header">
            <div>
                <h2 class="section-title">System & Demonstration Administrator Dashboard</h2>
                <p class="section-desc">User account overview, role distribution, system availability monitoring, and administrative controls.</p>
            </div>
            <span class="badge badge-scarlet" style="font-size: 11px;">Role: Administrator</span>
        </div>

        <div id="admin-dash-status-container"></div>

        <!-- User Accounts & Role Distribution KPIs -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 14px; margin-bottom: 24px;">
            <div class="card" style="padding: 14px 16px; margin-bottom: 0;">
                <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em;">Total Accounts</div>
                <div style="font-family: var(--font-mono); font-size: 22px; font-weight: 700; color: var(--text-primary); margin-top: 4px;" id="admin-dash-stat-total">1</div>
                <div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px;">Demonstration Users</div>
            </div>

            <div class="card" style="padding: 14px 16px; margin-bottom: 0;">
                <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em;">Active Sessions</div>
                <div style="font-family: var(--font-mono); font-size: 22px; font-weight: 700; color: var(--text-primary); margin-top: 4px;" id="admin-dash-stat-active">1</div>
                <div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px;">Authenticated Permitted</div>
            </div>

            <div class="card" style="padding: 14px 16px; margin-bottom: 0;">
                <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em;">Disabled Accounts</div>
                <div style="font-family: var(--font-mono); font-size: 22px; font-weight: 700; color: var(--text-primary); margin-top: 4px;" id="admin-dash-stat-disabled">0</div>
                <div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px;">Restricted Access</div>
            </div>

            <div class="card" style="padding: 14px 16px; margin-bottom: 0;">
                <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.04em;">Access Control</div>
                <div style="font-family: var(--font-mono); font-size: 16px; font-weight: 700; color: var(--text-primary); margin-top: 8px;">Role-Based (RBAC)</div>
                <div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px;">Analyst / Researcher / Admin</div>
            </div>
        </div>

        <!-- Administrator Quick Actions -->
        <div style="margin-bottom: 24px;">
            <div style="font-family: var(--font-mono); font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-muted); margin-bottom: 12px;">
                ADMINISTRATIVE WORKFLOWS
            </div>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px;">
                <div class="card" style="margin-bottom: 0; cursor: pointer; padding: 16px; transition: all var(--transition-fast);" onclick="window.location.hash='admin'">
                    <div style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 4px;">1. User Administration &rarr;</div>
                    <div style="font-size: 12px; color: var(--text-secondary); line-height: 1.5;">Review user accounts, assign roles, and toggle session permissions.</div>
                </div>

                <div class="card" style="margin-bottom: 0; cursor: pointer; padding: 16px; transition: all var(--transition-fast);" onclick="window.location.hash='provenance'">
                    <div style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 4px;">2. Dataset Manifest &rarr;</div>
                    <div style="font-size: 12px; color: var(--text-secondary); line-height: 1.5;">Inspect canonical freeze records, partition boundaries, and leakage audit.</div>
                </div>

                <div class="card" style="margin-bottom: 0; cursor: pointer; padding: 16px; transition: all var(--transition-fast);" onclick="window.location.hash='docs'">
                    <div style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 4px;">3. Documentation Specs &rarr;</div>
                    <div style="font-size: 12px; color: var(--text-secondary); line-height: 1.5;">Access REST API specifications and architecture reference manuals.</div>
                </div>

                <div class="card" style="margin-bottom: 0; cursor: pointer; padding: 16px; transition: all var(--transition-fast);" onclick="window.location.hash='profile'">
                    <div style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 4px;">4. Admin Profile &rarr;</div>
                    <div style="font-size: 12px; color: var(--text-secondary); line-height: 1.5;">Inspect active session claims and role authorization scope.</div>
                </div>
            </div>
        </div>

        <div class="workspace-grid" style="grid-template-columns: 1fr 1fr; gap: 24px; align-items: start;">
            <!-- System Engine & Service Availability -->
            <div class="card">
                <div class="card-header" style="padding-bottom: 12px; margin-bottom: 16px; border-bottom: 1px solid var(--border-subtle);">
                    <h3 class="card-title" style="font-size: 15px; margin: 0;">Service & Engine Availability</h3>
                </div>
                <div style="display: flex; flex-direction: column; gap: 8px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px 12px; background: var(--bg-muted); border-radius: var(--radius-sm); border: 1px solid var(--border-subtle); font-size: 12px;">
                        <span style="color: var(--text-primary);">FastAPI REST Server (Uvicorn)</span>
                        <span class="badge badge-success" style="font-size: 10px;">Online / Healthy</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px 12px; background: var(--bg-muted); border-radius: var(--radius-sm); border: 1px solid var(--border-subtle); font-size: 12px;">
                        <span style="color: var(--text-primary);">DuckDB Analytical Engine (366,547 CVEs)</span>
                        <span class="badge badge-neutral" style="font-size: 10px;">Read-Only Active</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px 12px; background: var(--bg-muted); border-radius: var(--radius-sm); border: 1px solid var(--border-subtle); font-size: 12px;">
                        <span style="color: var(--text-primary);">Serialized Models (EXP-A1 / B2 XGBoost)</span>
                        <span class="badge badge-neutral" style="font-size: 10px;">Loaded in Memory</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px 12px; background: var(--bg-muted); border-radius: var(--radius-sm); border: 1px solid var(--border-subtle); font-size: 12px;">
                        <span style="color: var(--text-primary);">SQLite Account Store (auth_users.sqlite)</span>
                        <span class="badge badge-neutral" style="font-size: 10px;">Connected</span>
                    </div>
                </div>
            </div>

            <!-- Quick User Directory Summary -->
            <div class="card">
                <div class="card-header" style="padding-bottom: 12px; margin-bottom: 16px; border-bottom: 1px solid var(--border-subtle); display: flex; justify-content: space-between; align-items: center;">
                    <h3 class="card-title" style="font-size: 15px; margin: 0;">Account Directory Overview</h3>
                    <button class="btn btn-secondary btn-sm" onclick="window.location.hash='admin'">Manage All</button>
                </div>
                <div class="table-container">
                    <table class="data-table">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Email</th>
                                <th>Role</th>
                                <th style="text-align: right;">Status</th>
                            </tr>
                        </thead>
                        <tbody id="admin-dash-users-table">
                            <tr><td colspan="4" style="text-align: center; color: var(--text-secondary); padding: 24px;">Querying user directory...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    `;

    loadAdminDashboardData(containerEl);
}

async function loadAdminDashboardData(containerEl) {
    const tbody = containerEl.querySelector('#admin-dash-users-table');
    try {
        const users = await api.listUsers();
        if (users && users.length > 0) {
            const activeCount = users.filter(u => u.is_active).length;
            const disabledCount = users.length - activeCount;

            const elTotal = containerEl.querySelector('#admin-dash-stat-total');
            const elActive = containerEl.querySelector('#admin-dash-stat-active');
            const elDisabled = containerEl.querySelector('#admin-dash-stat-disabled');

            if (elTotal) elTotal.textContent = users.length;
            if (elActive) elActive.textContent = activeCount;
            if (elDisabled) elDisabled.textContent = disabledCount;

            if (tbody) {
                tbody.innerHTML = users.slice(0, 4).map(u => {
                    const roleBadgeClass = u.role === 'admin' ? 'badge-scarlet' : u.role === 'analyst' ? 'badge-gold' : 'badge-neutral';
                    return `
                        <tr>
                            <td style="font-size: 12px; font-weight: 500; color: var(--text-primary);">${escapeHtml(u.name)}</td>
                            <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-secondary);">${escapeHtml(u.email)}</td>
                            <td><span class="badge ${roleBadgeClass}" style="font-size: 10px;">${escapeHtml(u.role)}</span></td>
                            <td style="text-align: right;"><span class="badge ${u.is_active ? 'badge-success' : 'badge-neutral'}" style="font-size: 10px;">${u.is_active ? 'Active' : 'Disabled'}</span></td>
                        </tr>
                    `;
                }).join('');
            }
        }
    } catch (e) {
        if (tbody) {
            tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 16px;">Unable to load account directory.</td></tr>`;
        }
    }
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
