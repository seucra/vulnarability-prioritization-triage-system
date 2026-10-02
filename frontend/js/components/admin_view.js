/**
 * Administration Workspace Component Controller (Admin Only)
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { api } from '../api.js';
import { state } from '../state.js';

export function renderAdminView(containerEl) {
    const s = state.getState();
    const user = s.currentUser;

    if (!user || user.role !== 'admin') {
        containerEl.innerHTML = `
            <div style="max-width: 480px; margin: 40px auto; text-align: center;">
                <div class="card" style="padding: 28px;">
                    <div style="font-family: var(--font-mono); font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--accent-scarlet); margin-bottom: 6px;">
                        HTTP 403 FORBIDDEN
                    </div>
                    <h3 style="font-size: 16px; margin: 0 0 10px 0; color: var(--text-primary);">Access Restricted</h3>
                    <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 20px; line-height: 1.5;">
                        The Administration Workspace requires the <strong>Administrator</strong> role. 
                        Your current session is authenticated as <strong>${user ? user.role : 'Guest'}</strong>.
                    </p>
                    <button class="btn btn-secondary" type="button" onclick="window.location.hash='dashboard'">Return to Dashboard</button>
                </div>
            </div>
        `;
        return;
    }

    containerEl.innerHTML = `
        <div class="section-header">
            <div>
                <h2 class="section-title">System & User Administration</h2>
                <p class="section-desc">Inspect demonstration accounts, review role allocations, and toggle active session states.</p>
            </div>
            <button class="btn btn-secondary btn-sm" id="btn-refresh-users" type="button">
                Refresh Accounts
            </button>
        </div>

        <div id="admin-status-container"></div>

        <div class="card">
            <div class="card-header" style="padding-bottom: 12px; margin-bottom: 16px; border-bottom: 1px solid var(--border-subtle);">
                <h3 class="card-title" style="font-size: 15px; margin: 0;">User Accounts Directory</h3>
            </div>
            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th style="width: 50px;">ID</th>
                            <th>Full Name</th>
                            <th>Email Address</th>
                            <th>Role</th>
                            <th>Created Date</th>
                            <th>Status</th>
                            <th style="text-align: right;">Action</th>
                        </tr>
                    </thead>
                    <tbody id="admin-users-table-body">
                        <tr>
                            <td colspan="7" style="text-align: center; color: var(--text-secondary); padding: 32px;">
                                Querying user accounts directory...
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    `;

    const btnRefresh = containerEl.querySelector('#btn-refresh-users');
    if (btnRefresh) {
        btnRefresh.addEventListener('click', () => loadUsersList(containerEl));
    }

    loadUsersList(containerEl);
}

async function loadUsersList(containerEl) {
    const tbody = containerEl.querySelector('#admin-users-table-body');
    const statusContainer = containerEl.querySelector('#admin-status-container');
    if (!tbody) return;

    try {
        const users = await api.listUsers();
        state.setState({ adminUsersList: users });

        if (!users || users.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-secondary); padding: 24px;">No user accounts found.</td></tr>`;
            return;
        }

        tbody.innerHTML = users.map(u => {
            const roleBadgeClass = u.role === 'admin' ? 'badge-scarlet' : u.role === 'analyst' ? 'badge-gold' : 'badge-neutral';
            const isSelfAdmin = u.role === 'admin';

            return `
                <tr>
                    <td style="font-family: var(--font-mono); font-size: 12px; font-weight: 600; color: var(--text-primary);">#${u.id}</td>
                    <td style="font-size: 13px; font-weight: 500; color: var(--text-primary);">${escapeHtml(u.name)}</td>
                    <td style="font-family: var(--font-mono); font-size: 12px; color: var(--text-secondary);">${escapeHtml(u.email)}</td>
                    <td><span class="badge ${roleBadgeClass}" style="font-size: 10px;">${escapeHtml(u.role)}</span></td>
                    <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">${new Date(u.created_at).toLocaleDateString()}</td>
                    <td>
                        <span class="badge ${u.is_active ? 'badge-success' : 'badge-neutral'}" style="font-size: 10px;">
                            ${u.is_active ? 'Active' : 'Disabled'}
                        </span>
                    </td>
                    <td style="text-align: right;">
                        ${isSelfAdmin ? `
                            <span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">Primary Admin</span>
                        ` : `
                            <button class="btn btn-ghost btn-sm toggle-status-btn" data-user-id="${u.id}" data-current-status="${u.is_active}" type="button" style="padding: 2px 8px; font-size: 11px;">
                                ${u.is_active ? 'Disable' : 'Enable'}
                            </button>
                        `}
                    </td>
                </tr>
            `;
        }).join('');

        tbody.querySelectorAll('.toggle-status-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const userId = parseInt(btn.getAttribute('data-user-id'), 10);
                const currentStatus = btn.getAttribute('data-current-status') === 'true';
                btn.disabled = true;

                try {
                    await api.updateUserStatus(userId, !currentStatus);
                    loadUsersList(containerEl);
                } catch (err) {
                    if (statusContainer) {
                        statusContainer.innerHTML = `
                            <div style="background: var(--bg-muted); border: 1px solid var(--accent-scarlet); border-radius: var(--radius-sm); padding: 12px; margin-bottom: 16px;">
                                <div style="font-family: var(--font-mono); font-size: 11px; font-weight: 600; color: var(--accent-scarlet);">STATUS UPDATE ERROR</div>
                                <div style="font-size: 12px; color: var(--text-primary); margin-top: 4px;">${escapeHtml(err.message)}</div>
                            </div>
                        `;
                    }
                }
            });
        });
    } catch (err) {
        if (tbody) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--accent-scarlet); padding: 24px;">Failed to load accounts: ${escapeHtml(err.message)}</td></tr>`;
        }
    }
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
