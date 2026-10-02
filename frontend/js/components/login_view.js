/**
 * Functional Authentication Login Component Controller
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { api } from '../api.js';
import { state } from '../state.js';

export function renderLoginView(containerEl) {
    containerEl.innerHTML = `
        <div style="max-width: 440px; margin: 40px auto;">
            <div class="card" style="padding: 28px;">
                <div style="margin-bottom: 20px; border-bottom: 1px solid var(--border-subtle); padding-bottom: 14px;">
                    <div style="font-family: var(--font-mono); font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--accent-gold); margin-bottom: 4px;">
                        SYSTEM AUTHENTICATION
                    </div>
                    <h3 style="font-size: 18px; font-weight: 700; color: var(--text-primary); margin: 0;">Sign In to VTS</h3>
                    <p style="font-size: 12px; color: var(--text-secondary); margin: 4px 0 0 0;">
                        Role-based access for Security Analysts and Academic Researchers.
                    </p>
                </div>

                <div id="login-error-container"></div>

                <form id="form-login">
                    <div class="form-group" style="margin-bottom: 16px;">
                        <label class="form-label" for="login-email">Email Address</label>
                        <input type="email" id="login-email" class="form-input" placeholder="e.g. analyst@example.com" required>
                    </div>

                    <div class="form-group" style="margin-bottom: 20px;">
                        <label class="form-label" for="login-password">Password</label>
                        <input type="password" id="login-password" class="form-input" placeholder="••••••••••••" required>
                    </div>

                    <button type="submit" class="btn btn-primary" id="btn-login-submit" style="width: 100%; justify-content: center; height: 38px;">
                        Authenticate & Sign In
                    </button>
                </form>

                <div style="margin-top: 20px; padding-top: 14px; border-top: 1px solid var(--border-subtle); text-align: center; font-size: 12px; color: var(--text-secondary);">
                    Need an analyst or researcher account? 
                    <a href="#register" style="color: var(--text-primary); font-weight: 600; text-decoration: underline;">Register Demonstration Account</a>
                </div>

                <!-- Demonstration Quick Fill Accounts -->
                <div style="margin-top: 18px; background: var(--bg-muted); border: 1px solid var(--border-subtle); border-radius: var(--radius-sm); padding: 12px 14px; font-size: 12px;">
                    <div style="font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-muted); margin-bottom: 8px;">
                        PRE-CONFIGURED DEMONSTRATION CREDENTIALS:
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <span style="color: var(--text-primary); font-weight: 500;">Administrator:</span>
                            <code style="font-family: var(--font-mono); font-size: 11px; margin-left: 4px; color: var(--text-secondary);">admin@vuln-triage.sec</code>
                        </div>
                        <button type="button" class="btn btn-secondary btn-sm demo-fill-btn" data-email="admin@vuln-triage.sec" data-pass="AdminDemoPassword123!" style="padding: 2px 8px; font-size: 11px;">
                            Quick Fill
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;

    const form = containerEl.querySelector('#form-login');
    const errorContainer = containerEl.querySelector('#login-error-container');
    const btnSubmit = containerEl.querySelector('#btn-login-submit');

    // Quick fill demo credentials
    containerEl.querySelectorAll('.demo-fill-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const email = btn.getAttribute('data-email');
            const pass = btn.getAttribute('data-pass');
            containerEl.querySelector('#login-email').value = email;
            containerEl.querySelector('#login-password').value = pass;
        });
    });

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        errorContainer.innerHTML = '';
        const email = containerEl.querySelector('#login-email').value.trim();
        const password = containerEl.querySelector('#login-password').value;

        btnSubmit.disabled = true;
        btnSubmit.textContent = 'Authenticating...';

        try {
            const res = await api.login({ email, password });
            state.setCurrentUser(res.user, res.access_token);
            window.location.hash = 'dashboard';
        } catch (err) {
            errorContainer.innerHTML = `
                <div style="background: var(--bg-muted); border: 1px solid var(--accent-scarlet); border-radius: var(--radius-sm); padding: 12px; margin-bottom: 16px;">
                    <div style="font-family: var(--font-mono); font-size: 11px; font-weight: 600; color: var(--accent-scarlet);">AUTHENTICATION FAILED</div>
                    <div style="font-size: 12px; color: var(--text-primary); margin-top: 4px;">${escapeHtml(err.message)}</div>
                </div>
            `;
        } finally {
            btnSubmit.disabled = false;
            btnSubmit.textContent = 'Authenticate & Sign In';
        }
    });
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
