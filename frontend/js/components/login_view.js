/**
 * Functional Authentication Login Component Controller
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { api } from '../api.js';
import { state } from '../state.js';

export function renderLoginView(containerEl) {
    containerEl.innerHTML = `
        <div style="max-width: 480px; margin: 40px auto;">
            <div class="card" style="padding: 32px; border-top: 4px solid var(--primary);">
                <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 20px;">
                    <div style="background: var(--bg-surface-container); padding: 10px; border-radius: var(--radius-md); color: var(--primary);">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>
                    </div>
                    <div>
                        <h3 style="font-size: 18px; font-weight: 700; color: var(--text-main);">User Authentication</h3>
                        <div style="font-size: 12px; color: var(--text-sub);">Academic Prototype Role-Based Login</div>
                    </div>
                </div>

                <div id="login-error-container"></div>

                <form id="form-login">
                    <div style="margin-bottom: 16px;">
                        <label class="input-label" for="login-email">Email Address</label>
                        <input type="email" id="login-email" class="text-input" placeholder="e.g. analyst@example.com" required style="width: 100%; box-sizing: border-box;">
                    </div>

                    <div style="margin-bottom: 20px;">
                        <label class="input-label" for="login-password">Password</label>
                        <input type="password" id="login-password" class="text-input" placeholder="••••••••••••" required style="width: 100%; box-sizing: border-box;">
                    </div>

                    <button type="submit" class="btn btn-primary" id="btn-login-submit" style="width: 100%; padding: 11px; font-size: 14px; font-weight: 600;">
                        Authenticate & Sign In
                    </button>
                </form>

                <div style="margin-top: 24px; padding-top: 16px; border-top: 1px solid var(--border-color); text-align: center; font-size: 13px; color: var(--text-sub);">
                    Don't have an account yet? 
                    <a href="#register" style="color: var(--primary); font-weight: 600; text-decoration: none;">Register Demonstration Account</a>
                </div>

                <!-- Demonstration Quick Fill Accounts Box -->
                <div style="margin-top: 20px; background: var(--bg-surface-low); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 14px; font-size: 12px;">
                    <strong style="color: var(--primary); display: block; margin-bottom: 8px;">Demonstration Accounts:</strong>
                    <div style="display: flex; flex-direction: column; gap: 6px;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span><strong>Admin:</strong> <code>admin@vuln-triage.sec</code></span>
                            <button class="btn btn-outline btn-sm demo-fill-btn" data-email="admin@vuln-triage.sec" data-pass="AdminDemoPassword123!" style="padding: 2px 8px; font-size: 11px;">Fill</button>
                        </div>
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
            state.setState({ currentUser: res.user, authToken: res.access_token });
            window.location.hash = 'dashboard';
        } catch (err) {
            errorContainer.innerHTML = `
                <div class="error-banner" style="margin-bottom: 16px;">
                    <strong>Authentication Failed:</strong> ${err.message}
                </div>
            `;
        } finally {
            btnSubmit.disabled = false;
            btnSubmit.textContent = 'Authenticate & Sign In';
        }
    });
}
