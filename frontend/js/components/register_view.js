/**
 * Functional Account Registration Component Controller
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { api } from '../api.js';

export function renderRegisterView(containerEl) {
    containerEl.innerHTML = `
        <div style="max-width: 480px; margin: 40px auto;">
            <div class="card" style="padding: 28px;">
                <div style="margin-bottom: 20px; border-bottom: 1px solid var(--border-subtle); padding-bottom: 14px;">
                    <div style="font-family: var(--font-mono); font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--accent-gold); margin-bottom: 4px;">
                        ACCOUNT PROVISIONING
                    </div>
                    <h3 style="font-size: 18px; font-weight: 700; color: var(--text-primary); margin: 0;">Register Demonstration Account</h3>
                    <p style="font-size: 12px; color: var(--text-secondary); margin: 4px 0 0 0;">
                        Create a Security Analyst or Academic Researcher account.
                    </p>
                </div>

                <div id="register-status-container"></div>

                <form id="form-register">
                    <div class="form-group" style="margin-bottom: 14px;">
                        <label class="form-label" for="reg-name">Full Name</label>
                        <input type="text" id="reg-name" class="form-input" placeholder="e.g. Dr. Jane Doe" required>
                    </div>

                    <div class="form-group" style="margin-bottom: 14px;">
                        <label class="form-label" for="reg-email">Email Address</label>
                        <input type="email" id="reg-email" class="form-input" placeholder="e.g. jane.doe@research.org" required>
                    </div>

                    <div class="form-group" style="margin-bottom: 14px;">
                        <label class="form-label" for="reg-role">Application Role</label>
                        <select id="reg-role" class="form-select" required>
                            <option value="analyst">Security Analyst — Operational Prioritization & Triage</option>
                            <option value="researcher">Academic Researcher — Inspection & Explainability</option>
                        </select>
                        <span class="form-hint">Administrator accounts are system-seeded.</span>
                    </div>

                    <div class="form-group" style="margin-bottom: 14px;">
                        <label class="form-label" for="reg-password">Password (Minimum 8 Characters)</label>
                        <input type="password" id="reg-password" class="form-input" placeholder="••••••••••••" minlength="8" required>
                    </div>

                    <div class="form-group" style="margin-bottom: 20px;">
                        <label class="form-label" for="reg-confirm-password">Confirm Password</label>
                        <input type="password" id="reg-confirm-password" class="form-input" placeholder="••••••••••••" minlength="8" required>
                    </div>

                    <button type="submit" class="btn btn-primary" id="btn-register-submit" style="width: 100%; justify-content: center; height: 38px;">
                        Create Demonstration Account
                    </button>
                </form>

                <div style="margin-top: 20px; padding-top: 14px; border-top: 1px solid var(--border-subtle); text-align: center; font-size: 12px; color: var(--text-secondary);">
                    Already have an account? 
                    <a href="#login" style="color: var(--text-primary); font-weight: 600; text-decoration: underline;">Sign In Here</a>
                </div>
            </div>
        </div>
    `;

    const form = containerEl.querySelector('#form-register');
    const statusContainer = containerEl.querySelector('#register-status-container');
    const btnSubmit = containerEl.querySelector('#btn-register-submit');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        statusContainer.innerHTML = '';
        const name = containerEl.querySelector('#reg-name').value.trim();
        const email = containerEl.querySelector('#reg-email').value.trim();
        const role = containerEl.querySelector('#reg-role').value;
        const password = containerEl.querySelector('#reg-password').value;
        const confirmPassword = containerEl.querySelector('#reg-confirm-password').value;

        if (password !== confirmPassword) {
            statusContainer.innerHTML = `
                <div style="background: var(--bg-muted); border: 1px solid var(--accent-scarlet); border-radius: var(--radius-sm); padding: 12px; margin-bottom: 16px;">
                    <div style="font-family: var(--font-mono); font-size: 11px; font-weight: 600; color: var(--accent-scarlet);">VALIDATION ERROR</div>
                    <div style="font-size: 12px; color: var(--text-primary); margin-top: 4px;">Passwords do not match.</div>
                </div>
            `;
            return;
        }

        btnSubmit.disabled = true;
        btnSubmit.textContent = 'Provisioning Account...';

        try {
            await api.register({ name, email, role, password });
            statusContainer.innerHTML = `
                <div style="background: var(--bg-muted); border: 1px solid var(--accent-gold); border-radius: var(--radius-sm); padding: 14px; margin-bottom: 16px; font-size: 12px; color: var(--text-primary);">
                    <strong>Account Created Successfully.</strong> Redirecting to login...
                </div>
            `;
            setTimeout(() => {
                window.location.hash = 'login';
            }, 1200);
        } catch (err) {
            statusContainer.innerHTML = `
                <div style="background: var(--bg-muted); border: 1px solid var(--accent-scarlet); border-radius: var(--radius-sm); padding: 12px; margin-bottom: 16px;">
                    <div style="font-family: var(--font-mono); font-size: 11px; font-weight: 600; color: var(--accent-scarlet);">REGISTRATION ERROR</div>
                    <div style="font-size: 12px; color: var(--text-primary); margin-top: 4px;">${escapeHtml(err.message)}</div>
                </div>
            `;
        } finally {
            btnSubmit.disabled = false;
            btnSubmit.textContent = 'Create Demonstration Account';
        }
    });
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
