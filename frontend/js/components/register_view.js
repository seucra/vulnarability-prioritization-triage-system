/**
 * Functional Account Registration Component Controller
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

import { api } from '../api.js';

export function renderRegisterView(containerEl) {
    containerEl.innerHTML = `
        <div style="max-width: 520px; margin: 40px auto;">
            <div class="card" style="padding: 32px; border-top: 4px solid var(--tertiary);">
                <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 20px;">
                    <div style="background: var(--bg-surface-container); padding: 10px; border-radius: var(--radius-md); color: var(--tertiary);">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="8.5" cy="7" r="4"/><line x1="20" y1="8" x2="20" y2="14"/><line x1="23" y1="11" x2="17" y2="11"/></svg>
                    </div>
                    <div>
                        <h3 style="font-size: 18px; font-weight: 700; color: var(--text-main);">Demonstration Registration</h3>
                        <div style="font-size: 12px; color: var(--text-sub);">Create Security Analyst or Researcher Account</div>
                    </div>
                </div>

                <div id="register-status-container"></div>

                <form id="form-register">
                    <div style="margin-bottom: 14px;">
                        <label class="input-label" for="reg-name">Full Name</label>
                        <input type="text" id="reg-name" class="text-input" placeholder="e.g. Dr. Jane Doe" required style="width: 100%; box-sizing: border-box;">
                    </div>

                    <div style="margin-bottom: 14px;">
                        <label class="input-label" for="reg-email">Email Address</label>
                        <input type="email" id="reg-email" class="text-input" placeholder="e.g. jane.doe@research.org" required style="width: 100%; box-sizing: border-box;">
                    </div>

                    <div style="margin-bottom: 14px;">
                        <label class="input-label" for="reg-role">Application Role</label>
                        <select id="reg-role" class="text-input" required style="width: 100%; box-sizing: border-box;">
                            <option value="analyst">Security Analyst — Operational Vulnerability Triage</option>
                            <option value="researcher">Researcher — Academic Methodology & Inspection</option>
                        </select>
                        <div style="font-size: 11px; color: var(--text-sub); margin-top: 4px;">
                            Administrator accounts are system-provisioned and cannot be registered publicly.
                        </div>
                    </div>

                    <div style="margin-bottom: 14px;">
                        <label class="input-label" for="reg-password">Password (Minimum 8 Characters)</label>
                        <input type="password" id="reg-password" class="text-input" placeholder="••••••••••••" minlength="8" required style="width: 100%; box-sizing: border-box;">
                    </div>

                    <div style="margin-bottom: 20px;">
                        <label class="input-label" for="reg-confirm-password">Confirm Password</label>
                        <input type="password" id="reg-confirm-password" class="text-input" placeholder="••••••••••••" minlength="8" required style="width: 100%; box-sizing: border-box;">
                    </div>

                    <button type="submit" class="btn btn-primary" id="btn-register-submit" style="width: 100%; padding: 11px; font-size: 14px; font-weight: 600;">
                        Create Demonstration Account
                    </button>
                </form>

                <div style="margin-top: 24px; padding-top: 16px; border-top: 1px solid var(--border-color); text-align: center; font-size: 13px; color: var(--text-sub);">
                    Already have an account? 
                    <a href="#login" style="color: var(--primary); font-weight: 600; text-decoration: none;">Sign In Here</a>
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
                <div class="error-banner" style="margin-bottom: 16px;">
                    <strong>Validation Error:</strong> Passwords do not match.
                </div>
            `;
            return;
        }

        btnSubmit.disabled = true;
        btnSubmit.textContent = 'Creating Account...';

        try {
            await api.register({ name, email, role, password });
            statusContainer.innerHTML = `
                <div style="background: var(--bg-surface-low); border: 1px solid var(--success); color: var(--success); padding: 14px; border-radius: var(--radius-md); margin-bottom: 16px; font-size: 13px;">
                    <strong>Registration Successful!</strong> Your demonstration account has been created. Redirecting to login...
                </div>
            `;
            setTimeout(() => {
                window.location.hash = 'login';
            }, 1200);
        } catch (err) {
            statusContainer.innerHTML = `
                <div class="error-banner" style="margin-bottom: 16px;">
                    <strong>Registration Failed:</strong> ${err.message}
                </div>
            `;
            btnSubmit.disabled = false;
            btnSubmit.textContent = 'Create Demonstration Account';
        }
    });
}
