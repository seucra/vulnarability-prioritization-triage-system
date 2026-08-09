/**
 * Contact & Prototype Feedback View Component
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

export function renderContactView(containerEl) {
    containerEl.innerHTML = `
        <div class="section-header">
            <div>
                <h2 class="section-title">Contact & Research Prototype Feedback</h2>
                <p class="section-desc">Submit feedback, bug observations, or methodology inquiries regarding the vulnerability prioritization system.</p>
            </div>
            <span class="badge badge-low" style="font-size: 12px; padding: 6px 12px;">Web Design Lab Demonstration</span>
        </div>

        <div style="max-width: 720px; margin: 0 auto;">
            <div id="contact-feedback-banner"></div>

            <div class="card" style="padding: 28px;">
                <h3 class="card-title" style="margin-bottom: 6px;">Research Feedback Submission Form</h3>
                <p style="font-size: 12px; color: var(--text-sub); margin-bottom: 20px;">
                    This form is provided for Web Design Lab prototype evaluation. Submissions are processed locally for demonstration feedback tracking.
                </p>

                <form id="contact-form" style="display: flex; flex-direction: column; gap: 16px;">
                    <div>
                        <label for="contact-name" class="input-label">Full Name <span style="color: var(--error);">*</span></label>
                        <input type="text" id="contact-name" class="input-field" placeholder="e.g. Dr. Jane Doe" required style="width: 100%;">
                    </div>

                    <div>
                        <label for="contact-email" class="input-label">Email Address <span style="color: var(--error);">*</span></label>
                        <input type="email" id="contact-email" class="input-field" placeholder="e.g. evaluator@university.edu" required style="width: 100%;">
                    </div>

                    <div>
                        <label for="contact-category" class="input-label">Feedback Category <span style="color: var(--error);">*</span></label>
                        <select id="contact-category" class="input-field" style="width: 100%;">
                            <option value="Research Methodology">Research Methodology & Temporal Split</option>
                            <option value="Vulnerability Explorer">Vulnerability Explorer & Filters</option>
                            <option value="Model Predictions">CVSS / KEV Risk Predictions</option>
                            <option value="Prioritization Engine">Prioritization Surface & Asset Tiers</option>
                            <option value="SHAP Explainability">SHAP Feature Explainability</option>
                            <option value="General Feedback">General UI / Application Usability</option>
                        </select>
                    </div>

                    <div>
                        <label for="contact-message" class="input-label">Message / Feedback <span style="color: var(--error);">*</span></label>
                        <textarea id="contact-message" class="input-field" rows="5" placeholder="Enter your detailed feedback or questions..." required style="width: 100%; resize: vertical;"></textarea>
                    </div>

                    <div style="font-size: 11px; color: var(--text-sub); background: var(--bg-surface-low); padding: 10px; border-radius: var(--radius-sm); border: 1px solid var(--border-color);">
                        Notice: Do not submit passwords, API keys, or sensitive credentials. All demonstration submissions are logged in local storage.
                    </div>

                    <button type="submit" class="btn btn-primary" style="padding: 10px 20px; align-self: flex-start;">
                        Submit Prototype Feedback
                    </button>
                </form>
            </div>
        </div>
    `;

    const form = containerEl.querySelector('#contact-form');
    const bannerContainer = containerEl.querySelector('#contact-feedback-banner');

    form.addEventListener('submit', (e) => {
        e.preventDefault();

        const name = containerEl.querySelector('#contact-name').value.trim();
        const email = containerEl.querySelector('#contact-email').value.trim();
        const category = containerEl.querySelector('#contact-category').value;
        const message = containerEl.querySelector('#contact-message').value.trim();

        if (!name || !email || !message) {
            bannerContainer.innerHTML = `
                <div class="error-banner" style="margin-bottom: 20px;">
                    Please fill out all required fields before submitting.
                </div>
            `;
            return;
        }

        // Save demonstration feedback to localStorage
        try {
            const submissionsStr = localStorage.getItem('wdl_feedback_submissions');
            const submissions = submissionsStr ? JSON.parse(submissionsStr) : [];
            submissions.push({
                name,
                email,
                category,
                message,
                submitted_at: new Date().toISOString()
            });
            localStorage.setItem('wdl_feedback_submissions', JSON.stringify(submissions));
        } catch (err) {
            // Ignore storage errors
        }

        bannerContainer.innerHTML = `
            <div style="background-color: var(--bg-surface-low); border: 1px solid var(--success); border-left: 4px solid var(--success); padding: 16px; border-radius: var(--radius-md); margin-bottom: 20px;">
                <div style="display: flex; align-items: center; gap: 8px; color: var(--success); font-weight: 600; margin-bottom: 4px;">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                    Feedback Received
                </div>
                <div style="font-size: 13px; color: var(--text-main);">
                    Thank you, <strong>${escapeHtml(name)}</strong>! Your feedback regarding <em>${escapeHtml(category)}</em> has been recorded locally for prototype evaluation.
                </div>
            </div>
        `;

        form.reset();
    });
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
