/**
 * Contact & Prototype Feedback View Component
 * Repository: seucra/vulnarability-prioritization-triage-system
 */

export function renderContactView(containerEl) {
    containerEl.innerHTML = `
        <div class="section-header">
            <div>
                <h2 class="section-title">Research Feedback & Inquiry</h2>
                <p class="section-desc">Submit observations, methodology inquiries, or feedback regarding the vulnerability prioritization system.</p>
            </div>
            <span class="badge badge-neutral" style="font-size: 11px;">Evaluation Feedback</span>
        </div>

        <div style="max-width: 600px; margin: 0 auto;">
            <div id="contact-feedback-banner"></div>

            <div class="card" style="padding: 28px;">
                <div class="card-header" style="padding-bottom: 12px; margin-bottom: 18px; border-bottom: 1px solid var(--border-subtle);">
                    <h3 class="card-title" style="font-size: 16px; margin: 0;">Evaluation Feedback Form</h3>
                    <p style="font-size: 12px; color: var(--text-secondary); margin: 4px 0 0 0;">
                        Feedback is stored locally in session storage for demonstration audit.
                    </p>
                </div>

                <form id="contact-form">
                    <div class="form-group" style="margin-bottom: 16px;">
                        <label for="contact-name" class="form-label">Full Name <span style="color: var(--accent-scarlet);">*</span></label>
                        <input type="text" id="contact-name" class="form-input" placeholder="e.g. Dr. Jane Doe" required>
                    </div>

                    <div class="form-group" style="margin-bottom: 16px;">
                        <label for="contact-email" class="form-label">Email Address <span style="color: var(--accent-scarlet);">*</span></label>
                        <input type="email" id="contact-email" class="form-input" placeholder="e.g. evaluator@university.edu" required>
                    </div>

                    <div class="form-group" style="margin-bottom: 16px;">
                        <label for="contact-category" class="form-label">Inquiry Category <span style="color: var(--accent-scarlet);">*</span></label>
                        <select id="contact-category" class="form-select">
                            <option value="Research Methodology">Research Methodology & Temporal Splitting</option>
                            <option value="Vulnerability Explorer">Vulnerability Explorer & Column Filters</option>
                            <option value="Model Predictions">Pre-Scoring CVSS / KEV Risk Models</option>
                            <option value="Prioritization Engine">Prioritization Surfaces & Asset Tiers</option>
                            <option value="SHAP Explainability">TreeExplainer SHAP Attributions</option>
                            <option value="General Feedback">General User Interface Usability</option>
                        </select>
                    </div>

                    <div class="form-group" style="margin-bottom: 16px;">
                        <label for="contact-message" class="form-label">Detailed Message <span style="color: var(--accent-scarlet);">*</span></label>
                        <textarea id="contact-message" class="form-textarea" rows="4" placeholder="Enter your detailed observations or inquiries..." required></textarea>
                    </div>

                    <div style="font-size: 11px; color: var(--text-muted); line-height: 1.5; margin-bottom: 18px; border-left: 2px solid var(--border-strong); padding-left: 10px;">
                        Notice: Do not submit confidential data or credentials. Submissions are persisted to local demonstration storage.
                    </div>

                    <button type="submit" class="btn btn-primary" style="width: 100%; justify-content: center; height: 38px;">
                        Submit Evaluation Feedback
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
                <div style="background: var(--bg-muted); border: 1px solid var(--accent-scarlet); border-radius: var(--radius-sm); padding: 12px; margin-bottom: 16px;">
                    <div style="font-size: 12px; color: var(--accent-scarlet);">Please fill out all required fields.</div>
                </div>
            `;
            return;
        }

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
            <div style="background: var(--bg-muted); border: 1px solid var(--accent-gold); border-radius: var(--radius-sm); padding: 14px; margin-bottom: 16px; font-size: 12px; color: var(--text-primary);">
                <strong>Feedback Recorded.</strong> Thank you for your review and feedback.
            </div>
        `;

        form.reset();
    });
}
