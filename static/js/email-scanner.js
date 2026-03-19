/**
 * Email Security Scanner
 * Professional multi-layer phishing detection frontend
 */

(function() {
    'use strict';

    const EmailScanner = {
        container: null,
        inputArea: null,
        scanBtn: null,
        progressArea: null,
        resultsArea: null,
        attachmentInput: null,
        currentStage: 0,
        stages: [
            { id: 1, name: 'Analyzing Sender', icon: 'bx-user' },
            { id: 2, name: 'Extracting Links', icon: 'bx-link' },
            { id: 3, name: 'Scanning Content', icon: 'bx-file' },
            { id: 4, name: 'Checking URLs', icon: 'bx-scan' },
            { id: 5, name: 'Calculating Risk', icon: 'bx-chart' }
        ],

        init() {
            this.container = document.getElementById('email-scanner-wrapper');
            this.inputArea = document.getElementById('email-input');
            this.scanBtn = document.getElementById('scan-email-btn');
            this.progressArea = document.getElementById('email-scan-progress');
            this.resultsArea = document.getElementById('email-scan-results');
            this.attachmentInput = document.getElementById('email-attachment');
            
            this.setupEventListeners();
        },

        setupEventListeners() {
            if (this.scanBtn) {
                this.scanBtn.addEventListener('click', () => this.startScan());
            }

            if (this.attachmentInput) {
                this.attachmentInput.addEventListener('change', (e) => this.handleAttachment(e));
            }

            if (this.inputArea) {
                this.inputArea.addEventListener('keydown', (e) => {
                    if (e.ctrlKey && e.key === 'Enter') {
                        this.startScan();
                    }
                });
            }
        },

        async startScan() {
            const emailText = this.inputArea?.value?.trim();
            
            if (!emailText) {
                this.showError('Please paste email content to scan');
                return;
            }

            const MAX_SIZE = 100 * 1024;
            if (emailText.length > MAX_SIZE) {
                this.showError(`Email exceeds ${MAX_SIZE / 1024}KB limit`);
                return;
            }

            this.showProgress();
            
            try {
                const result = await this.sendAnalysis(emailText);
                await this.animateToCompletion();
                this.showResults(result);
            } catch (error) {
                console.error('Email scan error:', error);
                this.hideProgress();
                this.showError(error.message || 'Analysis failed. Please try again.');
            }
        },

        async sendAnalysis(emailText) {
            const formData = new FormData();
            formData.append('email_text', emailText);

            if (this.attachmentInput?.files?.[0]) {
                formData.append('attachment', this.attachmentInput.files[0]);
            }

            let response;
            try {
                response = await fetch('/api/scan_email', {
                    method: 'POST',
                    body: formData
                });
            } catch (networkError) {
                console.error('Network error:', networkError);
                throw new Error('Cannot connect to server. Please make sure the Flask app is running.');
            }

            let data;
            try {
                data = await response.json();
            } catch (e) {
                console.error('JSON parse error:', e);
                throw new Error('Invalid response from server.');
            }

            if (!response.ok || !data.success) {
                throw new Error(data.error || data.message || `Server error (${response.status})`);
            }

            return data;
        },

        showProgress() {
            if (this.inputArea) this.inputArea.disabled = true;
            if (this.scanBtn) this.scanBtn.disabled = true;
            if (this.progressArea) {
                this.progressArea.style.display = 'block';
                this.progressArea.innerHTML = this.buildProgressHTML();
            }
            if (this.resultsArea) this.resultsArea.style.display = 'none';
        },

        hideProgress() {
            if (this.inputArea) this.inputArea.disabled = false;
            if (this.scanBtn) this.scanBtn.disabled = false;
            if (this.progressArea) this.progressArea.style.display = 'none';
        },

        buildProgressHTML() {
            return `
                <div class="email-scan-stages">
                    ${this.stages.map(stage => `
                        <div class="email-scan-stage" data-stage="${stage.id}">
                            <div class="stage-icon-wrapper">
                                <i class='bx ${stage.icon}'></i>
                            </div>
                            <span class="stage-name">${stage.name}</span>
                            <div class="stage-checkmark"><i class='bx bx-check'></i></div>
                        </div>
                    `).join('')}
                </div>
                <div class="email-scan-status">
                    <div class="status-text">Initializing analysis...</div>
                    <div class="progress-bar-container">
                        <div class="progress-bar-fill"></div>
                    </div>
                </div>
            `;
        },

        async animateToCompletion() {
            const statusTexts = [
                'Analyzing sender domain...',
                'Extracting URLs from content...',
                'Scanning for phishing patterns...',
                'Checking URL safety...',
                'Calculating final risk score...'
            ];

            for (let i = 0; i < this.stages.length; i++) {
                this.currentStage = i + 1;
                
                const stageEl = document.querySelector(`.email-scan-stage[data-stage="${i + 1}"]`);
                const statusEl = document.querySelector('.status-text');
                const progressFill = document.querySelector('.progress-bar-fill');
                
                if (stageEl) {
                    stageEl.classList.add('active');
                    await this.delay(400);
                    stageEl.classList.add('completed');
                    stageEl.classList.remove('active');
                }
                
                if (statusEl) {
                    statusEl.textContent = statusTexts[i] || 'Processing...';
                }
                
                if (progressFill) {
                    const progress = ((i + 1) / this.stages.length) * 100;
                    progressFill.style.width = `${progress}%`;
                }
                
                await this.delay(600);
            }

            await this.delay(300);
        },

        delay(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        },

        showResults(result) {
            this.hideProgress();
            
            if (!result.success) {
                this.showError(result.error || 'Analysis failed');
                return;
            }

            if (this.resultsArea) {
                this.resultsArea.style.display = 'block';
                this.resultsArea.innerHTML = this.buildResultsHTML(result);
            }
        },

        buildResultsHTML(result) {
            const riskColor = this.getRiskColor(result.risk_level);
            const riskIcon = this.getRiskIcon(result.risk_level);
            
            const sender = result.sender || {};
            const links = result.links || {};
            const content = result.content || {};
            const headers = result.headers || {};
            const brand = result.brand_claim || {};
            
            let senderHtml = '';
            if (sender.email) {
                senderHtml = `
                    <div class="result-section sender-section">
                        <div class="section-header">
                            <i class='bx bx-user'></i>
                            <h4>Sender Analysis</h4>
                        </div>
                        <div class="sender-info">
                            <div class="info-row">
                                <span class="info-label">From:</span>
                                <span class="info-value">${this.escapeHtml(sender.email)}</span>
                            </div>
                            <div class="info-row">
                                <span class="info-label">Domain:</span>
                                <span class="info-value ${sender.risk_level === 'high' ? 'text-danger' : sender.risk_level === 'medium' ? 'text-warning' : ''}">${this.escapeHtml(sender.domain)}</span>
                            </div>
                            ${sender.issues?.length ? `
                                <div class="sender-issues">
                                    ${sender.issues.map(issue => `
                                        <div class="issue-badge"><i class='bx bx-warning'></i> ${this.escapeHtml(issue)}</div>
                                    `).join('')}
                                </div>
                            ` : ''}
                        </div>
                    </div>
                `;
            }

            let linksHtml = '';
            if (links.urls?.length) {
                linksHtml = `
                    <div class="result-section links-section">
                        <div class="section-header">
                            <i class='bx bx-link'></i>
                            <h4>Link Analysis (${links.urls.length} found)</h4>
                        </div>
                        <div class="links-list">
                            ${links.urls.slice(0, 5).map(link => `
                                <div class="link-item ${link.status === 'phishing' ? 'danger' : link.status === 'suspicious' ? 'warning' : ''}">
                                    <div class="link-url">
                                        <span class="link-domain">${this.escapeHtml(link.domain)}</span>
                                        ${link.mismatch ? '<span class="badge badge-danger">MISMATCH</span>' : ''}
                                        ${link.shortened ? '<span class="badge badge-warning">SHORTENED</span>' : ''}
                                    </div>
                                    <div class="link-status">
                                        <span class="status-badge status-${link.status}">${link.status}</span>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `;
            }

            let contentHtml = '';
            const contentIssues = [
                ...(content.urgency_indicators || []),
                ...(content.threat_indicators || []),
                ...(content.financial_indicators || []),
                ...(content.prize_indicators || [])
            ];
            
            if (contentIssues.length) {
                contentHtml = `
                    <div class="result-section content-section">
                        <div class="section-header">
                            <i class='bx bx-file'></i>
                            <h4>Content Analysis</h4>
                        </div>
                        <div class="content-patterns">
                            ${contentIssues.slice(0, 6).map(pattern => `
                                <span class="pattern-badge">${this.escapeHtml(pattern)}</span>
                            `).join('')}
                        </div>
                    </div>
                `;
            }

            let authHtml = '';
            const authFailures = [];
            if (headers.spf?.status === 'fail') authFailures.push('SPF Failed');
            if (headers.dkim?.status === 'fail') authFailures.push('DKIM Failed');
            if (headers.dmarc?.status === 'fail') authFailures.push('DMARC Failed');

            if (authFailures.length || headers.spf?.status !== 'not_available') {
                authHtml = `
                    <div class="result-section auth-section">
                        <div class="section-header">
                            <i class='bx bx-shield'></i>
                            <h4>Email Authentication</h4>
                        </div>
                        <div class="auth-results">
                            ${this.buildAuthBadge('SPF', headers.spf?.status)}
                            ${this.buildAuthBadge('DKIM', headers.dkim?.status)}
                            ${this.buildAuthBadge('DMARC', headers.dmarc?.status)}
                        </div>
                    </div>
                `;
            }

            let brandHtml = '';
            if (brand.is_impersonation) {
                brandHtml = `
                    <div class="result-section brand-section danger">
                        <div class="section-header">
                            <i class='bx bx-error'></i>
                            <h4>Brand Impersonation Detected</h4>
                        </div>
                        <div class="brand-warning">
                            <p>Claims to be from <strong>${this.escapeHtml(brand.claimed_brand)}</strong> but sent from <strong>${this.escapeHtml(brand.sender_domain)}</strong></p>
                        </div>
                    </div>
                `;
            }

            return `
                <div class="email-result-card">
                    <div class="result-header" style="border-color: ${riskColor}">
                        <div class="risk-meter-container">
                            <div class="risk-meter">
                                <div class="risk-meter-fill" style="width: ${result.risk_score}%; background: ${riskColor}"></div>
                            </div>
                            <div class="risk-meter-labels">
                                <span>0</span>
                                <span>Safe</span>
                                <span>Suspicious</span>
                                <span>Dangerous</span>
                                <span>100</span>
                            </div>
                        </div>
                        <div class="result-title">
                            <div class="result-icon" style="background: ${riskColor}">
                                <i class='bx ${riskIcon}'></i>
                            </div>
                            <div class="result-text">
                                <h3 style="color: ${riskColor}">${result.risk_level}</h3>
                                <p>Risk Score: ${result.risk_score}/100</p>
                            </div>
                        </div>
                    </div>

                    ${senderHtml}
                    ${linksHtml}
                    ${contentHtml}
                    ${authHtml}
                    ${brandHtml}

                    ${result.explanation?.length ? `
                        <div class="result-section explanation-section">
                            <div class="section-header">
                                <i class='bx bx-list-check'></i>
                                <h4>Why This Result?</h4>
                            </div>
                            <ul class="explanation-list">
                                ${result.explanation.map(reason => `
                                    <li>${this.escapeHtml(reason)}</li>
                                `).join('')}
                            </ul>
                        </div>
                    ` : ''}

                    <div class="result-actions">
                        <button class="btn btn-outline-secondary" onclick="EmailScanner.reset()">
                            <i class='bx bx-refresh'></i> Scan Another Email
                        </button>
                    </div>
                </div>
            `;
        },

        buildAuthBadge(type, status) {
            let className = 'secondary';
            let icon = 'help';
            
            if (status === 'pass') {
                className = 'success';
                icon = 'check';
            } else if (status === 'fail') {
                className = 'danger';
                icon = 'x';
            } else if (status === 'not_available') {
                return '';
            }
            
            return `<span class="auth-badge ${className}"><i class='bx bx-${icon}'></i> ${type}: ${status}</span>`;
        },

        getRiskColor(level) {
            switch(level) {
                case 'Safe': return '#22c55e';
                case 'Suspicious': return '#f59e0b';
                case 'Phishing': return '#ef4444';
                default: return '#6b7280';
            }
        },

        getRiskIcon(level) {
            switch(level) {
                case 'Safe': return 'bx-check-shield';
                case 'Suspicious': return 'bx-error';
                case 'Phishing': return 'bx-skull';
                default: return 'bx-help-circle';
            }
        },

        showError(message) {
            if (this.resultsArea) {
                this.resultsArea.style.display = 'block';
                this.resultsArea.innerHTML = `
                    <div class="email-result-error">
                        <i class='bx bx-error-circle'></i>
                        <h4>Analysis Error</h4>
                        <p>${this.escapeHtml(message)}</p>
                        <button class="btn btn-outline-light" onclick="EmailScanner.reset()">
                            <i class='bx bx-refresh'></i> Try Again
                        </button>
                    </div>
                `;
            }
        },

        handleAttachment(e) {
            const file = e.target.files?.[0];
            if (file) {
                const maxSize = 10 * 1024 * 1024;
                if (file.size > maxSize) {
                    this.showError('Attachment exceeds 10MB limit');
                    e.target.value = '';
                }
            }
        },

        reset() {
            if (this.inputArea) this.inputArea.value = '';
            if (this.attachmentInput) this.attachmentInput.value = '';
            if (this.resultsArea) {
                this.resultsArea.style.display = 'none';
                this.resultsArea.innerHTML = '';
            }
            this.currentStage = 0;
        },

        escapeHtml(text) {
            if (typeof text !== 'string') return text;
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    };

    document.addEventListener('DOMContentLoaded', () => {
        EmailScanner.init();
    });

    window.EmailScanner = EmailScanner;
})();
