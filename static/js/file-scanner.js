(function() {
    'use strict';

    const FILE_SIZE_LIMITS = {
        '.pdf': 20 * 1024 * 1024,  // 20MB
        '.docx': 10 * 1024 * 1024,
        '.doc': 10 * 1024 * 1024,
        '.docm': 10 * 1024 * 1024,
        '.xlsx': 10 * 1024 * 1024,
        '.xls': 10 * 1024 * 1024,
        '.xlsm': 10 * 1024 * 1024,
        '.zip': 10 * 1024 * 1024,
        '.html': 10 * 1024 * 1024,
        '.htm': 10 * 1024 * 1024,
        '.txt': 10 * 1024 * 1024,
    };

    const FileScanner = {
        form: null,
        dropZone: null,
        fileInput: null,
        progressContainer: null,
        resultsContainer: null,
        
        // Hero section elements
        heroDropZone: null,
        heroFileInput: null,
        heroScanBtn: null,
        heroSelectedContent: null,
        heroDropContent: null,
        heroProgress: null,
        heroResults: null,
        currentFile: null,

        init() {
            // Main section elements
            this.form = document.getElementById('file-scan-form');
            this.dropZone = document.getElementById('file-drop-zone');
            this.fileInput = document.getElementById('file-input');
            this.progressContainer = document.getElementById('file-scan-progress');
            this.resultsContainer = document.getElementById('file-scan-results');

            // Hero section elements
            this.heroDropZone = document.getElementById('file-drop-hero');
            this.heroFileInput = document.getElementById('file-input-hero');
            this.heroScanBtn = document.getElementById('scan-file-hero-btn');
            this.heroSelectedContent = document.getElementById('file-selected-hero');
            this.heroDropContent = document.querySelector('.file-drop-content');
            this.heroProgress = document.getElementById('file-scan-progress-hero');
            this.heroResults = document.getElementById('file-scan-results-hero');

            this.setupEventListeners();
            this.setupHeroEventListeners();
        },

        setupEventListeners() {
            if (!this.form || !this.dropZone) return;

            this.dropZone.addEventListener('click', () => this.fileInput.click());

            this.dropZone.addEventListener('dragover', (e) => {
                e.preventDefault();
                this.dropZone.classList.add('drag-over');
            });

            this.dropZone.addEventListener('dragleave', () => {
                this.dropZone.classList.remove('drag-over');
            });

            this.dropZone.addEventListener('drop', (e) => {
                e.preventDefault();
                this.dropZone.classList.remove('drag-over');
                const files = e.dataTransfer.files;
                if (files.length > 0) {
                    this.handleFileSelect(files[0], 'main');
                }
            });

            this.fileInput.addEventListener('change', (e) => {
                if (e.target.files.length > 0) {
                    this.handleFileSelect(e.target.files[0], 'main');
                }
            });
        },

        setupHeroEventListeners() {
            if (!this.heroDropZone) return;

            // Drag and drop
            this.heroDropZone.addEventListener('dragover', (e) => {
                e.preventDefault();
                this.heroDropZone.classList.add('drag-over');
            });

            this.heroDropZone.addEventListener('dragleave', () => {
                this.heroDropZone.classList.remove('drag-over');
            });

            this.heroDropZone.addEventListener('drop', (e) => {
                e.preventDefault();
                this.heroDropZone.classList.remove('drag-over');
                const files = e.dataTransfer.files;
                if (files.length > 0) {
                    this.handleFileSelect(files[0], 'hero');
                }
            });

            // File input change (triggered by label click or file selection)
            this.heroFileInput.addEventListener('change', (e) => {
                if (e.target.files.length > 0) {
                    this.handleFileSelect(e.target.files[0], 'hero');
                }
            });

            // Scan button
            if (this.heroScanBtn) {
                this.heroScanBtn.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    if (this.currentFile) {
                        this.uploadFile(this.currentFile, 'hero');
                    }
                });
            }

            // Scan button when file selected
            const scanBtnSelected = document.getElementById('scan-file-hero-btn-selected');
            if (scanBtnSelected) {
                scanBtnSelected.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    if (this.currentFile) {
                        this.uploadFile(this.currentFile, 'hero');
                    }
                });
            }

            // Clear button
            const clearBtn = document.getElementById('clear-file-hero');
            if (clearBtn) {
                clearBtn.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    this.clearHeroFile();
                });
            }
        },

        handleFileSelect(file, context) {
            const ext = '.' + file.name.split('.').pop().toLowerCase();
            const maxSize = FILE_SIZE_LIMITS[ext] || (10 * 1024 * 1024);

            if (!FILE_SIZE_LIMITS[ext]) {
                this.showError('Unsupported file format. Please upload PDF, DOCX, XLSX, HTML, TXT, or ZIP files.', context);
                return;
            }

            if (file.size > maxSize) {
                const maxMB = maxSize / (1024 * 1024);
                const actualMB = (file.size / (1024 * 1024)).toFixed(2);
                this.showError(`File exceeds maximum allowed size (${maxMB}MB). Your file is ${actualMB}MB`, context);
                return;
            }

            this.currentFile = file;

            if (context === 'hero') {
                this.showHeroFileSelected(file);
            }
        },

        showHeroFileSelected(file) {
            if (this.heroDropContent) this.heroDropContent.style.display = 'none';
            if (this.heroSelectedContent) {
                this.heroSelectedContent.style.display = 'block';
                document.getElementById('hero-filename').textContent = file.name;
                document.getElementById('hero-filesize').textContent = this.formatFileSize(file.size);
            }
            if (this.heroScanBtn) this.heroScanBtn.disabled = false;
        },

        clearHeroFile() {
            this.currentFile = null;
            if (this.heroDropContent) this.heroDropContent.style.display = 'block';
            if (this.heroSelectedContent) this.heroSelectedContent.style.display = 'none';
            if (this.heroFileInput) this.heroFileInput.value = '';
            if (this.heroScanBtn) this.heroScanBtn.disabled = true;
            if (this.heroProgress) this.heroProgress.style.display = 'none';
            if (this.heroResults) this.heroResults.style.display = 'none';
            this.hideUploadSpinner();
        },

        showUploadSpinner() {
            if (this.heroSelectedContent) this.heroSelectedContent.style.display = 'none';
            if (this.heroDropContent) this.heroDropContent.style.display = 'none';
            const spinner = document.getElementById('upload-spinner');
            if (spinner) spinner.style.display = 'block';
            if (this.heroProgress) this.heroProgress.style.display = 'none';
            if (this.heroResults) this.heroResults.style.display = 'none';
        },

        hideUploadSpinner() {
            const spinner = document.getElementById('upload-spinner');
            if (spinner) spinner.style.display = 'none';
        },

        async uploadFile(file, context = 'main') {
            const formData = new FormData();
            formData.append('file', file);

            // Show upload spinner first
            if (context === 'hero') {
                this.showUploadSpinner();
            }

            try {
                const response = await fetch('/scan-file', {
                    method: 'POST',
                    body: formData
                });

                if (!response.ok) {
                    const errorData = await response.json().catch(() => ({ error: 'Server error' }));
                    throw new Error(errorData.error || `Server returned ${response.status}`);
                }

                const data = await response.json();

                if (context === 'hero') {
                    this.showHeroResults(data);
                } else {
                    this.showProgress(100);
                    this.displayResults(data);
                }

            } catch (error) {
                console.error('File scan error:', error);
                let errorMessage = 'An unexpected error occurred';
                
                if (error.name === 'TypeError' && error.message === 'Failed to fetch') {
                    errorMessage = 'Cannot connect to server. Please make sure the Flask app is running.';
                } else if (error.message) {
                    if (error.message.includes('image.png') || error.message.includes('does not support image')) {
                        errorMessage = 'This file type is not supported for analysis. Please upload a different file.';
                    } else if (error.message.includes('File exceeds maximum')) {
                        errorMessage = error.message;
                    } else if (error.message.includes('Unsupported file format')) {
                        errorMessage = 'Unsupported file format. Please upload PDF, DOCX, XLSX, HTML, TXT, or ZIP files.';
                    } else {
                        errorMessage = error.message;
                    }
                }
                
                if (context === 'hero') {
                    this.hideUploadSpinner();
                    this.showHeroError(errorMessage);
                } else {
                    this.showError(errorMessage);
                }
            }
        },

        // Hero scanning animation
        showHeroScanning() {
            if (this.heroSelectedContent) this.heroSelectedContent.style.display = 'none';
            if (this.heroProgress) {
                this.heroProgress.style.display = 'block';
                // Animate stages
                const stages = this.heroProgress.querySelectorAll('.scan-stage-item');
                stages.forEach((stage, index) => {
                    setTimeout(() => {
                        stage.classList.add('active');
                        if (index > 0) {
                            stages[index - 1].classList.add('completed');
                            stages[index - 1].classList.remove('active');
                        }
                    }, index * 1500);
                });
            }
            if (this.heroResults) this.heroResults.style.display = 'none';
        },

        showHeroResults(report) {
            if (this.heroProgress) this.heroProgress.style.display = 'none';
            if (this.heroResults) {
                this.heroResults.style.display = 'block';
                this.heroResults.innerHTML = this.buildResultsHTML(report);
                this.attachResultListeners(this.heroResults, report);
            }
        },

        showHeroError(message) {
            if (this.heroProgress) this.heroProgress.style.display = 'none';
            if (this.heroResults) {
                this.heroResults.style.display = 'block';
                this.heroResults.innerHTML = `
                    <div class="file-result-error">
                        <i class="bx bx-error-circle"></i>
                        <h4>Scan Error</h4>
                        <p>${message}</p>
                        <button class="btn btn-outline-light mt-3" onclick="FileScanner.clearHeroFile()">
                            <i class="bx bx-refresh"></i> Try Again
                        </button>
                    </div>
                `;
            }
        },

        // Main section functions
        showProgress(percent) {
            if (this.progressContainer) {
                this.progressContainer.style.display = 'block';
                const progressBar = this.progressContainer.querySelector('.progress-bar');
                if (progressBar) {
                    progressBar.style.width = percent + '%';
                    progressBar.setAttribute('aria-valuenow', percent);
                }
            }
        },

        hideProgress() {
            if (this.progressContainer) {
                this.progressContainer.style.display = 'none';
                const progressBar = this.progressContainer.querySelector('.progress-bar');
                if (progressBar) {
                    progressBar.style.width = '0%';
                }
            }
        },

        showError(message, context = 'main') {
            if (context === 'main') {
                this.hideProgress();
                if (this.resultsContainer) {
                    this.resultsContainer.innerHTML = `
                        <div class="file-result-error">
                            <i class="bx bx-error-circle"></i>
                            <h4>Scan Error</h4>
                            <p>${message}</p>
                        </div>
                    `;
                    this.resultsContainer.style.display = 'block';
                }
            }
        },

        buildResultsHTML(report) {
            const riskColor = this.getRiskColor(report.risk_level || 'Safe');
            const riskIcon = this.getRiskIcon(report.risk_level || 'Safe');
            
            let urlsHtml = '';
            if (report.urls_found && report.urls_found.length > 0) {
                urlsHtml = `
                    <div class="file-result-section">
                        <h5><i class="bx bx-link"></i> URLs Found (${report.urls_found.length})</h5>
                        <ul class="url-list">
                            ${report.urls_found.slice(0, 10).map(item => `
                                <li class="${item.risk === 'high' || item.status === 'high_risk' ? 'suspicious' : ''}">
                                    <span class="url-text">${this.escapeHtml(item.url)}</span>
                                    ${item.risk === 'high' || item.status === 'high_risk' ? '<span class="badge badge-danger">High Risk</span>' : ''}
                                    ${item.risk === 'medium' || item.status === 'suspicious' ? '<span class="badge badge-warning">Suspicious</span>' : ''}
                                    ${item.risk === 'none' || item.status === 'trusted' ? '<span class="badge badge-success">Trusted</span>' : ''}
                                </li>
                            `).join('')}
                        </ul>
                    </div>
                `;
            }

            let scriptsHtml = '';
            if (report.scripts_detected && report.scripts_detected.length > 0) {
                scriptsHtml = `
                    <div class="file-result-section">
                        <h5><i class="bx bx-code-alt"></i> Scripts Detected</h5>
                        <ul class="detection-list">
                            ${report.scripts_detected.map(script => `<li>${this.escapeHtml(script)}</li>`).join('')}
                        </ul>
                    </div>
                `;
            }

            let macrosHtml = '';
            if (report.macros_detected) {
                macrosHtml = `
                    <div class="file-result-section danger">
                        <h5><i class="bx bx-warning"></i> Macros Detected</h5>
                        <p>This file contains macros that could execute malicious code.</p>
                    </div>
                `;
            }

            const totalRisks = (report.url_analysis?.high_risk_urls || 0) + (report.url_analysis?.suspicious_urls || 0);

            return `
                <div class="file-result-header" style="border-color: ${riskColor}">
                    <div class="file-result-icon" style="background: ${riskColor}">
                        <i class="bx ${riskIcon}"></i>
                    </div>
                    <div class="file-result-title">
                        <h3>${report.risk_level || 'Safe'}</h3>
                        <p>${this.escapeHtml(report.summary || 'No summary available')}</p>
                    </div>
                </div>

                <!-- Comparison Grid -->
                <div class="file-result-section">
                    <h5><i class="bx bx-git-compare"></i> Analysis Summary</h5>
                    <div class="comparison-grid">
                        <div class="comparison-item">
                            <i class="bx bx-file"></i>
                            <div class="comparison-label">File</div>
                            <div class="comparison-value">${this.escapeHtml(report.filename || 'Unknown')}</div>
                        </div>
                        <div class="comparison-item">
                            <i class="bx bx-link"></i>
                            <div class="comparison-label">URLs Found</div>
                            <div class="comparison-value">${report.url_analysis?.total_urls || 0}</div>
                        </div>
                        <div class="comparison-item ${totalRisks > 0 ? 'danger' : ''}">
                            <i class="bx bx-error"></i>
                            <div class="comparison-label">Risks</div>
                            <div class="comparison-value">${totalRisks}</div>
                        </div>
                        <div class="comparison-item" style="border-color: ${riskColor}">
                            <i class="bx bx-shield" style="color: ${riskColor}"></i>
                            <div class="comparison-label">Status</div>
                            <div class="comparison-value" style="color: ${riskColor}">${report.risk_level || 'Safe'}</div>
                        </div>
                    </div>
                </div>

                <div class="file-result-grid">
                    <div class="file-result-card">
                        <h5><i class="bx bx-file"></i> File Info</h5>
                        <p><strong>Name:</strong> ${this.escapeHtml(report.filename || 'Unknown')}</p>
                        <p><strong>Type:</strong> ${report.file_type || 'Unknown'}</p>
                        <p><strong>Size:</strong> ${this.formatFileSize(report.file_size || 0)}</p>
                    </div>

                    <div class="file-result-card">
                        <h5><i class="bx bx-shield"></i> Malware Scan</h5>
                        <p class="malware-status ${report.malware_scan?.status === 'Clean' ? 'clean' : 'danger'}">
                            ${report.malware_scan?.status || 'Unknown'}
                        </p>
                    </div>

                    <div class="file-result-card">
                        <h5><i class="bx bx-lock"></i> URL Analysis</h5>
                        <p><strong>Total:</strong> ${report.url_analysis?.total_urls || 0}</p>
                        <p><strong>Trusted:</strong> ${report.url_analysis?.trusted_urls || 0}</p>
                        <p><strong>Suspicious:</strong> ${report.url_analysis?.suspicious_urls || 0}</p>
                        <p><strong>High Risk:</strong> ${report.url_analysis?.high_risk_urls || 0}</p>
                    </div>

                    <div class="file-result-card">
                        <h5><i class="bx bx-bar-chart"></i> Entropy</h5>
                        <p>Score: ${report.entropy_score || 0}</p>
                        <p>Level: <span class="badge badge-${report.entropy_level === 'High' ? 'danger' : report.entropy_level === 'Medium' ? 'warning' : 'success'}">${report.entropy_level || 'Low'}</span></p>
                    </div>
                </div>

                ${urlsHtml}
                ${scriptsHtml}
                ${macrosHtml}

                <div class="file-result-risk-meter">
                    <h5><i class="bx bx-gauge"></i> Security Score</h5>
                    <div class="risk-meter">
                        <div class="risk-meter-fill" style="width: ${report.risk_score || 0}%; background: ${riskColor}"></div>
                    </div>
                    <div class="risk-meter-labels">
                        <span>0</span>
                        <span>Safe</span>
                        <span>Suspicious</span>
                        <span>Dangerous</span>
                        <span>100</span>
                    </div>
                </div>

                <div class="result-actions">
                    <button class="btn btn-download-report" onclick="FileScanner.downloadReport(${this.escapeHtml(JSON.stringify(report))})">
                        <i class="bx bx-download"></i> Download Report
                    </button>
                    <button class="btn btn-scan-another" onclick="FileScanner.scanAnother('${report.context || 'main'}')">
                        <i class="bx bx-refresh"></i> Scan Another File
                    </button>
                </div>
            `;
        },

        attachResultListeners(container, report) {
            // Add any event listeners for result actions if needed
        },

        displayResults(report) {
            this.hideProgress();
            
            if (!this.resultsContainer) return;

            this.resultsContainer.innerHTML = this.buildResultsHTML(report);
            this.resultsContainer.style.display = 'block';
        },

        downloadReport(report) {
            const reportData = {
                scanDate: new Date().toISOString(),
                fileInfo: {
                    name: report.filename,
                    type: report.file_type,
                    size: report.file_size,
                    sizeFormatted: this.formatFileSize(report.file_size)
                },
                analysis: {
                    riskScore: report.risk_score,
                    riskLevel: report.risk_level,
                    malwareStatus: report.malware_scan?.status,
                    malwareSignatures: report.malware_scan?.suspicious_signatures || [],
                    urlsFound: report.url_analysis?.total_urls || 0,
                    trustedUrls: report.url_analysis?.trusted_urls || 0,
                    suspiciousUrls: report.url_analysis?.suspicious_urls || 0,
                    highRiskUrls: report.url_analysis?.high_risk_urls || 0,
                    macrosDetected: report.macros_detected,
                    scriptsDetected: report.scripts_detected || [],
                    entropyScore: report.entropy_score,
                    entropyLevel: report.entropy_level
                },
                summary: report.summary,
                recommendations: this.getRecommendations(report)
            };
            
            const blob = new Blob([JSON.stringify(reportData, null, 2)], {type: 'application/json'});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `security-report-${report.filename || 'file'}-${Date.now()}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        },

        getRecommendations(report) {
            const recommendations = [];
            
            if (report.risk_score > 50) {
                recommendations.push("High risk detected - do not open this file");
                recommendations.push("Delete the file immediately");
            }
            
            if (report.macros_detected) {
                recommendations.push("Disable macros before opening Office documents");
            }
            
            if (report.url_analysis?.high_risk_urls > 0) {
                recommendations.push("Do not click on any links in this file");
            }
            
            if (report.entropy_level === 'High') {
                recommendations.push("File may be packed or encrypted - exercise caution");
            }
            
            if (recommendations.length === 0) {
                recommendations.push("File appears safe but always verify sources");
            }
            
            return recommendations;
        },

        scanAnother(context = 'main') {
            if (context === 'hero') {
                this.clearHeroFile();
            } else {
                if (this.resultsContainer) this.resultsContainer.style.display = 'none';
                if (this.fileInput) this.fileInput.value = '';
            }
        },

        getRiskColor(level) {
            switch(level) {
                case 'Safe': return '#22c55e';
                case 'Suspicious': return '#f59e0b';
                case 'Dangerous': return '#ef4444';
                default: return '#6b7280';
            }
        },

        getRiskIcon(level) {
            switch(level) {
                case 'Safe': return 'bx-check-shield';
                case 'Suspicious': return 'bx-error';
                case 'Dangerous': return 'bx-skull';
                default: return 'bx-help-circle';
            }
        },

        formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        },

        escapeHtml(text) {
            if (typeof text !== 'string') return text;
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    };

    document.addEventListener('DOMContentLoaded', () => {
        FileScanner.init();
    });

    window.FileScanner = FileScanner;
})();
