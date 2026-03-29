/**
 * QR Code Security Scanner - High Performance Version
 * Uses html5-qrcode library for camera-based scanning
 * All processing is in-memory only - NO data stored
 */

(function() {
    if (typeof window !== 'undefined') {
        window.BarCodeDetector = undefined;
        if (typeof Symbol !== 'undefined') {
            try {
                delete window.BarCodeDetector;
            } catch (e) {}
        }
    }
    
    if (typeof Html5Qrcode !== 'undefined') {
        Html5Qrcode.BarCodeDetector = undefined;
        if (Html5Qrcode.prototype) {
            Html5Qrcode.prototype.BarCodeDetector = undefined;
        }
    }
    
    if (typeof Html5QrcodeScanner !== 'undefined') {
        Html5QrcodeScanner.BarCodeDetector = undefined;
    }
})();

window.addEventListener('error', function(e) {
    if (e.message && (
        e.message.includes('BarCodeDetector') ||
        e.message.includes('does not support image input') ||
        e.message.includes('model does not support')
    )) {
        e.preventDefault();
        e.stopPropagation();
        return true;
    }
}, true);

const QRScanner = {
    html5QrCode: null,
    isScanning: false,
    previewImageData: null,
    scanTimeout: null,
    zoomApplied: false,
    lastScanTime: 0,

    init() {
        console.log('[QR Scanner] Initializing...');
        this.disableBarCodeDetector();
        this.setupEventListeners();
        this.setupDropZone();
        console.log('[QR Scanner] Initialization complete');
    },

    disableBarCodeDetector() {
        try {
            if (typeof Html5Qrcode !== 'undefined') {
                if (Html5Qrcode.BarCodeDetector) {
                    delete Html5Qrcode.BarCodeDetector;
                }
                if (Html5Qrcode.prototype) {
                    Html5Qrcode.prototype.BarCodeDetector = null;
                }
            }
            if (typeof BarCodeDetector !== 'undefined') {
                BarCodeDetector = null;
            }
        } catch (e) {
            console.log('[QR Scanner] BarCodeDetector cleanup:', e.message);
        }
    },

    isMobile() {
        return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent) 
            || window.innerWidth < 768;
    },

    setupEventListeners() {
        const uploadBtn = document.getElementById('qr-upload-btn');
        const cameraBtn = document.getElementById('qr-camera-btn');
        const scanBtn = document.getElementById('qr-scan-btn');
        const manualToggle = document.getElementById('qr-manual-toggle');
        const manualInput = document.getElementById('qr-manual-input');
        const exitFullscreen = document.getElementById('qr-exit-fullscreen');

        if (uploadBtn) {
            uploadBtn.addEventListener('click', () => this.triggerFileUpload());
        }

        if (cameraBtn) {
            cameraBtn.addEventListener('click', () => this.toggleCamera());
        }

        if (scanBtn) {
            scanBtn.addEventListener('click', () => {
                console.log('[QR Scanner] Analyze button clicked');
                this.analyzeQR();
            });
        }

        if (manualToggle) {
            manualToggle.addEventListener('click', () => this.toggleManualInput());
        }

        if (manualInput) {
            manualInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' && e.ctrlKey) {
                    this.analyzeQR();
                }
            });
        }

        if (exitFullscreen) {
            exitFullscreen.addEventListener('click', () => this.stopCamera());
        }

        document.addEventListener('fullscreenchange', () => {
            if (!document.fullscreenElement && this.isScanning) {
                this.stopCamera();
            }
        });
    },

    getOptimalScanBoxSize() {
        const viewportWidth = window.innerWidth;
        const viewportHeight = window.innerHeight;
        const maxSize = Math.min(viewportWidth * 0.65, 280);
        const minSize = Math.min(viewportWidth * 0.65, 200);
        const size = Math.max(minSize, Math.min(maxSize, 250));
        return { width: size, height: size };
    },

    setupDropZone() {
        const previewArea = document.getElementById('qr-preview-area');
        const fileInput = document.getElementById('qr-file-input');

        if (!previewArea || !fileInput) return;

        previewArea.addEventListener('click', () => fileInput.click());

        previewArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            previewArea.classList.add('drag-over');
        });

        previewArea.addEventListener('dragleave', () => {
            previewArea.classList.remove('drag-over');
        });

        previewArea.addEventListener('drop', (e) => {
            e.preventDefault();
            previewArea.classList.remove('drag-over');
            
            const file = e.dataTransfer.files[0];
            if (file && file.type.startsWith('image/')) {
                this.handleFileSelect(file);
            }
        });

        fileInput.addEventListener('change', (e) => {
            if (e.target.files && e.target.files[0]) {
                this.handleFileSelect(e.target.files[0]);
            }
        });
    },

    triggerFileUpload() {
        const fileInput = document.getElementById('qr-file-input');
        if (fileInput) {
            fileInput.click();
        }
    },

    async handleFileSelect(file) {
        if (!file.type.startsWith('image/')) {
            this.showError('Please select an image file');
            return;
        }

        console.log('[QR Scanner] Processing uploaded image:', file.name, file.size, 'bytes');

        const reader = new FileReader();
        reader.onload = (e) => {
            const imageData = e.target.result;
            
            this.displayPreview(imageData);
            this.setPreviewImage(imageData);
            
            this.showProgress();
            this.setProgressStage(1, 'Decoding QR...');
            
            this.decodeAndAnalyzeImage(imageData);
        };
        reader.onerror = () => {
            this.showError('Failed to read the image file. Please try again.');
        };
        reader.readAsDataURL(file);
    },

    async decodeAndAnalyzeImage(imageData) {
        try {
            const base64 = imageData.includes(',') ? imageData.split(',')[1] : imageData;
            
            this.showProgress();
            this.setProgressStage(1, 'Decoding QR...');
            
            const response = await fetch('/api/scan_qr', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ qr_image: base64 })
            });
            
            const data = await response.json();
            
            if (data.success && data.content) {
                this.setProgressStage(2, 'Analyzing...');
                this.completeProgress();
                this.displayQRContent(data);
            } else if (data.success && !data.content) {
                this.completeProgress();
                this.showError('No QR code found in the image. Please try a clearer image.');
            } else {
                this.completeProgress();
                this.showError(data.error || 'Could not decode QR code. Please try a clearer image.');
            }
        } catch (err) {
            console.error('[QR Scanner] Error:', err);
            this.hideProgress();
            this.showError('Failed to analyze QR code. Please try again.');
        }
    },

    displayPreview(imageData) {
        const previewArea = document.getElementById('qr-preview-area');
        const previewImage = document.getElementById('qr-preview-image');
        const previewText = document.getElementById('qr-preview-text');

        if (previewImage) {
            previewImage.src = imageData;
            previewImage.style.display = 'block';
        }

        if (previewText) {
            previewText.textContent = 'QR code image loaded';
        }

        if (previewArea) {
            previewArea.classList.add('has-image');
        }
    },

    setPreviewImage(imageData) {
        this.previewImageData = imageData;
    },

    async decodeQRFromImageFile(file) {
        return new Promise((resolve) => {
            const reader = new FileReader();
            reader.onload = (e) => {
                const img = new Image();
                img.onload = () => {
                    try {
                        const canvas = document.createElement('canvas');
                        canvas.width = img.width;
                        canvas.height = img.height;
                        const ctx = canvas.getContext('2d');
                        ctx.drawImage(img, 0, 0);
                        
                        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                        
                        if (typeof jsQR === 'function') {
                            const code = jsQR(imageData.data, imageData.width, imageData.height);
                            if (code && code.data) {
                                console.log('[QR Scanner] QR decoded:', code.data);
                                resolve(code.data);
                                return;
                            }
                        }
                        
                        resolve(null);
                    } catch (err) {
                        console.error('[QR Scanner] Client-side decode error:', err);
                        resolve(null);
                    }
                };
                img.onerror = () => {
                    console.error('[QR Scanner] Failed to load image');
                    resolve(null);
                };
                img.src = e.target.result;
            };
            reader.onerror = () => {
                console.error('[QR Scanner] Failed to read file');
                resolve(null);
            };
            reader.readAsDataURL(file);
        });
    },

    async toggleCamera() {
        const cameraBtn = document.getElementById('qr-camera-btn');
        const cameraSection = document.getElementById('qr-camera-section');
        const previewArea = document.getElementById('qr-preview-area');

        if (this.isScanning) {
            await this.stopCamera();
            cameraBtn.innerHTML = '<i class="bx bx-camera"></i> Start Camera';
            cameraBtn.classList.remove('active');
            cameraSection.style.display = 'none';
            previewArea.style.display = 'flex';
        } else {
            cameraSection.style.display = 'block';
            previewArea.style.display = 'none';
            cameraBtn.innerHTML = '<i class="bx bx-stop"></i> Stop Camera';
            cameraBtn.classList.add('active');
            
            await this.startCameraScanner();
        }
    },

    async startCameraScanner() {
        const instruction = document.getElementById('qr-scan-instruction');
        const cameraWrapper = document.querySelector('.qr-camera-wrapper');
        const scanOverlay = document.querySelector('.qr-scan-overlay');
        
        if (!window.Html5Qrcode) {
            console.error('Html5Qrcode library not loaded');
            this.onCameraError({ message: 'Scanner library not loaded. Please refresh the page.' });
            return;
        }

        this.html5QrCode = new Html5Qrcode("qr-reader");
        
        const scanBoxSize = this.getOptimalScanBoxSize();
        
        const config = {
            fps: 20,
            qrbox: scanBoxSize,
            aspectRatio: 1.0,
            disableFlip: false,
            experimentalFeatures: {
                useBarCodeDetectorIfSupported: false
            },
            videoConstraints: {
                facingMode: { ideal: "environment" },
                width: { ideal: 1280, min: 640 },
                height: { ideal: 720, min: 480 },
                aspectRatio: { ideal: 1.0, min: 0.75, max: 1.5 }
            }
        };

        try {
            const cameras = await Html5Qrcode.getCameras();
            
            if (cameras && cameras.length) {
                let cameraId = cameras[0].id;
                
                const backCamera = cameras.find(c => 
                    c.label.toLowerCase().includes('back') ||
                    c.label.toLowerCase().includes('rear') ||
                    c.label.toLowerCase().includes('environment')
                );
                
                if (backCamera) {
                    cameraId = backCamera.id;
                    console.log('[QR Scanner] Selected back camera:', backCamera.label);
                }

                console.log('[QR Scanner] Starting camera:', cameraId);

                await this.html5QrCode.start(
                    cameraId,
                    config,
                    (decodedText) => this.onScanSuccess(decodedText),
                    (errorMessage) => this.onScanFailure(errorMessage)
                );

                this.isScanning = true;
                this.zoomApplied = false;
                this.lastScanTime = Date.now();

                if (scanOverlay) {
                    scanOverlay.classList.add('scanning');
                }

                if (instruction) {
                    instruction.textContent = 'Align QR code inside the box';
                    instruction.className = 'qr-scan-instruction';
                }

                if (cameraWrapper) {
                    cameraWrapper.classList.add('camera-active');
                }

                if (this.isMobile()) {
                    this.requestFullscreen(cameraWrapper);
                    this.lockOrientation();
                }

                this.applyZoomAfterDelay();

                this.scanTimeout = setTimeout(() => {
                    if (this.isScanning) {
                        this.updateGuidance('Unable to detect QR. Try better lighting or upload image.', 'warning');
                    }
                }, 15000);

            } else {
                throw new Error('No cameras found');
            }

        } catch (err) {
            console.error('[QR Scanner] Camera error:', err);
            this.onCameraError(err);
        }
    },

    requestFullscreen(element) {
        if (element && element.requestFullscreen) {
            element.requestFullscreen().catch(() => {
                console.log('[QR Scanner] Fullscreen not available');
            });
        }
    },

    lockOrientation() {
        if (screen.orientation && screen.orientation.lock) {
            screen.orientation.lock('portrait').catch(() => {
                console.log('[QR Scanner] Orientation lock not supported');
            });
        }
    },

    applyZoomAfterDelay() {
        setTimeout(() => {
            if (this.isScanning && !this.zoomApplied) {
                const video = document.querySelector('#qr-reader video');
                if (video) {
                    video.style.transform = 'scale(1.3)';
                    video.style.transformOrigin = 'center center';
                    this.zoomApplied = true;
                    this.updateGuidance('Move closer for better detection', 'warning');
                }
            }
        }, 5000);
    },

    updateGuidance(message, type = 'default') {
        const instruction = document.getElementById('qr-scan-instruction');
        if (!instruction) return;

        instruction.textContent = message;
        instruction.className = 'qr-scan-instruction';
        
        if (type === 'warning') {
            instruction.classList.add('guidance-warning');
        } else if (type === 'success') {
            instruction.classList.add('guidance-success');
        } else if (type === 'scanning') {
            instruction.classList.add('guidance-scanning');
        }
    },

    vibrate() {
        if ('vibrate' in navigator) {
            navigator.vibrate(100);
        }
    },

    onScanSuccess(decodedText) {
        const timeSinceLastScan = Date.now() - this.lastScanTime;
        if (timeSinceLastScan < 1000) {
            return;
        }
        this.lastScanTime = Date.now();

        console.log('[QR Scanner] QR detected:', decodedText);
        
        clearTimeout(this.scanTimeout);
        
        this.updateGuidance('✓ QR Detected!', 'success');
        this.vibrate();
        this.flashScanSuccess();
        
        setTimeout(async () => {
            await this.stopCamera();
            
            // Analyze the QR content
            try {
                this.showProgress();
                this.setProgressStage(1, 'Analyzing...');
                
                const response = await fetch('/api/scan_qr', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ qr_content: decodedText })
                });
                
                const data = await response.json();
                this.completeProgress();
                
                if (data.success) {
                    this.displayQRContent(data);
                } else {
                    this.showError(data.error || 'Failed to analyze QR code');
                }
            } catch (err) {
                this.hideProgress();
                this.showError('Failed to analyze QR code');
            }
        }, 500);
    },

    onScanFailure(errorMessage) {
        // Ignore scan failures during continuous scanning
        // This is normal - QR codes take time to be detected
    },

    flashScanSuccess() {
        const reader = document.getElementById('qr-reader');
        const scanOverlay = document.querySelector('.qr-scan-overlay');
        const cameraWrapper = document.querySelector('.qr-camera-wrapper');
        
        if (reader) {
            reader.classList.add('scan-success');
        }
        
        if (scanOverlay) {
            scanOverlay.classList.add('scan-success');
        }
        
        if (cameraWrapper) {
            cameraWrapper.classList.add('scan-success');
        }
        
        setTimeout(() => {
            if (reader) reader.classList.remove('scan-success');
            if (scanOverlay) scanOverlay.classList.remove('scan-success');
            if (cameraWrapper) cameraWrapper.classList.remove('scan-success');
        }, 600);
    },

    async stopCamera() {
        clearTimeout(this.scanTimeout);
        
        if (this.html5QrCode) {
            try {
                const state = this.html5QrCode.getState();
                if (state === 2) {
                    await this.html5QrCode.stop();
                }
            } catch (e) {
                console.log('[QR Scanner] Camera stop error:', e);
            }
            this.html5QrCode.clear();
            this.html5QrCode = null;
        }
        
        this.isScanning = false;
        this.zoomApplied = false;
        
        if (document.fullscreenElement) {
            document.exitFullscreen().catch(() => {});
        }
        
        if (screen.orientation && screen.orientation.unlock) {
            screen.orientation.unlock();
        }
        
        const scanOverlay = document.querySelector('.qr-scan-overlay');
        const cameraWrapper = document.querySelector('.qr-camera-wrapper');
        const video = document.querySelector('#qr-reader video');
        
        if (scanOverlay) {
            scanOverlay.classList.remove('scanning', 'scan-success');
        }
        if (cameraWrapper) {
            cameraWrapper.classList.remove('camera-active', 'scan-success');
        }
        if (video) {
            video.style.transform = '';
        }
        
        const instruction = document.getElementById('qr-scan-instruction');
        if (instruction) {
            instruction.textContent = 'Align QR code inside the box';
            instruction.className = 'qr-scan-instruction';
        }
    },

    onCameraError(err) {
        this.isScanning = false;
        
        const cameraSection = document.getElementById('qr-camera-section');
        const cameraBtn = document.getElementById('qr-camera-btn');
        const previewArea = document.getElementById('qr-preview-area');
        
        if (cameraSection) cameraSection.style.display = 'none';
        if (cameraBtn) {
            cameraBtn.innerHTML = '<i class="bx bx-camera"></i> Start Camera';
            cameraBtn.classList.remove('active');
        }
        if (previewArea) previewArea.style.display = 'flex';
        
        let errorMsg = 'Camera not available. Please use image upload instead.';
        if (err.message && err.message.includes('Permission')) {
            errorMsg = 'Camera permission denied. Please allow camera access or use image upload.';
        } else if (err.message && err.message.includes('NotFoundError')) {
            errorMsg = 'No camera found. Please connect a camera or use image upload.';
        }
        
        this.showError(errorMsg);
    },

    displayQRContent(data) {
        const previewArea = document.getElementById('qr-preview-area');
        const previewText = document.getElementById('qr-preview-text');

        if (previewArea) {
            previewArea.classList.add('has-image');
        }

        // Update preview text if no image is shown
        if (previewText && data.content && !this.previewImageData) {
            previewText.innerHTML = `<strong>QR Content:</strong><br><code style="word-break: break-all; font-size: 0.85rem;">${this.escapeHtml(data.content.substring(0, 100))}${data.content.length > 100 ? '...' : ''}</code>`;
        }

        // Display results directly (no duplicate API call)
        this.displayResults(data);
    },

    toggleManualInput() {
        const manualSection = document.getElementById('qr-manual-section');
        const manualInput = document.getElementById('qr-manual-input');
        const toggleBtn = document.getElementById('qr-manual-toggle');

        if (manualSection.style.display === 'none' || !manualSection.style.display) {
            manualSection.style.display = 'block';
            if (manualInput) manualInput.focus();
            if (toggleBtn) toggleBtn.innerHTML = '<i class="bx bx-hide"></i> Hide Manual Input';
        } else {
            manualSection.style.display = 'none';
            if (toggleBtn) toggleBtn.innerHTML = '<i class="bx bx-edit"></i> Enter Manually';
        }
    },

    async analyzeQR(manualContent = null) {
        const manualInput = document.getElementById('qr-manual-input');
        let qrContent = manualContent;

        if (!qrContent) {
            qrContent = manualInput ? manualInput.value.trim() : '';
        }

        console.log('[QR Scanner] analyzeQR called', { qrContent, previewImageData: !!this.previewImageData });

        if (!qrContent && !this.previewImageData) {
            this.showError('Please upload a QR code image or enter content manually');
            return;
        }

        this.showProgress();

        const isImage = !!this.previewImageData;
        let response;

        try {
            await this.animateProgress();

            console.log('[QR Scanner] Sending request to /api/scan_qr');

            if (isImage) {
                // Use FormData for images (handles large base64 data better)
                const base64Data = this.previewImageData.includes(',') 
                    ? this.previewImageData.split(',')[1] 
                    : this.previewImageData;
                
                console.log('[QR Scanner] Sending image data, length:', base64Data.length);
                
                const formData = new FormData();
                formData.append('qr_image', base64Data);
                
                response = await fetch('/api/scan_qr', {
                    method: 'POST',
                    body: formData
                });
            } else {
                // Use JSON for text content
                console.log('[QR Scanner] Sending text content:', qrContent);
                
                response = await fetch('/api/scan_qr', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ qr_content: qrContent })
                });
            }

            console.log('[QR Scanner] Response status:', response.status);

            const data = await response.json();
            console.log('[QR Scanner] Response data:', data);

            this.completeProgress();

            // Handle both successful scans and "no QR found" responses
            if (!data.success) {
                this.hideProgress();
                this.showError(data.error || 'Could not analyze QR code');
                return;
            }

            setTimeout(() => {
                this.displayResults(data);
            }, 300);

        } catch (err) {
            console.error('[QR Scanner] Scan error:', err);
            this.hideProgress();
            this.showError('Failed to analyze QR code: ' + err.message);
        }
    },

    showProgress() {
        const progressEl = document.getElementById('qr-scan-progress');
        if (!progressEl) return;

        progressEl.classList.add('active');
        const stages = progressEl.querySelectorAll('.qr-scan-stage');
        stages.forEach((stage, index) => {
            setTimeout(() => {
                stage.classList.add('active');
            }, index * 500);
        });
    },

    setProgressStage(stageIndex, text) {
        const progressEl = document.getElementById('qr-scan-progress');
        if (!progressEl) return;

        const stages = progressEl.querySelectorAll('.qr-scan-stage');
        stages.forEach((stage, index) => {
            stage.classList.remove('active', 'completed');
            if (index < stageIndex) {
                stage.classList.add('completed');
            } else if (index === stageIndex) {
                stage.classList.add('active');
                const textEl = stage.querySelector('.qr-scan-stage-text');
                if (textEl) textEl.textContent = text;
            }
        });
    },

    async animateProgress() {
        const progressEl = document.getElementById('qr-scan-progress');
        if (!progressEl) return;

        const stages = progressEl.querySelectorAll('.qr-scan-stage');
        
        for (let i = 0; i < stages.length; i++) {
            stages[i].classList.add('active');
            stages[i].classList.remove('completed');
            await this.sleep(600);
        }
    },

    completeProgress() {
        const progressEl = document.getElementById('qr-scan-progress');
        if (!progressEl) return;

        const stages = progressEl.querySelectorAll('.qr-scan-stage');
        stages.forEach(stage => {
            stage.classList.remove('active');
            stage.classList.add('completed');
        });

        setTimeout(() => {
            progressEl.classList.remove('active');
        }, 500);
    },

    hideProgress() {
        const progressEl = document.getElementById('qr-scan-progress');
        if (progressEl) {
            progressEl.classList.remove('active');
        }
    },

    displayResults(data) {
        const previewArea = document.getElementById('qr-preview-area');
        const resultsContainer = document.getElementById('qr-results-container');
        const resultsContent = document.getElementById('qr-results-content');

        if (!resultsContainer || !resultsContent) return;

        // Remove existing results if any
        const existingResults = document.querySelector('.qr-inline-results');
        if (existingResults) {
            existingResults.remove();
        }

        const html = this.buildResultsHTML(data);
        
        // Insert results directly after preview area
        if (previewArea) {
            previewArea.insertAdjacentHTML('afterend', html);
        } else {
            resultsContent.innerHTML = html;
            resultsContainer.classList.add('active');
        }

        // Scroll to results smoothly
        const newResults = document.querySelector('.qr-inline-results');
        if (newResults) {
            newResults.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }

        // Don't clear previewImageData - keep image visible
    },

    buildResultsHTML(data) {
        const riskLevel = data.risk_level || 'Safe';
        const riskScore = data.risk_score || 0;
        
        let icon, badgeClass, iconClass;
        
        if (riskLevel === 'Phishing') {
            icon = 'bxs-x-circle';
            badgeClass = 'phishing';
            iconClass = 'phishing';
        } else if (riskLevel === 'Suspicious') {
            icon = 'bx-error';
            badgeClass = 'suspicious';
            iconClass = 'suspicious';
        } else {
            icon = 'bx-check-circle';
            badgeClass = 'safe';
            iconClass = 'safe';
        }

        let qrTypeLabel = this.getQRTypeLabel(data.qr_type);
        
        let contentPreview = '';
        if (data.content) {
            if (data.content.length > 100) {
                contentPreview = this.escapeHtml(data.content.substring(0, 100)) + '...';
            } else {
                contentPreview = this.escapeHtml(data.content);
            }
        }

        let detailsSection = '';

        if (data.qr_type === 'upi' && data.upi_details) {
            const upi = data.upi_details;
            detailsSection = `
                <div class="qr-result-section">
                    <h4 class="qr-section-title"><i class="bx bx-wallet"></i> UPI Payment Details</h4>
                    <div class="qr-info-grid">
                        ${upi.pa ? `<div class="qr-info-item"><div class="qr-info-label">UPI ID</div><div class="qr-info-value">${this.escapeHtml(upi.pa)}</div></div>` : ''}
                        ${upi.pn ? `<div class="qr-info-item"><div class="qr-info-label">Payee Name</div><div class="qr-info-value">${this.escapeHtml(upi.pn)}</div></div>` : ''}
                        ${upi.am ? `<div class="qr-info-item"><div class="qr-info-label">Amount</div><div class="qr-info-value">₹${this.escapeHtml(upi.am)}</div></div>` : ''}
                    </div>
                </div>
            `;
        } else if (data.qr_type === 'url' && data.content) {
            detailsSection = `
                <div class="qr-result-section">
                    <h4 class="qr-section-title"><i class="bx bx-link"></i> URL Details</h4>
                    <div class="qr-detected-content">
                        <div class="qr-detected-label">Detected URL</div>
                        <div class="qr-detected-value">${this.escapeHtml(data.content)}</div>
                    </div>
                </div>
            `;
        }

        let analysisList = '';
        if (data.explanation && data.explanation.length > 0) {
            const items = data.explanation.map(item => {
                let itemClass = 'safe';
                if (item.toLowerCase().includes('suspicious') || 
                    item.toLowerCase().includes('fake') || 
                    item.toLowerCase().includes('warning') ||
                    item.toLowerCase().includes('danger')) {
                    itemClass = 'danger';
                } else if (item.toLowerCase().includes('check') || item.toLowerCase().includes('note')) {
                    itemClass = 'warning';
                }
                
                return `<li class="qr-analysis-item ${itemClass}"><i class='bx ${itemClass === 'safe' ? 'bx-check' : itemClass === 'warning' ? 'bx-alert' : 'bx-x-circle'}'></i><span>${this.escapeHtml(item)}</span></li>`;
            }).join('');
            
            analysisList = `
                <div class="qr-result-section">
                    <h4 class="qr-section-title"><i class="bx bx-search-alt"></i> Analysis</h4>
                    <ul class="qr-analysis-list">${items}</ul>
                </div>
            `;
        }

        let criticalBox = '';
        if (data.critical_flags && data.critical_flags.length > 0) {
            const flags = data.critical_flags.map(flag => `<li>${this.formatCriticalFlag(flag)}</li>`).join('');
            criticalBox = `
                <div class="qr-critical-box">
                    <div class="qr-critical-title"><i class="bx bx-error"></i> Critical Warnings</div>
                    <ul class="qr-critical-list">${flags}</ul>
                </div>
            `;
        }

        let warningsList = '';
        if (data.warnings && data.warnings.length > 0) {
            const warnings = data.warnings.map(w => `<li class="qr-analysis-item warning"><i class='bx bx-alert'></i><span>${this.escapeHtml(w)}</span></li>`).join('');
            warningsList = `
                <div class="qr-result-section">
                    <h4 class="qr-section-title"><i class="bx bx-bell"></i> Warnings</h4>
                    <ul class="qr-analysis-list">${warnings}</ul>
                </div>
            `;
        }

        let riskBarClass = 'low';
        if (riskScore > 69) riskBarClass = 'high';
        else if (riskScore > 30) riskBarClass = 'medium';

        return `
            <div class="qr-inline-results">
                <div class="qr-result-card">
                    <div class="qr-result-header">
                        <div class="qr-result-icon ${iconClass}">
                            <i class='bx ${icon}'></i>
                        </div>
                        <div class="qr-result-badge ${badgeClass}">${riskLevel}</div>
                        <h2 class="qr-result-title">QR Security Report</h2>
                        <p class="qr-result-subtitle">Type: ${qrTypeLabel}</p>
                    </div>
                    
                    <div class="qr-risk-meter">
                        <div class="qr-risk-bar-container">
                            <div class="qr-risk-bar ${riskBarClass}" style="width: ${riskScore}%"></div>
                        </div>
                        <div class="qr-risk-label">
                            <span>Risk Score</span>
                            <strong>${riskScore}/100</strong>
                        </div>
                    </div>
                    
                    ${detailsSection}
                    
                    ${analysisList}
                    
                    ${warningsList}
                    
                    ${criticalBox}
                    
                    ${data.content ? `
                    <div class="qr-result-section">
                        <h4 class="qr-section-title"><i class="bx bx-qr-scan"></i> Raw Content</h4>
                        <div class="qr-detected-content">
                            <div class="qr-detected-value">${this.escapeHtml(data.content)}</div>
                        </div>
                    </div>
                    ` : ''}
                </div>
            </div>
        `;
    },

    getQRTypeLabel(type) {
        const labels = {
            'url': 'URL Link',
            'upi': 'UPI Payment',
            'wifi': 'WiFi Network',
            'sms': 'SMS Command',
            'app': 'App Download',
            'phone': 'Phone Number',
            'email': 'Email Address',
            'geo': 'Location',
            'text': 'Plain Text',
            'unknown': 'Unknown'
        };
        return labels[type] || type;
    },

    formatCriticalFlag(flag) {
        const flagLabels = {
            'PHISHING_URL': 'Phishing URL Detected',
            'FAKE_BRAND_DOMAIN': 'Fake Brand Domain',
            'LOOKALIKE_DOMAIN': 'Lookalike Domain',
            'HTTP_WITH_PAYMENT_KEYWORDS': 'HTTP + Payment Keywords',
            'INVALID_UPI_FORMAT': 'Invalid UPI Format',
            'SUSPICIOUS_UPI_PATTERN': 'Suspicious UPI Pattern',
            'SMS_COMMAND': 'SMS Command Detected',
            'CREDENTIAL_HARVEST': 'Credential Harvesting Pattern'
        };
        return flagLabels[flag] || flag.replace(/_/g, ' ');
    },

    showError(message) {
        const resultsContainer = document.getElementById('qr-results-container');
        const resultsContent = document.getElementById('qr-results-content');

        if (resultsContent) {
            resultsContent.innerHTML = `
                <div class="qr-error-message">
                    <i class="bx bx-error-circle"></i>
                    <p>${this.escapeHtml(message)}</p>
                </div>
            `;
        }

        if (resultsContainer) {
            resultsContainer.classList.add('active');
        }
    },

    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    },

    reset() {
        const previewArea = document.getElementById('qr-preview-area');
        const previewImage = document.getElementById('qr-preview-image');
        const previewText = document.getElementById('qr-preview-text');
        const manualInput = document.getElementById('qr-manual-input');
        const resultsContainer = document.getElementById('qr-results-container');
        const progressEl = document.getElementById('qr-scan-progress');

        if (previewArea) {
            previewArea.classList.remove('has-image');
            previewArea.style.display = 'flex';
        }

        if (previewImage) {
            previewImage.style.display = 'none';
        }

        if (previewText) {
            previewText.textContent = 'Upload QR code image or start camera';
        }

        if (manualInput) {
            manualInput.value = '';
        }

        if (resultsContainer) {
            resultsContainer.classList.remove('active');
        }

        if (progressEl) {
            progressEl.classList.remove('active');
            const stages = progressEl.querySelectorAll('.qr-scan-stage');
            stages.forEach(stage => {
                stage.classList.remove('active', 'completed');
            });
        }

        this.previewImageData = null;
        this.stopCamera();
    }
};

document.addEventListener('DOMContentLoaded', () => {
    QRScanner.init();
});

window.QRScanner = QRScanner;
