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
    nativeStream: null,
    nativeVideoEl: null,
    nativeScanRaf: null,
    nativeDetector: null,
    nativeDetectionPending: false,
    usingNativeScanner: false,
    isScanning: false,
    isStartingCamera: false,
    libraryLoadPromise: null,
    previewImageData: null,
    scanTimeout: null,
    zoomApplied: false,
    lastScanTime: 0,
    activeCameraType: 'default',

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

    async ensureScannerLibraryLoaded() {
        if (window.Html5Qrcode) {
            return true;
        }

        if (this.libraryLoadPromise) {
            return this.libraryLoadPromise;
        }

        const sources = [
            'https://cdn.jsdelivr.net/npm/html5-qrcode@2.3.10/html5-qrcode.min.js',
            'https://unpkg.com/html5-qrcode@2.3.10/html5-qrcode.min.js'
        ];

        this.libraryLoadPromise = (async () => {
            for (const source of sources) {
                try {
                    await this.loadScript(source);
                    if (window.Html5Qrcode) {
                        return true;
                    }
                } catch (err) {
                    console.log('[QR Scanner] Failed to load scanner library from', source, err.message);
                }
            }

            throw new Error('Scanner library not loaded. Please refresh the page.');
        })();

        try {
            return await this.libraryLoadPromise;
        } finally {
            if (!window.Html5Qrcode) {
                this.libraryLoadPromise = null;
            }
        }
    },

    loadScript(src) {
        return new Promise((resolve, reject) => {
            const existingScript = document.querySelector(`script[data-qr-lib="${src}"], script[src="${src}"]`);
            if (existingScript && existingScript.dataset.loaded === 'true') {
                resolve();
                return;
            }

            if (existingScript) {
                existingScript.addEventListener('load', () => resolve(), { once: true });
                existingScript.addEventListener('error', () => reject(new Error(`Failed to load ${src}`)), { once: true });
                return;
            }

            const script = document.createElement('script');
            script.src = src;
            script.async = true;
            script.dataset.qrLib = src;
            script.onload = () => {
                script.dataset.loaded = 'true';
                resolve();
            };
            script.onerror = () => reject(new Error(`Failed to load ${src}`));
            document.head.appendChild(script);
        });
    },

    async hasNativeQrSupport() {
        if (typeof window === 'undefined' || typeof window.BarcodeDetector === 'undefined') {
            return false;
        }

        if (typeof window.BarcodeDetector.getSupportedFormats !== 'function') {
            return true;
        }

        try {
            const formats = await window.BarcodeDetector.getSupportedFormats();
            return Array.isArray(formats) && formats.includes('qr_code');
        } catch (err) {
            console.log('[QR Scanner] Native BarcodeDetector format check failed:', err.message);
            return false;
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

        if (!cameraBtn || !cameraSection || !previewArea || this.isStartingCamera) {
            return;
        }

        if (this.isScanning) {
            await this.stopCamera();
        } else {
            cameraSection.style.display = 'block';
            previewArea.style.display = 'none';
            this.setCameraButtonState('starting');
            
            await this.startCameraScanner();
        }
    },

    async startCameraScanner() {
        const instruction = document.getElementById('qr-scan-instruction');
        const cameraWrapper = document.querySelector('.qr-camera-wrapper');
        const scanOverlay = document.querySelector('.qr-scan-overlay');
        const hasNativeSupport = await this.hasNativeQrSupport();
        let hasHtml5Library = false;

        try {
            await this.ensureScannerLibraryLoaded();
            hasHtml5Library = !!window.Html5Qrcode;
        } catch (libraryError) {
            console.warn('[QR Scanner] Html5Qrcode library unavailable:', libraryError.message);
            if (!hasNativeSupport) {
                this.onCameraError(libraryError);
                return;
            }
        }

        this.isStartingCamera = true;
        this.updateGuidance('Requesting camera access...', 'scanning');
        this.hideProgress();
        this.hideUploadFallback();
        await this.stopCamera({ preserveLayout: true, preserveButtonState: true });

        const isMobileDevice = this.isMobile();
        const scanBoxSize = this.getOptimalScanBoxSize();
        const fps = isMobileDevice ? 12 : 10;
        const qrFormat = typeof Html5QrcodeSupportedFormats !== 'undefined'
            ? Html5QrcodeSupportedFormats.QR_CODE
            : 0;
        
        const config = {
            fps: fps,
            qrbox: scanBoxSize,
            aspectRatio: isMobileDevice ? 1.0 : 1.333334,
            formatsToSupport: [qrFormat],
            rememberLastUsedCamera: true
        };

        if (typeof Html5QrcodeScanType !== 'undefined') {
            config.supportedScanTypes = [Html5QrcodeScanType.SCAN_TYPE_CAMERA];
        }

        try {
            this.ensureCameraSupport();
            await this.primeCameraAccess(isMobileDevice);
            let startResult;

            if (hasHtml5Library) {
                this.html5QrCode = new Html5Qrcode("qr-reader");
                const cameras = await this.getAvailableCameras();
                const selectedCamera = this.selectBestCamera(cameras, isMobileDevice);
                const startCandidates = this.buildStartCandidates(selectedCamera, cameras, isMobileDevice);
                try {
                    startResult = await this.startWithFallback(startCandidates, config);
                } catch (html5StartError) {
                    console.warn('[QR Scanner] Html5Qrcode camera start failed:', html5StartError.message);
                    if (!hasNativeSupport) {
                        throw html5StartError;
                    }

                    await this.stopCamera({ preserveLayout: true, preserveButtonState: true });
                    startResult = await this.startNativeCameraScanner(isMobileDevice);
                }
            } else if (hasNativeSupport) {
                startResult = await this.startNativeCameraScanner(isMobileDevice);
            } else {
                throw new Error('No supported QR scanner backend is available in this browser.');
            }

            this.activeCameraType = startResult.cameraType;

                console.log('[QR Scanner] Camera type:', startResult.cameraType, '| FPS:', fps, '| Device:', isMobileDevice ? 'Mobile' : 'Desktop/Laptop');
                console.log('[QR Scanner] Starting scanner with config:', JSON.stringify(config, null, 2));

                this.isScanning = true;
                this.isStartingCamera = false;
                this.zoomApplied = false;
                this.lastScanTime = Date.now();
                this.setCameraButtonState('active');

                if (scanOverlay) {
                    scanOverlay.classList.add('scanning');
                }

                if (instruction) {
                    if (isMobileDevice) {
                        instruction.textContent = 'Align QR code inside the box';
                    } else {
                        instruction.textContent = 'Hold QR steady • Bring closer • Good lighting helps';
                    }
                    instruction.className = 'qr-scan-instruction';
                }

                if (cameraWrapper) {
                    cameraWrapper.classList.add('camera-active');
                    cameraWrapper.classList.toggle('front-camera', startResult.cameraType === 'front');
                    if (!isMobileDevice) {
                        cameraWrapper.classList.add('laptop-mode');
                        cameraWrapper.dataset.cameraType = startResult.cameraType;
                    }
                }

                if (isMobileDevice) {
                    this.requestFullscreen(cameraWrapper);
                    this.lockOrientation();
                }

                if (!isMobileDevice) {
                    this.applyZoomAfterDelay();
                }

                this.scanTimeout = setTimeout(() => {
                    if (this.isScanning) {
                        this.updateGuidance('Having trouble? Try uploading an image instead.', 'warning');
                        this.showUploadFallback();
                    }
                }, 15000);

        } catch (err) {
            console.error('[QR Scanner] Camera error:', err);
            this.onCameraError(err);
        }
    },

    async primeCameraAccess(isMobileDevice) {
        if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
            return;
        }

        let stream = null;

        try {
            stream = await navigator.mediaDevices.getUserMedia({
                video: {
                    facingMode: { ideal: isMobileDevice ? 'environment' : 'user' }
                },
                audio: false
            });
        } catch (err) {
            // html5-qrcode will surface the final permission/device error during start().
            console.log('[QR Scanner] Camera priming skipped:', err.message);
        } finally {
            if (stream) {
                stream.getTracks().forEach(track => track.stop());
            }
        }
    },

    ensureCameraSupport() {
        if (!window.isSecureContext) {
            const secureError = new Error('Camera access requires a secure context (HTTPS or localhost).');
            secureError.code = 'INSECURE_CONTEXT';
            throw secureError;
        }

        if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
            const mediaError = new Error('This browser does not expose camera APIs.');
            mediaError.code = 'MEDIA_DEVICES_UNAVAILABLE';
            throw mediaError;
        }
    },

    async getAvailableCameras() {
        try {
            const cameras = await Html5Qrcode.getCameras();
            return Array.isArray(cameras) ? cameras : [];
        } catch (err) {
            console.log('[QR Scanner] Camera enumeration failed:', err.message);
            return [];
        }
    },

    selectBestCamera(cameras, isMobileDevice) {
        if (!cameras || !cameras.length) {
            return null;
        }

        const normalizedCameras = cameras.map((camera, index) => ({
            ...camera,
            label: (camera.label || '').toLowerCase(),
            sortIndex: index
        }));

        const environmentHints = ['back', 'rear', 'environment', 'world'];
        const userHints = ['front', 'user', 'face', 'webcam'];

        const preferred = normalizedCameras.find(camera =>
            environmentHints.some(hint => camera.label.includes(hint))
        );
        const secondary = normalizedCameras.find(camera =>
            userHints.some(hint => camera.label.includes(hint))
        );

        const selected = isMobileDevice
            ? (preferred || normalizedCameras[0])
            : (secondary || preferred || normalizedCameras[0]);

        let type = 'default';
        if (preferred && selected.id === preferred.id) {
            type = 'back';
        } else if (secondary && selected.id === secondary.id) {
            type = 'front';
        }

        console.log('[QR Scanner] Available cameras:', normalizedCameras.map(camera => camera.label || `camera-${camera.sortIndex + 1}`));
        console.log('[QR Scanner] Selected camera:', selected.label || selected.id);

        return { id: selected.id, type };
    },

    buildStartCandidates(selectedCamera, cameras, isMobileDevice) {
        const candidates = [];

        if (isMobileDevice) {
            candidates.push({
                label: 'rear-facing camera',
                source: { facingMode: { exact: 'environment' } },
                cameraType: 'back'
            });
            candidates.push({
                label: 'environment camera fallback',
                source: { facingMode: 'environment' },
                cameraType: 'back'
            });
        } else {
            candidates.push({
                label: 'default webcam',
                source: { facingMode: 'user' },
                cameraType: 'front'
            });
        }

        if (selectedCamera && selectedCamera.id) {
            candidates.push({
                label: `named ${selectedCamera.type} camera`,
                source: selectedCamera.id,
                cameraType: selectedCamera.type
            });
        }

        if (cameras && cameras.length) {
            cameras.forEach((camera, index) => {
                if (!camera.id || (selectedCamera && camera.id === selectedCamera.id)) {
                    return;
                }

                candidates.push({
                    label: `camera ${index + 1}`,
                    source: camera.id,
                    cameraType: 'default'
                });
            });
        }

        if (!isMobileDevice) {
            candidates.push({
                label: 'generic camera fallback',
                source: { facingMode: { ideal: 'environment' } },
                cameraType: selectedCamera ? selectedCamera.type : 'default'
            });
        }

        return candidates;
    },

    async startWithFallback(candidates, config) {
        let lastError = null;

        for (const candidate of candidates) {
            try {
                console.log('[QR Scanner] Trying camera candidate:', candidate.label, candidate.source);
                await this.html5QrCode.start(
                    candidate.source,
                    config,
                    (decodedText) => {
                        console.log('[QR Scanner] QR Code detected:', decodedText);
                        this.onScanSuccess(decodedText);
                    },
                    (errorMessage) => {
                        if (!errorMessage.includes('No MultiFormat Readers')) {
                            console.log('[QR Scanner] Scan error (ignored):', errorMessage);
                        }
                    }
                );

                return candidate;
            } catch (err) {
                lastError = err;
                console.log('[QR Scanner] Camera candidate failed:', candidate.label, err.message);

                try {
                    if (this.html5QrCode) {
                        this.html5QrCode.clear();
                    }
                } catch (clearErr) {
                    console.log('[QR Scanner] Scanner clear after failed start:', clearErr.message);
                }
            }
        }

        if (lastError) {
            throw lastError;
        }

        throw new Error('No camera found');
    },

    async startNativeCameraScanner(isMobileDevice) {
        if (!(await this.hasNativeQrSupport())) {
            throw new Error('Native QR detection is not supported in this browser.');
        }

        const reader = document.getElementById('qr-reader');
        if (!reader) {
            throw new Error('QR reader element not found.');
        }

        const detector = new window.BarcodeDetector({ formats: ['qr_code'] });
        const candidates = isMobileDevice
            ? [
                { label: 'rear camera', cameraType: 'back', constraints: { facingMode: { exact: 'environment' } } },
                { label: 'environment fallback', cameraType: 'back', constraints: { facingMode: 'environment' } },
                { label: 'any camera', cameraType: 'default', constraints: true }
            ]
            : [
                { label: 'front camera', cameraType: 'front', constraints: { facingMode: 'user' } },
                { label: 'default camera', cameraType: 'default', constraints: true }
            ];

        let lastError = null;

        for (const candidate of candidates) {
            let stream = null;

            try {
                console.log('[QR Scanner] Trying native camera candidate:', candidate.label);
                stream = await navigator.mediaDevices.getUserMedia({
                    video: candidate.constraints,
                    audio: false
                });

                await this.attachNativeVideoStream(reader, stream);

                this.nativeStream = stream;
                this.nativeDetector = detector;
                this.usingNativeScanner = true;
                this.nativeDetectionPending = false;
                this.scanNativeFrame();

                return { cameraType: candidate.cameraType };
            } catch (err) {
                lastError = err;
                if (stream) {
                    stream.getTracks().forEach(track => track.stop());
                }
                console.log('[QR Scanner] Native camera candidate failed:', candidate.label, err.message);
            }
        }

        throw lastError || new Error('No camera found');
    },

    attachNativeVideoStream(reader, stream) {
        return new Promise((resolve, reject) => {
            reader.innerHTML = '';

            const video = document.createElement('video');
            video.setAttribute('playsinline', 'true');
            video.setAttribute('autoplay', 'true');
            video.setAttribute('muted', 'true');
            video.muted = true;
            video.autoplay = true;
            video.playsInline = true;
            video.srcObject = stream;

            const cleanup = () => {
                video.onloadedmetadata = null;
                video.onerror = null;
            };

            video.onloadedmetadata = async () => {
                try {
                    await video.play();
                    this.nativeVideoEl = video;
                    cleanup();
                    resolve();
                } catch (err) {
                    cleanup();
                    reject(err);
                }
            };

            video.onerror = () => {
                cleanup();
                reject(new Error('Native camera preview failed to start.'));
            };

            reader.appendChild(video);
        });
    },

    scanNativeFrame() {
        if (!this.usingNativeScanner || !this.nativeVideoEl || !this.nativeDetector) {
            return;
        }

        if (this.nativeVideoEl.readyState < 2) {
            this.nativeScanRaf = window.requestAnimationFrame(() => this.scanNativeFrame());
            return;
        }

        if (this.nativeDetectionPending) {
            this.nativeScanRaf = window.requestAnimationFrame(() => this.scanNativeFrame());
            return;
        }

        this.nativeDetectionPending = true;

        this.nativeDetector.detect(this.nativeVideoEl)
            .then(codes => {
                if (codes && codes.length) {
                    const firstCode = codes.find(code => code.rawValue);
                    if (firstCode && firstCode.rawValue) {
                        this.onScanSuccess(firstCode.rawValue);
                        return;
                    }
                }

                this.nativeScanRaf = window.requestAnimationFrame(() => this.scanNativeFrame());
            })
            .catch(err => {
                console.log('[QR Scanner] Native detection error:', err.message);
                this.nativeScanRaf = window.requestAnimationFrame(() => this.scanNativeFrame());
            })
            .finally(() => {
                this.nativeDetectionPending = false;
            });
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

    showUploadFallback() {
        const uploadBtn = document.getElementById('qr-upload-btn');
        if (uploadBtn) {
            uploadBtn.classList.add('pulse-upload');
            uploadBtn.style.display = 'inline-flex';
        }
    },

    hideUploadFallback() {
        const uploadBtn = document.getElementById('qr-upload-btn');
        if (uploadBtn) {
            uploadBtn.classList.remove('pulse-upload');
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

    async stopCamera(options = {}) {
        const {
            preserveLayout = false,
            preserveButtonState = false
        } = options;

        clearTimeout(this.scanTimeout);
        
        if (this.html5QrCode) {
            try {
                const state = this.html5QrCode.getState();
                if (state !== 1) {
                    await this.html5QrCode.stop();
                }
            } catch (e) {
                console.log('[QR Scanner] Camera stop error:', e);
            }
            this.html5QrCode.clear();
            this.html5QrCode = null;
        }

        if (this.nativeScanRaf) {
            cancelAnimationFrame(this.nativeScanRaf);
            this.nativeScanRaf = null;
        }

        if (this.nativeVideoEl) {
            try {
                this.nativeVideoEl.pause();
            } catch (e) {}
            this.nativeVideoEl.srcObject = null;
            this.nativeVideoEl.remove();
            this.nativeVideoEl = null;
        }

        if (this.nativeStream) {
            this.nativeStream.getTracks().forEach(track => track.stop());
            this.nativeStream = null;
        }

        this.nativeDetector = null;
        this.nativeDetectionPending = false;
        this.usingNativeScanner = false;
        
        this.isScanning = false;
        this.isStartingCamera = false;
        this.zoomApplied = false;
        this.activeCameraType = 'default';
        
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
            cameraWrapper.classList.remove('camera-active', 'scan-success', 'laptop-mode', 'front-camera');
            delete cameraWrapper.dataset.cameraType;
        }
        if (video) {
            video.style.transform = '';
        }
        
        this.hideUploadFallback();
        
        const instruction = document.getElementById('qr-scan-instruction');
        if (instruction) {
            instruction.textContent = 'Align QR code inside the box';
            instruction.className = 'qr-scan-instruction';
        }

        if (!preserveButtonState) {
            this.setCameraButtonState('idle');
        }

        const cameraSection = document.getElementById('qr-camera-section');
        const previewArea = document.getElementById('qr-preview-area');

        if (cameraSection && !preserveLayout) {
            cameraSection.style.display = 'none';
        }
        if (previewArea && !preserveLayout) {
            previewArea.style.display = 'flex';
        }
    },

    onCameraError(err) {
        this.stopCamera();
        this.isScanning = false;
        
        this.hideUploadFallback();
        
        const cameraSection = document.getElementById('qr-camera-section');
        const cameraBtn = document.getElementById('qr-camera-btn');
        const previewArea = document.getElementById('qr-preview-area');
        
        if (cameraSection) cameraSection.style.display = 'none';
        if (cameraBtn) {
            cameraBtn.innerHTML = '<i class="bx bx-camera"></i> Start Camera';
            cameraBtn.classList.remove('active');
        }
        if (previewArea) previewArea.style.display = 'flex';
        
        this.showError(
            this.getCameraErrorMessage(err),
            this.buildCameraErrorDetails(err)
        );
    },

    getCameraErrorMessage(err) {
        const errorText = `${err && err.name ? err.name : ''} ${err && err.message ? err.message : ''}`.toLowerCase();

        if (err && err.code === 'INSECURE_CONTEXT') {
            return 'Camera access requires HTTPS or localhost. Open this site on https:// or on http://localhost and try again.';
        }

        if (err && err.code === 'MEDIA_DEVICES_UNAVAILABLE') {
            return 'This browser does not expose camera access. Use Chrome, Edge, or Safari, or upload a QR image instead.';
        }

        if (
            errorText.includes('permission') ||
            errorText.includes('notallowederror') ||
            errorText.includes('permission denied')
        ) {
            return 'Camera permission was denied. Allow camera access in the browser and try again.';
        }

        if (
            errorText.includes('notfounderror') ||
            errorText.includes('devicesnotfounderror') ||
            errorText.includes('requested device not found')
        ) {
            return 'No camera was found on this device. Connect or enable a camera, or upload a QR image instead.';
        }

        if (
            errorText.includes('notreadableerror') ||
            errorText.includes('trackstarterror') ||
            errorText.includes('could not start video source')
        ) {
            return 'The camera is busy in another app or browser tab. Close other apps using the camera and try again.';
        }

        if (
            errorText.includes('overconstrainederror') ||
            errorText.includes('constraint')
        ) {
            return 'The preferred camera could not be opened on this device. Try again or use image upload instead.';
        }

        if (
            errorText.includes('scanner backend') ||
            errorText.includes('native qr detection is not supported')
        ) {
            return 'This browser cannot start any QR scanning backend. Try Chrome or Edge, or use image upload instead.';
        }

        return 'Camera could not be started. If you opened this page on a network IP over HTTP, switch to HTTPS or localhost. Otherwise try image upload instead.';
    },

    buildCameraErrorDetails(err) {
        const detailParts = [];
        const rawName = err && err.name ? err.name : 'UnknownError';
        const rawMessage = err && err.message ? err.message : 'No browser error message was provided.';

        detailParts.push(`Browser error: ${rawName} - ${rawMessage}`);
        detailParts.push(`Context: ${window.isSecureContext ? 'secure' : 'not secure'}`);
        detailParts.push(`Origin: ${window.location.origin}`);
        detailParts.push(
            `Camera API: ${navigator.mediaDevices && navigator.mediaDevices.getUserMedia ? 'available' : 'unavailable'}`
        );

        return detailParts.join(' | ');
    },

    setCameraButtonState(state) {
        const cameraBtn = document.getElementById('qr-camera-btn');
        if (!cameraBtn) return;

        cameraBtn.disabled = state === 'starting';

        if (state === 'starting') {
            cameraBtn.innerHTML = '<i class="bx bx-loader-alt bx-spin"></i> Starting Camera...';
            cameraBtn.classList.remove('active');
            return;
        }

        if (state === 'active') {
            cameraBtn.innerHTML = '<i class="bx bx-stop"></i> Stop Camera';
            cameraBtn.classList.add('active');
            return;
        }

        cameraBtn.innerHTML = '<i class="bx bx-camera"></i> Start Camera';
        cameraBtn.classList.remove('active');
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

    showError(message, details = '') {
        const resultsContainer = document.getElementById('qr-results-container');
        const resultsContent = document.getElementById('qr-results-content');

        if (resultsContent) {
            resultsContent.innerHTML = `
                <div class="qr-error-message">
                    <i class="bx bx-error-circle"></i>
                    <p>${this.escapeHtml(message)}</p>
                    ${details ? `<small class="qr-error-details">${this.escapeHtml(details)}</small>` : ''}
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
