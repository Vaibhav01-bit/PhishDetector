/**
 * ULTRA-FAST PROGRESSIVE SCAN TIMELINE
 * ─────────────────────────────────────────────────────────────────────────────
 * Architecture:
 *   1. All 6 steps rendered in "pending" state INSTANTLY (t=0)
 *   2. POST /scan/fast  →  layers 1-5 run server-side (no sandbox)
 *   3. Preliminary result card rendered at verdict receipt (~1-2s)
 *   4. Sandbox step stays "active" (spinner); result card visible simultaneously
 *   5. Poll /scan/status/<id> every 1.5s  →  screenshot fades in when ready
 *
 * ZERO artificial sequential delays.
 * ZERO dead time between timeline and result card.
 */

(function () {
    'use strict';

    // ─── DOM refs ─────────────────────────────────────────────────────────────
    const form = document.getElementById('url-scan-form');
    const timelineEl = document.getElementById('scan-timeline');
    const resultCard = document.getElementById('legacy-result-card');

    if (!form || !timelineEl || !resultCard) return;

    // ─── Step metadata ────────────────────────────────────────────────────────
    // "fast" steps update together when /scan/fast resolves.
    // "sandbox" step (index 5) updates independently when polling completes.
    const STEPS = [
        { id: 'step-1', label: 'URL Normalization', desc: 'Resolving and normalizing URL structure...', group: 'fast' },
        { id: 'step-2', label: 'Domain Parsing', desc: 'Analyzing TLD, subdomains and registrar...', group: 'fast' },
        { id: 'step-3', label: 'SSL & Redirect Check', desc: 'Tracing redirect chain and validating HTTPS...', group: 'fast' },
        { id: 'step-4', label: 'Brand Impersonation', desc: 'Detecting fake brand signatures...', group: 'fast' },
        { id: 'step-5', label: 'AI / ML Risk Evaluation', desc: 'Running behavioral neural model...', group: 'fast' },
        { id: 'step-6', label: 'Secure Sandbox Execution', desc: 'Executing in isolated environment...', group: 'sandbox' },
    ];

    // ─── State ────────────────────────────────────────────────────────────────
    let pollingTimer = null;
    let currentScanId = null;
    let pollingAttempts = 0;
    const MAX_POLL = 50; // 50 × 1.5s = 75s max

    // ─── Main Event ───────────────────────────────────────────────────────────
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        clearPolling();

        const formData = new FormData(form);
        const url = formData.get('name');
        if (!url) return;

        // t=0: show timeline, all steps pending
        initTimeline();

        // t=100ms: kick off the fast scan (visually feels instant)
        await sleep(100);

        // Mark all fast steps as "active" together – zero sequential fake delay
        STEPS.filter(s => s.group === 'fast').forEach(s => setActive(s.id));

        // ── Fetch fast verdict ────────────────────────────────────────────────
        let result;
        try {
            const scanFormData = new FormData();
            scanFormData.append('name', url);

            const resp = await fetch('/scan/fast', {
                method: 'POST',
                body: scanFormData
            });

            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            result = await resp.json();
        } catch (err) {
            console.error('[Scanner] /scan/fast failed:', err);
            // Graceful fallback: submit the form the old way
            form.submit();
            return;
        }

        // ── Fast layers done: complete steps 1-5 simultaneously ───────────────
        STEPS.filter(s => s.group === 'fast').forEach(s => setCompleted(s.id));

        // Step 6 stays active (sandbox still running)
        setActive('step-6', 'Executing secure isolated environment…');

        // ── Render preliminary result card (INSTANT — no wait) ───────────────
        currentScanId = result.scan_id;
        pollingAttempts = 0;

        await sleep(120); // just enough for CSS transition to fire on steps
        renderResultCard(result, { preliminary: true });
        showResultCard();

        // ── Begin polling for sandbox ─────────────────────────────────────────
        if (currentScanId) {
            startPolling(currentScanId);
        }
    });


    // ═══════════════════════════════════════════════════════════════════════════
    // TIMELINE HELPERS
    // ═══════════════════════════════════════════════════════════════════════════

    function initTimeline() {
        // Reset result card
        resultCard.style.display = 'none';
        resultCard.classList.remove('result-card-enter');

        // Reset all steps to pending
        STEPS.forEach(s => {
            const el = document.getElementById(s.id);
            if (!el) return;
            el.className = 'scan-step';
            const icon = el.querySelector('.step-icon');
            if (icon) icon.innerHTML = "<i class='bx bx-circle'></i>";
            const desc = el.querySelector('.step-description');
            if (desc) desc.textContent = s.desc;
        });

        // Show timeline
        timelineEl.style.display = 'block';
        timelineEl.style.opacity = '1';
        timelineEl.style.transform = '';
        timelineEl.classList.remove('scan-complete', 'tl-exit');
        timelineEl.classList.add('active-scan');
    }

    function setActive(stepId, customDesc = null) {
        const el = document.getElementById(stepId);
        if (!el) return;
        el.classList.add('active');
        el.classList.remove('completed');
        el.querySelector('.step-icon').innerHTML = "<i class='bx bx-loader-alt bx-spin'></i>";
        if (customDesc) {
            const d = el.querySelector('.step-description');
            if (d) d.textContent = customDesc;
        }
    }

    function setCompleted(stepId, customDesc = null) {
        const el = document.getElementById(stepId);
        if (!el) return;
        el.classList.remove('active');
        el.classList.add('completed');
        el.querySelector('.step-icon').innerHTML = "<i class='bx bx-check'></i>";
        if (customDesc) {
            const d = el.querySelector('.step-description');
            if (d) d.textContent = customDesc;
        }
    }

    function collapseTimeline() {
        timelineEl.classList.remove('active-scan');
        timelineEl.classList.add('tl-exit');
        setTimeout(() => { timelineEl.style.display = 'none'; }, 400);
    }


    // ═══════════════════════════════════════════════════════════════════════════
    // RESULT CARD RENDERING
    // ═══════════════════════════════════════════════════════════════════════════

    function renderResultCard(data, opts = {}) {
        const { preliminary = false } = opts;

        const status = data.status || 'Safe';
        const isSafe = data.is_safe || (status === 'Safe');
        const isWarning = data.is_warning || (status === 'Warning');
        const url = data.url || '';

        // ── URL display ─────────────────────────────────────────────────────
        const urlSpan = resultCard.querySelector('.url-text span');
        if (urlSpan) urlSpan.textContent = url;
        else {
            const urlP = resultCard.querySelector('.url-text');
            if (urlP) urlP.innerHTML = `<i class='bx bx-link-alt me-1'></i>Scanning: <span class="fw-medium">${escHtml(url)}</span>`;
        }

        // ── Verdict icon + heading ────────────────────────────────────────────
        const iconWrapper = resultCard.querySelector('.security-icon');
        const iconI = iconWrapper && iconWrapper.querySelector('i');
        const verdictHead = resultCard.querySelector('.verdict-text');

        if (iconWrapper) {
            iconWrapper.className = 'security-icon';
            if (isSafe) {
                iconWrapper.classList.add('icon-safe');
                if (iconI) iconI.className = 'bx bxs-shield-alt-2';
                if (verdictHead) {
                    verdictHead.textContent = 'This website appears safe';
                    verdictHead.className = 'verdict-text text-success fw-bold mb-0';
                }
            } else if (isWarning) {
                iconWrapper.classList.add('icon-warning');
                if (iconI) iconI.className = 'bx bxs-error-alt';
                if (verdictHead) {
                    verdictHead.textContent = 'Suspicious patterns detected';
                    verdictHead.className = 'verdict-text text-warning fw-bold mb-0';
                }
            } else {
                iconWrapper.classList.add('icon-danger');
                if (iconI) iconI.className = 'bx bxs-shield-x';
                if (verdictHead) {
                    verdictHead.textContent = 'High-risk phishing indicators found';
                    verdictHead.className = 'verdict-text text-danger fw-bold mb-0';
                }
            }
        }

        // ── Sandbox badge (visible during preliminary) ────────────────────────
        injectSandboxBadge(preliminary);

        // ── Screenshot placeholder ─────────────────────────────────────────────
        injectScreenshotFrame();

        // ── Analysis detail list ─────────────────────────────────────────────
        renderAnalysisDetails(data, isSafe);

        // ── CTA buttons ──────────────────────────────────────────────────────
        const secondaryWrapper = resultCard.querySelector('.secondary-cta-wrapper');
        if (secondaryWrapper) {
            if (isSafe) {
                secondaryWrapper.innerHTML = `
                    <button class="btn-proceed-secondary" onclick="window.open('${escHtml(url)}', '_blank')">
                      <i class='bx bx-check-circle me-1'></i> Proceed Safely
                    </button>`;
            } else {
                secondaryWrapper.innerHTML = `
                    <button class="btn-proceed-danger" onclick="window.open('${escHtml(url)}', '_blank')">
                      <i class='bx bx-error-circle me-1'></i> View Anyway (Risk)
                    </button>`;
            }
        }

        // ── Sandbox primary CTA: hide until sandbox is done ──────────────────
        const sandboxCTA = resultCard.querySelector('.primary-cta-wrapper');
        if (sandboxCTA) sandboxCTA.style.display = 'none';
    }

    function injectSandboxBadge(visible) {
        let badge = resultCard.querySelector('#sandbox-progress-badge');
        if (!badge) {
            badge = document.createElement('div');
            badge.id = 'sandbox-progress-badge';
            badge.className = 'sandbox-progress-badge';
            badge.innerHTML = "<i class='bx bx-loader-alt bx-spin me-1'></i>Sandbox analysis in progress…";

            // Insert before CTA section
            const cta = resultCard.querySelector('.cta-section');
            if (cta) cta.insertAdjacentElement('beforebegin', badge);
            else resultCard.appendChild(badge);
        }
        badge.style.display = visible ? 'flex' : 'none';
    }

    function injectScreenshotFrame() {
        if (resultCard.querySelector('#screenshot-frame')) return;
        const frame = document.createElement('div');
        frame.id = 'screenshot-frame';
        frame.className = 'screenshot-frame screenshot-placeholder';
        frame.innerHTML = `
            <div class="screenshot-shimmer">
                <i class='bx bx-image-alt screenshot-icon'></i>
                <span class="screenshot-label">Screenshot loading…</span>
            </div>`;

        const cta = resultCard.querySelector('.cta-section');
        if (cta) cta.insertAdjacentElement('beforebegin', frame);
    }

    function renderAnalysisDetails(data, isSafe) {
        const list = resultCard.querySelector('.risk-analysis ul');
        if (!list) return;
        list.innerHTML = '';

        const layers = data.layers || {};
        const forensics = data.forensics || {};

        const addItem = (cls, icon, label, msg) => {
            const li = document.createElement('li');
            li.className = `mb-2 ${cls}`;
            li.innerHTML = `<i class='bx ${icon}'></i> <strong>${label}:</strong> ${escHtml(msg)}`;
            list.appendChild(li);
        };

        // Forensics
        if (layers.forensics_check && layers.forensics_check.status !== 'Safe') {
            addItem('text-warning', 'bx-search-alt', 'Redirects', layers.forensics_check.message);
        }
        // Domain
        if (layers.layer2 && layers.layer2.status !== 'Safe') {
            addItem('text-warning', 'bx-globe', 'Domain', layers.layer2.message);
        }
        // SSL
        if (layers.layer3 && layers.layer3.status !== 'Safe') {
            addItem('text-warning', 'bx-lock-open-alt', 'SSL', layers.layer3.message);
        }
        // Behavioral
        if (layers.layer5 && layers.layer5.status !== 'Safe') {
            addItem('text-warning', 'bx-radar', 'Behavior', layers.layer5.message);
        }
        // AI
        if (layers.layer4 && layers.layer4.status === 'Phishing') {
            addItem('text-danger', 'bx-brain', 'AI Detection', 'High confidence phishing pattern detected.');
        }

        // Trust signals if safe
        if (isSafe) {
            addItem('text-success', 'bx-check-shield', 'Domain', 'No obvious brand impersonation detected.');
            addItem('text-success', 'bx-lock-alt', 'SSL', 'Valid HTTPS connection.');
            addItem('text-success', 'bx-data', 'Reputation', 'Not found in active blacklists.');
        }

        // Redirect chain
        const chain = forensics.redirect_chain;
        const chainContainer = resultCard.querySelector('.redirect-chain');
        if (chain && chain.length > 1) {
            if (!chainContainer) {
                const div = document.createElement('div');
                div.className = 'redirect-chain mt-3 pt-3 border-top border-secondary';
                const inner = chain.map((h, i) => `
                    <div class="chain-node py-1" style="font-size:.85rem">
                      <span class="${i === chain.length - 1 ? 'text-success font-weight-bold' : 'text-muted'}">
                        ${escHtml((h.url || '').substring(0, 50))}${(h.url || '').length > 50 ? '…' : ''}
                      </span>
                      ${i < chain.length - 1 ? "<div class='text-muted small'><i class='bx bx-down-arrow-alt'></i></div>" : ''}
                    </div>`).join('');
                div.innerHTML = `<h6 class="section-header mb-2" style="font-size:.85rem"><i class='bx bx-git-branch'></i> Redirect Path:</h6>
                    <div class="chain-visual pl-2" style="border-left:2px solid rgba(59,130,246,.3)">${inner}</div>`;
                list.closest('.risk-analysis').appendChild(div);
            }
        }
    }

    function showResultCard() {
        resultCard.style.display = 'block';
        resultCard.classList.add('result-card-enter');
        // Smooth scroll
        setTimeout(() => resultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 50);
    }


    // ═══════════════════════════════════════════════════════════════════════════
    // SANDBOX POLLING
    // ═══════════════════════════════════════════════════════════════════════════

    function startPolling(scanId) {
        console.log('[Scanner] Starting polling for scan:', scanId);
        pollingTimer = setInterval(async () => {
            pollingAttempts++;
            
            console.log('[Scanner] Polling attempt:', pollingAttempts);

            if (pollingAttempts > MAX_POLL) {
                clearPolling();
                finalizeSandboxTimeout();
                return;
            }

            try {
                const resp = await fetch(`/scan/status/${scanId}`);
                if (!resp.ok) {
                    console.warn('[Scanner] Poll response not OK:', resp.status);
                    return;
                }
                const status = await resp.json();
                console.log('[Scanner] Poll status:', status);

                if (status.done) {
                    clearPolling();
                    onSandboxComplete(status);
                }
            } catch (err) {
                console.warn('[Scanner] polling error:', err);
            }
        }, 1500);
    }

    function clearPolling() {
        if (pollingTimer) {
            clearInterval(pollingTimer);
            pollingTimer = null;
        }
    }

    function onSandboxComplete(status) {
        console.log('[Scanner] Sandbox complete:', status);
        console.log('[Scanner] currentScanId:', currentScanId);

        // Update step 6
        if (status.success) {
            setCompleted('step-6', 'Sandbox execution complete ✓');
        } else {
            const el = document.getElementById('step-6');
            if (el) {
                el.classList.remove('active');
                el.classList.add('step-error');
                el.querySelector('.step-icon').innerHTML = "<i class='bx bx-x'></i>";
                const d = el.querySelector('.step-description');
                if (d) d.textContent = status.error ? 'Sandbox unavailable: ' + status.error.substring(0, 60) : 'Sandbox unavailable for this URL.';
            }
        }

        // Collapse timeline after sandbox completes
        setTimeout(collapseTimeline, 600);

        // Hide sandbox badge
        const badge = resultCard.querySelector('#sandbox-progress-badge');
        if (badge) {
            badge.classList.add('badge-fadeout');
            setTimeout(() => badge.remove(), 400);
        }

        // Reveal screenshot (now Base64 data instead of file URL)
        if (status.screenshot) {
            revealScreenshot(status.screenshot);
        } else {
            removeScreenshotFrame();
        }

        // ── Show sandbox CTA button ─────────────────────────────────────────
        // Button now opens the sandbox details page
        const sandboxCTA = resultCard.querySelector('.primary-cta-wrapper');
        
        // Get scan_id - use either from status or from the initial scan
        const scanId = status.scan_id || currentScanId;
        
        // Store all sandbox data
        window.latestSandboxData = {
            screenshot: status.screenshot,
            sourceUrl: status.source_url,
            finalUrl: status.final_url,
            ipAddress: status.ip_address,
            domain: status.domain,
            pageTitle: status.page_title,
            redirectCount: status.redirect_count,
            loadTime: status.load_time,
            timestamp: status.timestamp,
            hasLoginForm: status.has_login_form,
            hasPasswordField: status.has_password_field,
            hasEmailField: status.has_email_field,
            suspiciousKeywords: status.suspicious_keywords || [],
            sandboxMessage: status.sandbox_message,
            scanId: scanId,
            layers: status.layers,
            forensics: status.forensics,
            finalStatus: status.final_status
        };
        
        console.log('[Scanner] sandboxCTA found:', !!sandboxCTA);
        console.log('[Scanner] status.success:', status.success);
        console.log('[Scanner] scanId:', scanId);
        console.log('[Scanner] status.screenshot exists:', !!status.screenshot);
        
        // Show button when we have a scanId (even if sandbox failed, user can still view partial results)
        const shouldShowButton = scanId && status.done;
        
        if (sandboxCTA && shouldShowButton) {
            // Show button to view sandbox details page (even if partially failed)
            const statusIcon = status.success ? 'bx-check-circle' : 'bx-info-circle';
            const statusLabel = status.success ? 'View Sandbox Analysis' : 'View Scan Details';
            
            sandboxCTA.innerHTML = `
                <a href="/sandbox/${scanId}" class="btn-sandbox-primary">
                    <span>${statusLabel}</span>
                    <i class='bx bx-right-arrow-alt'></i>
                </a>
                <p class="sandbox-caption mt-2 mb-0 text-center">
                    <i class='bx bxs-lock-alt'></i>
                    Secure sandbox environment &bull; No user interaction performed
                </p>`;
            sandboxCTA.style.display = 'block';
            sandboxCTA.classList.add('cta-fade-in');
            console.log('[Scanner] Button HTML set for scan ID:', scanId);
        } else if (sandboxCTA && !status.done) {
            // Sandbox failed - show error message
            console.log('[Scanner] Sandbox failed, showing error');
            sandboxCTA.innerHTML = `
                <p class="text-center mb-0" style="font-size:.82rem;opacity:.7">
                    <i class='bx bx-info-circle'></i>
                    Sandbox analysis unavailable for this URL.
                </p>`;
            sandboxCTA.style.display = 'block';
        } else if (sandboxCTA && !scanId) {
            console.log('[Scanner] WARNING: No scanId available');
        }
    }

    function revealScreenshot(url) {
        const frame = resultCard.querySelector('#screenshot-frame');
        if (!frame) return;

        const img = new Image();
        img.onload = () => {
            frame.className = 'screenshot-frame screenshot-loaded';
            frame.innerHTML = '';
            img.className = 'screenshot-img';
            frame.appendChild(img);
        };
        img.onerror = () => removeScreenshotFrame();
        img.src = url;
    }

    function removeScreenshotFrame() {
        const frame = resultCard.querySelector('#screenshot-frame');
        if (frame) {
            frame.classList.add('frame-fadeout');
            setTimeout(() => frame.remove(), 300);
        }
    }

    function finalizeSandboxTimeout() {
        setCompleted('step-6', 'Sandbox analysis timed out.');
        collapseTimeline();
        const badge = resultCard.querySelector('#sandbox-progress-badge');
        if (badge) badge.remove();
        removeScreenshotFrame();
    }


    // ═══════════════════════════════════════════════════════════════════════════
    // UTILS
    // ═══════════════════════════════════════════════════════════════════════════

    function sleep(ms) {
        return new Promise(r => setTimeout(r, ms));
    }

    function escHtml(str) {
        const div = document.createElement('div');
        div.appendChild(document.createTextNode(str || ''));
        return div.innerHTML;
    }

    // Global function to show sandbox modal
    window.showSandboxModal = function() {
        const data = window.latestSandboxData;
        if (!data || !data.screenshot) {
            alert('Sandbox data not available');
            return;
        }
        
        const d = document;
        
        const modal = d.createElement('div');
        modal.className = 'sandbox-modal';
        modal.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.85);
            z-index: 10000;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            box-sizing: border-box;
            overflow-y: auto;
        `;
        
        const getStatusColor = (status) => {
            if (status === 'Safe') return '#4caf50';
            if (status === 'Warning') return '#ffa500';
            return '#f44336';
        };
        
        const getStatusIcon = (status) => {
            if (status === 'Safe') return 'bxs-shield-check';
            if (status === 'Warning') return 'bx-error';
            return 'bxs-shield-x';
        };
        
        const statusColor = getStatusColor(data.finalStatus || 'Safe');
        const statusIcon = getStatusIcon(data.finalStatus || 'Safe');
        
        // Build layers HTML
        let layersHtml = '';
        if (data.layers) {
            const layerNames = ['layer1', 'layer2', 'layer3', 'layer4', 'layer5'];
            const layerTitles = ['Blacklist Check', 'Domain Analysis', 'SSL Certificate', 'ML Model', 'Behavioral Analysis'];
            
            layerNames.forEach((layer, idx) => {
                if (data.layers[layer]) {
                    const layerStatus = data.layers[layer].status || 'Safe';
                    const layerColor = getStatusColor(layerStatus);
                    const layerIcon = getStatusIcon(layerStatus);
                    layersHtml += `
                        <div style="padding: 12px; margin-bottom: 8px; background: rgba(255,255,255,0.05); border-radius: 8px; border-left: 3px solid ${layerColor};">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <span style="font-weight: 600; color: #fff;">${idx + 1}. ${layerTitles[idx]}</span>
                                <span style="color: ${layerColor}; font-size: 12px;">
                                    <i class='bx ${layerIcon}'></i> ${layerStatus}
                                </span>
                            </div>
                            <p style="color: #888; font-size: 12px; margin: 4px 0 0 0;">${data.layers[layer].message || 'No issues detected'}</p>
                        </div>
                    `;
                }
            });
        }
        
        // Build behavioral signals HTML
        const signals = [];
        if (data.hasLoginForm) signals.push('Login Form Detected');
        if (data.hasPasswordField) signals.push('Password Field Detected');
        if (data.hasEmailField) signals.push('Email Input Detected');
        if (data.suspiciousKeywords && data.suspiciousKeywords.length > 0) {
            signals.push('Suspicious Keywords: ' + data.suspiciousKeywords.join(', '));
        }
        
        const signalsHtml = signals.length > 0 ? 
            signals.map(s => `<div style="background: #3a2a1a; padding: 10px; margin-bottom: 6px; border-radius: 6px; color: #ffa500; font-size: 13px;"><i class='bx bx-warning' style="margin-right: 6px;"></i>${s}</div>`).join('') :
            `<div style="background: #1a3a1a; padding: 10px; border-radius: 6px; color: #4caf50; font-size: 13px;"><i class='bx bx-check-circle' style="margin-right: 6px;"></i>No Security Issues Detected</div>`;
        
        modal.innerHTML = `
            <div style="background: linear-gradient(180deg, #1a1a2e 0%, #0f0f1a 100%); border-radius: 16px; max-width: 1000px; width: 100%; max-height: 95vh; overflow-y: auto; padding: 0; position: relative; box-shadow: 0 25px 50px rgba(0,0,0,0.5);">
                <!-- Header -->
                <div style="background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); padding: 20px 24px; border-radius: 16px 16px 0 0;">
                    <button onclick="this.closest('.sandbox-modal').remove()" style="position: absolute; top: 12px; right: 16px; background: rgba(255,255,255,0.2); border: none; color: #fff; width: 32px; height: 32px; border-radius: 50%; cursor: pointer; font-size: 18px; display: flex; align-items: center; justify-content: center;">&times;</button>
                    <div style="display: flex; align-items: center; gap: 16px;">
                        <div style="width: 48px; height: 48px; background: ${statusColor}; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 24px;">
                            <i class='bx ${statusIcon}' style="color: #fff;"></i>
                        </div>
                        <div>
                            <h2 style="color: #fff; margin: 0; font-size: 22px; font-weight: 600;">Sandbox Analysis Report</h2>
                            <p style="color: rgba(255,255,255,0.8); margin: 4px 0 0 0; font-size: 14px;">${data.sourceUrl || 'N/A'}</p>
                        </div>
                    </div>
                </div>
                
                <!-- Trust Banner -->
                <div style="background: rgba(76, 175, 80, 0.1); border: 1px solid rgba(76, 175, 80, 0.3); margin: 20px; padding: 16px; border-radius: 12px; display: flex; align-items: center; gap: 12px;">
                    <i class='bx bxs-lock-alt' style="font-size: 24px; color: #4caf50;"></i>
                    <div>
                        <strong style="color: #4caf50;">Secure Sandbox Environment</strong>
                        <p style="color: #888; margin: 4px 0 0 0; font-size: 12px;">This URL was opened in an isolated, read-only browser. No data was submitted.</p>
                    </div>
                </div>
                
                <!-- Content Grid -->
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; padding: 0 20px 20px 20px;">
                    <!-- Left Column - Screenshot -->
                    <div>
                        <h3 style="color: #fff; margin: 0 0 12px 0; font-size: 16px;">🖼️ Website Screenshot</h3>
                        <div style="background: #0a0a15; border-radius: 12px; overflow: hidden; border: 1px solid #333;">
                            <div style="background: #1a1a2e; padding: 10px 16px; display: flex; align-items: center; gap: 8px; border-bottom: 1px solid #333;">
                                <div style="display: flex; gap: 6px;">
                                    <span style="width: 12px; height: 12px; border-radius: 50%; background: #ff5f57;"></span>
                                    <span style="width: 12px; height: 12px; border-radius: 50%; background: #febc2e;"></span>
                                    <span style="width: 12px; height: 12px; border-radius: 50%; background: #28c840;"></span>
                                </div>
                                <div style="flex: 1; background: #0a0a15; border-radius: 6px; padding: 6px 12px; margin-left: 12px; font-size: 12px; color: #888; display: flex; align-items: center; gap: 6px;">
                                    <i class='bx bx-lock-alt' style="font-size: 10px;"></i>
                                    ${data.finalUrl || 'N/A'}
                                </div>
                            </div>
                            <img src="${data.screenshot}" style="width: 100%; display: block;" alt="Website Screenshot">
                        </div>
                        <p style="color: #666; font-size: 11px; margin: 8px 0 0 0; text-align: center;">
                            <i class='bx bx-time'></i> Captured: ${data.timestamp || 'N/A'}
                        </p>
                    </div>
                    
                    <!-- Right Column - Details -->
                    <div>
                        <h3 style="color: #fff; margin: 0 0 12px 0; font-size: 16px;">📊 Technical Metadata</h3>
                        <div style="background: #0a0a15; border-radius: 12px; padding: 16px; border: 1px solid #333; margin-bottom: 20px;">
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                                <div>
                                    <p style="color: #666; font-size: 11px; margin: 0;">Final URL</p>
                                    <p style="color: #ccc; font-size: 12px; margin: 4px 0 0 0; word-break: break-all;">${data.finalUrl || 'N/A'}</p>
                                </div>
                                <div>
                                    <p style="color: #666; font-size: 11px; margin: 0;">Domain</p>
                                    <p style="color: #ccc; font-size: 12px; margin: 4px 0 0 0;">${data.domain || 'N/A'}</p>
                                </div>
                                <div>
                                    <p style="color: #666; font-size: 11px; margin: 0;">IP Address</p>
                                    <p style="color: #ccc; font-size: 12px; margin: 4px 0 0 0;">${data.ipAddress || 'N/A'}</p>
                                </div>
                                <div>
                                    <p style="color: #666; font-size: 11px; margin: 0;">Page Title</p>
                                    <p style="color: #ccc; font-size: 12px; margin: 4px 0 0 0;">${data.pageTitle || 'N/A'}</p>
                                </div>
                                <div>
                                    <p style="color: #666; font-size: 11px; margin: 0;">Redirects</p>
                                    <p style="color: #ccc; font-size: 12px; margin: 4px 0 0 0;">${data.redirectCount || 0}</p>
                                </div>
                                <div>
                                    <p style="color: #666; font-size: 11px; margin: 0;">Load Time</p>
                                    <p style="color: #ccc; font-size: 12px; margin: 4px 0 0 0;">${data.loadTime || 0}ms</p>
                                </div>
                            </div>
                        </div>
                        
                        <h3 style="color: #fff; margin: 0 0 12px 0; font-size: 16px;">🔍 Behavioral Signals</h3>
                        <div style="background: #0a0a15; border-radius: 12px; padding: 16px; border: 1px solid #333;">
                            ${signalsHtml}
                        </div>
                    </div>
                </div>
                
                <!-- 5-Layer Analysis -->
                <div style="padding: 0 20px 20px 20px;">
                    <h3 style="color: #fff; margin: 0 0 12px 0; font-size: 16px;">🛡️ 5-Layer Security Analysis</h3>
                    <div style="background: #0a0a15; border-radius: 12px; padding: 16px; border: 1px solid #333;">
                        ${layersHtml || '<p style="color: #666; text-align: center;">No layer data available</p>'}
                    </div>
                </div>
                
                <!-- Footer -->
                <div style="background: rgba(255,255,255,0.03); padding: 16px 20px; border-radius: 0 0 16px 16px; text-align: center;">
                    <p style="color: #666; font-size: 12px; margin: 0;">
                        <i class='bx bx-info-circle'></i> 
                        This analysis reflects the website state at scan time. No personal data was accessed.
                    </p>
                    <p style="color: #444; font-size: 11px; margin: 8px 0 0 0;">
                        Scan ID: ${data.scanId || 'N/A'}
                    </p>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        
        modal.onclick = (e) => {
            if (e.target === modal) modal.remove();
        };
    };

})();
