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

        // Reveal screenshot
        if (status.screenshot_url) {
            revealScreenshot(status.screenshot_url);
        } else {
            removeScreenshotFrame();
        }

        // ── Show sandbox CTA button ─────────────────────────────────────────
        // Always show the button when sandbox succeeds - construct URL from scan_id
        const sandboxCTA = resultCard.querySelector('.primary-cta-wrapper');
        
        // Get scan_id from either status or currentScanId
        const scanId = status.scan_id || currentScanId;
        
        console.log('[Scanner] sandboxCTA found:', !!sandboxCTA);
        console.log('[Scanner] status.success:', status.success);
        console.log('[Scanner] scanId:', scanId);
        
        if (sandboxCTA && status.success && scanId) {
            // Sandbox succeeded - show the View Sandbox button
            const sandboxUrl = `/sandbox/${scanId}`;
            console.log('[Scanner] Showing sandbox button with URL:', sandboxUrl);
            
            sandboxCTA.innerHTML = `
                <a href="${escHtml(sandboxUrl)}" class="btn-sandbox-primary">
                    <span>View Sandbox Analysis</span>
                    <i class='bx bx-right-arrow-alt'></i>
                </a>
                <p class="sandbox-caption mt-2 mb-0 text-center">
                    <i class='bx bxs-lock-alt'></i>
                    Secure sandbox environment &bull; No user interaction performed
                </p>`;
            sandboxCTA.style.display = 'block';
            sandboxCTA.classList.add('cta-fade-in');
        } else if (sandboxCTA && !status.success) {
            // Sandbox failed - show error message
            console.log('[Scanner] Sandbox failed, showing error');
            sandboxCTA.innerHTML = `
                <p class="text-center mb-0" style="font-size:.82rem;opacity:.7">
                    <i class='bx bx-info-circle'></i>
                    Sandbox analysis unavailable for this URL.
                </p>`;
            sandboxCTA.style.display = 'block';
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

})();
