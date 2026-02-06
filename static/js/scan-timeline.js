/**
 * PROGRESSIVE SCAN TIMELINE LOGIC
 * Cinematic security analysis with step-by-step visualization
 */

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('url-scan-form');
    const timeline = document.getElementById('scan-timeline');
    const legacyCard = document.getElementById('legacy-result-card');

    // Steps Configuration (Must match HTML)
    const steps = [
        { id: 'step-1', delay: 600 },  // URL Validation
        { id: 'step-2', delay: 800 },  // Domain Parsing
        { id: 'step-3', delay: 1000 }, // Redirect Resolution
        { id: 'step-4', delay: 800 },  // Brand Impersonation
        { id: 'step-5', delay: 900 },  // AI Evaluation
        { id: 'step-6', delay: 600 }   // Sandbox
    ];

    if (form) {
        form.addEventListener('submit', async (e) => {
            e.preventDefault();

            // 1. UI INITIALIZATION
            if (legacyCard) {
                legacyCard.style.display = 'none';
                legacyCard.classList.remove('slide-up-entrance');
            }
            timeline.style.display = 'block';
            timeline.classList.remove('scan-complete'); // Reset exit animation
            timeline.classList.add('active-scan');

            // Reset all steps
            resetTimeline();

            // Get URL
            const formData = new FormData(form);
            const url = formData.get('name');

            try {
                // 2. START PROGRESSIVE ANIMATION (Steps 1-3: "Fast" checks)
                // We show these running immediately to provide instant feedback
                await runStep(0);
                await runStep(1);

                // Start backend request in parallel with Step 3
                // This makes it feel faster but maintains the illusion of sequential work
                const scanPromise = fetch('/result', {
                    method: 'POST',
                    body: formData,
                    headers: { 'X-Requested-With': 'XMLHttpRequest' }
                });

                await runStep(2); // Redirects

                // 3. WAIT FOR BACKEND (Simulate "Deep Analysis")
                // Activate Step 4 (Brand Check) to show we are working
                setActive(3, "Deep scanning...");

                const response = await scanPromise;
                if (!response.ok) throw new Error("Scan failed");
                const result = await response.json();

                // 4. COMPLETE REMAINING STEPS
                markCompleted(3); // Finish Brand Check
                await runStep(4); // AI
                await runStep(5); // Sandbox

                // 5. CRITICAL TRANSITION PHASE
                await new Promise(r => setTimeout(r, 400)); // Pause for impact

                // Mark timeline as finished visually
                timeline.classList.remove('active-scan');

                // Fade out timeline
                timeline.classList.add('scan-complete');

                // Wait for fade out
                await new Promise(r => setTimeout(r, 500));

                // 6. REVEAL VERDICT
                timeline.style.display = 'none';
                populateResultCard(result);
                legacyCard.style.display = 'block';
                legacyCard.classList.add('slide-up-entrance');

            } catch (error) {
                console.error("Scan Error:", error);
                // In case of error, just fallback to standard submit or show error
                // For now, we'll reload the page with standard submit if JS fails
                form.submit();
            }
        });
    }

    // --- ANIMATION HELPERS ---

    function resetTimeline() {
        steps.forEach(s => {
            const el = document.getElementById(s.id);
            if (el) {
                el.className = 'scan-step';
                el.querySelector('.step-icon').innerHTML = "<i class='bx bx-circle'></i>";
                // Reset text if we changed it
                if (s.id === 'step-4') el.querySelector('.step-description').innerText = "Detecting fake brand signatures...";
            }
        });
    }

    async function runStep(index) {
        if (index >= steps.length) return;
        const s = steps[index];

        // Active Phase
        setActive(index);

        // Wait
        await new Promise(r => setTimeout(r, s.delay));

        // Complete Phase
        markCompleted(index);
    }

    function setActive(index, customText = null) {
        const el = document.getElementById(steps[index].id);
        if (!el) return;

        el.classList.add('active');
        el.querySelector('.step-icon').innerHTML = "<i class='bx bx-loader-alt'></i>";
        if (customText) {
            el.querySelector('.step-description').innerText = customText;
        }
    }

    function markCompleted(index) {
        const el = document.getElementById(steps[index].id);
        if (!el) return;

        el.classList.remove('active');
        el.classList.add('completed');
        el.querySelector('.step-icon').innerHTML = "<i class='bx bx-check'></i>";
    }

    // --- RESULT POPULATION ---
    function populateResultCard(data) {
        const card = document.getElementById('legacy-result-card');
        if (!card) return;

        // 1. Update Scanned URL
        // Finding elements by class or structure since IDs might not exist in loop
        // Best approach: Use the 'name' array logic from the backend

        // Helper to update text safely
        const setTxt = (sel, txt) => {
            const el = card.querySelector(sel);
            if (el) el.innerText = txt;
        };

        // URL Display
        const urlSpan = card.querySelector('.url-text span');
        if (urlSpan) urlSpan.innerText = data.url;

        // 2. Logic for Safe vs Phishing
        const isSafe = data.is_safe;
        const isWarning = data.status === 'Warning';

        // Icon Wrapper
        const iconWrapper = card.querySelector('.security-icon');
        iconWrapper.className = 'security-icon'; // Reset

        // Icon I element
        const iconI = iconWrapper.querySelector('i');

        // Verdict Heading
        const verdictHead = card.querySelector('.verdict-text');

        if (isSafe) {
            iconWrapper.classList.add('icon-safe');
            iconI.className = 'bx bxs-shield-alt-2';
            verdictHead.innerText = "This website appears safe";
            verdictHead.className = "verdict-text text-success fw-bold mb-0";
        } else if (isWarning) {
            iconWrapper.classList.add('icon-warning');
            iconI.className = 'bx bxs-error-alt';
            verdictHead.innerText = "Suspicious patterns detected";
            verdictHead.className = "verdict-text text-warning fw-bold mb-0";
        } else {
            iconWrapper.classList.add('icon-danger');
            iconI.className = 'bx bxs-shield-x';
            verdictHead.innerText = "High-risk phishing indicators found";
            verdictHead.className = "verdict-text text-danger fw-bold mb-0";
        }

        // 3. CTA Buttons (Sandbox vs Proceed)
        const sandboxLink = card.querySelector('.btn-sandbox-primary');
        if (sandboxLink) {
            if (data.details && data.details.layers.sandbox && data.details.layers.sandbox.success) {
                sandboxLink.href = `/sandbox/${data.details.layers.sandbox.scan_id}`;
            } else {
                // Hide or disable if no sandbox
            }
        }

        // Update Proceed Button
        const btnProceeding = card.querySelector('button[onclick]'); // Naive selector
        // Ideally we recreate the button or change its class/onclick
        // For simplicity: Update the 'secondary-cta-wrapper'
        const secondaryWrapper = card.querySelector('.secondary-cta-wrapper');
        if (secondaryWrapper) {
            if (isSafe) {
                secondaryWrapper.innerHTML = `
                    <button class="btn-proceed-secondary" onclick="window.open('${data.url}')" target="_blank">
                      <i class='bx bx-check-circle me-1'></i> Proceed Safely
                    </button>
                `;
            } else {
                secondaryWrapper.innerHTML = `
                    <button class="btn-proceed-danger" onclick="window.open('${data.url}')" target="_blank">
                      <i class='bx bx-error-circle me-1'></i> View Anyway (Risk)
                    </button>
                `;
            }
        }

        // 4. Update Analysis Details List (Optional but good)
        // ... (We could iterate layers and update the list, but for now the verdict is key)
    }
});

