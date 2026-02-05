/**
 * PROGRESSIVE SCAN TIMELINE LOGIC - DISABLED
 * Timeline feature has been removed
 */

/* DISABLED - Timeline removed
document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('url-scan-form');
    const timeline = document.getElementById('scan-timeline');
    const legacyCard = document.getElementById('legacy-result-card');

    // Scan Steps Data
    const steps = [
        { id: 'step-1', text: 'Validating URL' },
        { id: 'step-2', text: 'Parsing Domain' },
        { id: 'step-3', text: 'Resolving Redirects' },
        { id: 'step-4', text: 'Brand Analysis' },
        { id: 'step-5', text: 'AI Threat Detection' },
        { id: 'step-6', text: 'Sandbox Execution' }
    ];

    if (form) {
        form.addEventListener('submit', async (e) => {
            e.preventDefault();

            // 1. UI RESET
            if (legacyCard) legacyCard.style.display = 'none';
            timeline.style.display = 'block';
            resetTimeline();

            const formData = new FormData(form);
            const url = formData.get('name');

            // 2. START PROGRESSIVE ANIMATION (Steps 1-3)
            // We simulate early steps immediately to feel responsive
            await simulateStep(0, 600);  // URL
            await simulateStep(1, 800);  // Domain
            await simulateStep(2, 1000); // Redirects (Simulated wait)

            // 3. TRIGGER BACKEND SCAN (AJAX)
            try {
                // Mark Step 4 (AI/Brand) as Loading while we fetch
                setActive(3);

                const response = await fetch('/result', {
                    method: 'POST',
                    body: formData,
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                });

                if (!response.ok) throw new Error("Scan failed");
                const result = await response.json();

                // 4. HANDLE SUCCESS (Fast-forward remaining steps)
                markCompleted(3);     // Brand done
                await simulateStep(4, 500); // AI
                await simulateStep(5, 500); // Sandbox

                // 5. SHOW VERDICT
                showVerdict(result);

            } catch (error) {
                console.error("Scan Error:", error);
                showError();
            }
        });
    }


    // --- HELPER FUNCTIONS ---

    function resetTimeline() {
        document.getElementById('verdict-banner').style.display = 'none';
        document.getElementById('timeline-actions').style.display = 'none';

        steps.forEach((s, index) => {
            const el = document.getElementById(s.id);
            el.className = 'scan-step'; // Reset classes
            el.style.opacity = '0.5';

            // Reset Icon
            const icon = el.querySelector('.step-icon');
            icon.innerHTML = "<i class='bx bx-circle'></i>";
        });

        // Set Step 1 Active
        const step1 = document.getElementById('step-1');
        step1.classList.add('active');
        step1.style.opacity = '1';
    }

    function setActive(index) {
        if (index >= steps.length) return;
        const el = document.getElementById(steps[index].id);
        el.classList.add('active');
        el.style.opacity = '1';
        el.querySelector('.step-icon').innerHTML = "<i class='bx bx-radio-circle-marked'></i>";
        el.querySelector('.step-description').innerText = "Processing...";
    }

    function markCompleted(index) {
        if (index >= steps.length) return;
        const el = document.getElementById(steps[index].id);
        el.classList.remove('active');
        el.classList.add('completed');
        el.querySelector('.step-icon').innerHTML = "<i class='bx bx-check'></i>";
        el.querySelector('.step-description').innerText = "Completed";
    }

    function markWarning(index, msg) {
        const el = document.getElementById(steps[index].id);
        el.classList.remove('active');
        el.classList.add('warning'); // You need CSS for this
        el.querySelector('.step-icon').innerHTML = "<i class='bx bx-error'></i>";
        el.querySelector('.step-description').innerText = msg || "Suspicious";
    }

    // Returns a promise that resolves after 'ms' time
    // Also handles UI updates for that step
    async function simulateStep(index, ms) {
        setActive(index);
        await new Promise(r => setTimeout(r, ms));
        markCompleted(index);
    }

    function showVerdict(data) {
        const banner = document.getElementById('verdict-banner');
        const title = document.getElementById('verdict-title');
        const text = document.getElementById('verdict-text');
        const icon = document.getElementById('verdict-icon-i');
        const actions = document.getElementById('timeline-actions');

        banner.style.display = 'block';
        actions.style.display = 'block';

        if (data.is_safe) {
            banner.className = 'verdict-banner success';
            banner.style.background = 'rgba(16, 185, 129, 0.1)';
            banner.style.borderColor = 'rgba(16, 185, 129, 0.3)';
            title.innerText = "Website is Safe";
            title.style.color = '#10b981';
            text.innerText = "No malicious threats detected across 5 layers.";
            icon.className = 'bx bx-shield-check text-success-bold';
        } else {
            banner.className = 'verdict-banner danger';
            banner.style.background = 'rgba(239, 68, 68, 0.1)';
            banner.style.borderColor = 'rgba(239, 68, 68, 0.3)';
            title.innerText = "Phishing Detected";
            title.style.color = '#ef4444';
            text.innerText = "This URL exhibits malicious behavior. Do not visit.";
            icon.className = 'bx bx-shield-x text-danger-bold';

            // Highlight specific failing steps if possible? 
            // For simplicity, we just show global verdict now.
        }
    }

    function showError() {
        const banner = document.getElementById('verdict-banner');
        banner.style.display = 'block';
        banner.className = 'verdict-banner danger';
        banner.innerHTML = "<h3>Error</h3><p>Could not complete scan. Please try again.</p>";
    }
*/ // END DISABLED CODE
