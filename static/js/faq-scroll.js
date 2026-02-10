/**
 * FAQ Scroll-Driven Animations - Ultra Premium Master Suite
 * Coordinated Progress, Stacking, and 3D Depth
 */

document.addEventListener('DOMContentLoaded', () => {
    // Check for prefers-reduced-motion
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (prefersReducedMotion) return;

    // Register ScrollTrigger
    gsap.registerPlugin(ScrollTrigger);

    const faqSection = document.querySelector('.faq');
    const faqCards = document.querySelectorAll('.faq-card');
    const progressBar = document.querySelector('.faq-progress-bar');

    if (!faqSection || faqCards.length === 0) return;

    // 1. MASTER PROGRESS BAR COORDINATION
    gsap.to(progressBar, {
        height: "100%",
        ease: "none",
        scrollTrigger: {
            trigger: faqSection,
            start: "top 20%",
            end: "bottom 80%",
            scrub: true
        }
    });

    // 2. COORDINATED CARD SEQUENCING
    faqCards.forEach((card, index) => {
        const answer = card.querySelector('.faq-answer');
        const h3 = card.querySelector('h3');

        // Timeline for the card's entire lifecycle
        const tl = gsap.timeline({
            scrollTrigger: {
                trigger: card,
                start: "top 95%",    // Enters from bottom
                end: "bottom 5%",    // Clears from top
                scrub: 1.2,          // Ultra-smooth follow
                onToggle: self => {
                    if (self.isActive) card.classList.add('is-active');
                    else card.classList.remove('is-active');
                }
            }
        });

        // 3-PHASE TRANSITION (Entry -> Focus -> Exit)

        // Phase 1: Entry from bottom
        tl.fromTo(card, {
            opacity: 0.1,
            scale: 0.85,
            y: 80,
            rotateX: 10,
            translateZ: -150,
            filter: "blur(12px)",
        }, {
            opacity: 1,
            scale: 1,
            y: 0,
            rotateX: 0,
            translateZ: 0,
            filter: "blur(0px)",
            duration: 1.5,
            ease: "power2.out"
        });

        // Answer Expansion (Centered in the lifecycle)
        tl.to(answer, {
            height: "auto",
            opacity: 1,
            marginTop: "16px",
            duration: 0.8,
            ease: "power3.out"
        }, 0.4);

        // Phase 2: Exit to top (The "Stacking" feel)
        tl.to(card, {
            opacity: 0.15,
            scale: 0.9,
            y: -80,
            rotateX: -10,
            translateZ: -100,
            filter: "blur(10px)",
            duration: 1.5,
            ease: "power2.in"
        }, "+=0.4"); // Hold focus before exiting

        // Collapse Answer on exit
        tl.to(answer, {
            height: 0,
            opacity: 0,
            marginTop: 0,
            duration: 0.8,
            ease: "power3.in"
        }, ">-1");

        // Real-time Theme Color Sync
        ScrollTrigger.create({
            trigger: card,
            start: "top center",
            end: "bottom center",
            onUpdate: (self) => {
                const isDark = document.body.classList.contains('dark-mode');
                const progress = self.progress;

                if (self.isActive) {
                    gsap.to(card, {
                        backgroundColor: isDark ? "rgba(255, 255, 255, 0.05)" : "rgba(255, 255, 255, 0.98)",
                        borderColor: isDark ? `rgba(0, 242, 255, ${0.1 + progress * 0.4})` : `rgba(59, 130, 246, ${0.1 + progress * 0.3})`,
                        boxShadow: isDark ? "0 20px 50px rgba(0, 0, 0, 0.4)" : "0 20px 50px rgba(0, 0, 0, 0.05)",
                        duration: 0.3
                    });
                }
            }
        });
    });

    // 3. HOVER MICRO-GLOW (Desktop)
    faqCards.forEach(card => {
        card.addEventListener('mouseenter', () => {
            if (window.innerWidth > 991) {
                gsap.to(card, {
                    y: -5,
                    translateZ: 20,
                    borderColor: document.body.classList.contains('dark-mode') ? "rgba(0, 242, 255, 0.6)" : "rgba(59, 130, 246, 0.6)",
                    boxShadow: "0 30px 60px rgba(0, 0, 0, 0.15)",
                    duration: 0.4,
                    ease: "power2.out"
                });
            }
        });

        card.addEventListener('mouseleave', () => {
            if (window.innerWidth > 991) {
                gsap.to(card, {
                    y: 0,
                    translateZ: 0,
                    borderColor: "inherit",
                    boxShadow: "inherit",
                    duration: 0.4,
                    ease: "power2.out"
                });
            }
        });
    });
});
