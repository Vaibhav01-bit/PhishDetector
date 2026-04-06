document.addEventListener('DOMContentLoaded', () => {
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (prefersReducedMotion) return;

    gsap.registerPlugin(ScrollTrigger);

    const faqSection = document.querySelector('.faq');
    const faqCards = document.querySelectorAll('.faq-card');
    const progressBar = document.querySelector('.faq-progress-bar');
    const progressStepsContainer = document.querySelector('.faq-progress-steps');
    const faqHeader = document.querySelector('.faq-header-sticky');

    if (!faqSection || faqCards.length === 0) return;

    // 0. GENERATE PROGRESS DOTS dynamically based on number of cards
    if (progressStepsContainer) {
        faqCards.forEach((_, i) => {
            const dot = document.createElement('div');
            dot.classList.add('faq-step-dot');
            dot.dataset.index = i;
            progressStepsContainer.appendChild(dot);
        });
    }
    const dots = document.querySelectorAll('.faq-step-dot');

    // 1. STITCHED PROGRESS BAR - Dynamic color & pulse based on card activity
    gsap.to(progressBar, {
        height: "100%",
        ease: "none",
        scrollTrigger: {
            trigger: faqSection,
            start: "top 20%",
            end: "bottom 80%",
            scrub: true,
            onUpdate: (self) => {
                const hue = 210 + (self.progress * 150); // Shift from Blue to Cyan/Teal
                gsap.set(progressBar, { 
                    backgroundColor: `hsl(${hue}, 100%, 50%)`,
                    boxShadow: `0 0 20px hsla(${hue}, 100%, 50%, 0.6)`
                });
            }
        }
    });

    // 2. COORDINATED "STITCHED" TIMELINE
    faqCards.forEach((card, index) => {
        const answer = card.querySelector('.faq-answer');
        const icon = card.querySelector('h3 i');
        const dot = dots[index];
        
        // Internal Card Timeline
        const cardTl = gsap.timeline({
            scrollTrigger: {
                trigger: card,
                start: "top 85%",
                end: "bottom 35%", // Keeps it active a bit longer
                scrub: 1.2,
                onToggle: self => {
                    if (self.isActive) {
                        card.classList.add('is-active');
                        if (dot) dot.classList.add('active');
                    } else {
                        card.classList.remove('is-active');
                        if (dot) dot.classList.remove('active');
                    }
                }
            }
        });

        // Entrance: Magnetic Slide + Premium 3D Fold
        cardTl.fromTo(card, {
            opacity: 0,
            x: index % 2 === 0 ? -60 : 60,
            rotateY: index % 2 === 0 ? 25 : -25,
            rotateX: -10,
            transformOrigin: index % 2 === 0 ? "left center" : "right center",
            scale: 0.85,
            filter: "blur(15px)",
        }, {
            opacity: 1,
            x: 0,
            rotateY: 0,
            rotateX: 0,
            scale: 1,
            filter: "blur(0px)",
            duration: 1.5,
            ease: "expo.out"
        });

        // Stitch Effect: Reveal Answer with a coordinated icon spin
        cardTl.to(answer, {
            height: "auto",
            opacity: 1,
            marginTop: "16px",
            duration: 1,
            ease: "power4.out"
        }, 0.3);

        cardTl.to(icon, {
            rotate: 360,
            scale: 1.2,
            backgroundColor: "rgba(59, 130, 246, 0.2)",
            duration: 1,
            ease: "back.out(1.7)"
        }, 0.3);

        // Exit: Dramatic Fade and Stack
        cardTl.to(card, {
            opacity: 0.1,
            scale: 0.9,
            y: -80,
            rotateX: 15,
            filter: "blur(8px)",
            duration: 1.2,
            ease: "power2.inOut"
        }, "+=0.6");
    });

    // 3. MAGNETIC HOVER EFFECT - Subtle pull towards cursor
    faqCards.forEach(card => {
        card.addEventListener('mousemove', (e) => {
            // Only apply hover effect if active (in view)
            if (!card.classList.contains('is-active')) return;
            
            const rect = card.getBoundingClientRect();
            const x = e.clientX - rect.left - rect.width / 2;
            const y = e.clientY - rect.top - rect.height / 2;
            
            gsap.to(card, {
                x: x * 0.08,
                y: y * 0.08,
                rotateX: -y * 0.04,
                rotateY: x * 0.04,
                duration: 0.4,
                ease: "power2.out"
            });
        });

        card.addEventListener('mouseleave', () => {
            gsap.to(card, {
                x: 0,
                y: 0,
                rotateX: 0,
                rotateY: 0,
                duration: 0.7,
                ease: "elastic.out(1, 0.4)"
            });
        });
    });
});

