document.addEventListener('DOMContentLoaded', () => {
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (prefersReducedMotion) return;

    gsap.registerPlugin(ScrollTrigger);

    const faqSection = document.querySelector('.faq');
    const faqCards = document.querySelectorAll('.faq-card');
    const progressBar = document.querySelector('.faq-progress-bar');
    const faqHeader = document.querySelector('.faq-header-sticky');

    if (!faqSection || faqCards.length === 0) return;

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
    const mainTl = gsap.timeline({
        scrollTrigger: {
            trigger: faqSection,
            start: "top center",
            end: "bottom center",
            scrub: 1.5
        }
    });

    faqCards.forEach((card, index) => {
        const answer = card.querySelector('.faq-answer');
        const icon = card.querySelector('h3 i');
        
        // Internal Card Timeline
        const cardTl = gsap.timeline({
            scrollTrigger: {
                trigger: card,
                start: "top 95%",
                end: "bottom 5%",
                scrub: 1.2,
                onToggle: self => {
                    if (self.isActive) card.classList.add('is-active');
                    else card.classList.remove('is-active');
                }
            }
        });

        // Entrance: Magnetic Slide + 3D Rotation
        cardTl.fromTo(card, {
            opacity: 0,
            x: index % 2 === 0 ? -40 : 40,
            rotateY: index % 2 === 0 ? 15 : -15,
            scale: 0.9,
            filter: "blur(10px)",
        }, {
            opacity: 1,
            x: 0,
            rotateY: 0,
            scale: 1,
            filter: "blur(0px)",
            duration: 1.2,
            ease: "expo.out"
        });

        // Stitch Effect: Reveal Answer with a coordinated icon spin
        cardTl.to(answer, {
            height: "auto",
            opacity: 1,
            marginTop: "16px",
            duration: 0.8,
            ease: "power3.out"
        }, 0.2);

        cardTl.to(icon, {
            rotate: 360,
            scale: 1.2,
            backgroundColor: "rgba(59, 130, 246, 0.2)",
            duration: 0.8
        }, 0.2);

        // Exit: Fade and Stack
        cardTl.to(card, {
            opacity: 0.3,
            scale: 0.95,
            y: -50,
            rotateX: -10,
            filter: "blur(4px)",
            duration: 1,
            ease: "power2.in"
        }, "+=0.5");
    });

    // 3. MAGNETIC HOVER EFFECT - Subtle pull towards cursor
    faqCards.forEach(card => {
        card.addEventListener('mousemove', (e) => {
            const rect = card.getBoundingClientRect();
            const x = e.clientX - rect.left - rect.width / 2;
            const y = e.clientY - rect.top - rect.height / 2;
            
            gsap.to(card, {
                x: x * 0.1,
                y: y * 0.1,
                rotateX: -y * 0.05,
                rotateY: x * 0.05,
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
                duration: 0.6,
                ease: "elastic.out(1, 0.3)"
            });
        });
    });
});
