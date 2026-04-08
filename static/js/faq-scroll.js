document.addEventListener('DOMContentLoaded', () => {
    const faqSection = document.querySelector('.faq');
    const faqCards = Array.from(document.querySelectorAll('.faq-card'));
    const progressBar = document.querySelector('.faq-progress-bar');
    const progressStepsContainer = document.querySelector('.faq-progress-steps');
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const hasGsap = typeof window.gsap !== 'undefined' && typeof window.ScrollTrigger !== 'undefined';

    if (!faqSection || faqCards.length === 0) {
        return;
    }

    if (progressStepsContainer) {
        progressStepsContainer.innerHTML = '';
        faqCards.forEach((_, index) => {
            const dot = document.createElement('div');
            dot.className = 'faq-step-dot';
            dot.dataset.index = String(index);
            progressStepsContainer.appendChild(dot);
        });
    }

    const dots = Array.from(document.querySelectorAll('.faq-step-dot'));

    const setActiveCard = (activeIndex) => {
        faqCards.forEach((card, index) => {
            card.classList.toggle('is-active', index === activeIndex);
        });

        dots.forEach((dot, index) => {
            dot.classList.toggle('active', index === activeIndex);
        });
    };

    setActiveCard(0);

    if (prefersReducedMotion || !hasGsap) {
        if (progressBar) {
            progressBar.style.height = '100%';
        }
        return;
    }

    const { gsap, ScrollTrigger } = window;
    gsap.registerPlugin(ScrollTrigger);

    if (progressBar) {
        gsap.to(progressBar, {
            height: '100%',
            ease: 'none',
            scrollTrigger: {
                trigger: faqSection,
                start: 'top 20%',
                end: 'bottom 80%',
                scrub: true
            }
        });
    }

    faqCards.forEach((card, index) => {
        const icon = card.querySelector('h3 i');

        gsap.fromTo(card, {
            y: 40,
            opacity: 0
        }, {
            y: 0,
            opacity: 1,
            duration: 0.8,
            ease: 'power3.out',
            scrollTrigger: {
                trigger: card,
                start: 'top 88%',
                once: true
            }
        });

        if (icon) {
            gsap.fromTo(icon, {
                scale: 0.85,
                rotate: -12
            }, {
                scale: 1,
                rotate: 0,
                duration: 0.6,
                ease: 'back.out(1.7)',
                scrollTrigger: {
                    trigger: card,
                    start: 'top 88%',
                    once: true
                }
            });
        }

        ScrollTrigger.create({
            trigger: card,
            start: 'top 55%',
            end: 'bottom 45%',
            onEnter: () => setActiveCard(index),
            onEnterBack: () => setActiveCard(index)
        });
    });

    const canHover = window.matchMedia('(hover: hover) and (pointer: fine)').matches;

    if (!canHover) {
        return;
    }

    faqCards.forEach((card) => {
        card.addEventListener('mousemove', (event) => {
            if (!card.classList.contains('is-active')) {
                return;
            }

            const rect = card.getBoundingClientRect();
            const offsetX = event.clientX - rect.left - rect.width / 2;
            const offsetY = event.clientY - rect.top - rect.height / 2;

            gsap.to(card, {
                x: offsetX * 0.05,
                y: offsetY * 0.05,
                rotateX: -offsetY * 0.025,
                rotateY: offsetX * 0.025,
                duration: 0.3,
                ease: 'power2.out',
                overwrite: true
            });
        });

        card.addEventListener('mouseleave', () => {
            gsap.to(card, {
                x: 0,
                y: 0,
                rotateX: 0,
                rotateY: 0,
                duration: 0.35,
                ease: 'power2.out',
                overwrite: true
            });
        });
    });
});
