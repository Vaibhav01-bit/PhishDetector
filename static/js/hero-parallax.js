/**
 * MOUSE PARALLAX EFFECT
 * Premium feel for hero image
 */

document.addEventListener('DOMContentLoaded', () => {
    const heroSection = document.getElementById('hero');
    const heroImages = document.querySelectorAll('.floating-dashboard');

    if (!heroSection || heroImages.length === 0) return;

    heroSection.addEventListener('mousemove', (e) => {
        const x = (window.innerWidth - e.pageX * 2) / 90;
        const y = (window.innerHeight - e.pageY * 2) / 90;

        heroImages.forEach(img => {
            // Check if visible
            if (getComputedStyle(img).opacity !== '0') {
                img.style.transform = `translateX(${x}px) translateY(${y}px) perspective(1000px) rotateY(${x * 0.5}deg) rotateX(${-y * 0.5}deg)`;
            }
        });
    });

    // Reset on mouse leave
    heroSection.addEventListener('mouseleave', () => {
        heroImages.forEach(img => {
            img.style.transform = 'translateY(0) perspective(1000px) rotateY(0deg) rotateX(0deg)';
        });
    });
});
