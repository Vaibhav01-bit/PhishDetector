document.addEventListener('DOMContentLoaded', () => {
    const stage = document.querySelector('.carousel-stage');
    const container = document.querySelector('.carousel-container');
    const items = document.querySelectorAll('.testimonial-item');
    const numberOfItems = items.length;
    const angleIncrement = 360 / numberOfItems;
    // Virtual width 400px for spacing
    const radius = Math.round((400 / 2) / Math.tan(Math.PI / numberOfItems)) + 70;

    let currentRotation = 0;
    let isPaused = false;
    let isDragging = false;
    let startX = 0;
    let startRotation = 0;
    let autoRotateSpeed = 0.15;

    // Arrange items
    items.forEach((item, index) => {
        const itemAngle = angleIncrement * index;
        item.dataset.baseAngle = itemAngle;
        item.style.transform = `rotateY(${itemAngle}deg) translateZ(${radius}px)`;
    });

    // Animation Loop
    function loop() {
        if (!isPaused && !isDragging) {
            currentRotation -= autoRotateSpeed;
            stage.style.transform = `rotateY(${currentRotation}deg)`;
        }
        requestAnimationFrame(loop);
    }
    loop();

    // -- Interaction Logic --

    // Pause on Hover
    container.addEventListener('mouseenter', () => {
        isPaused = true;
    });

    container.addEventListener('mouseleave', () => {
        // Only resume if not currently being dragged
        if (!isDragging) {
            isPaused = false;
        }
    });

    // Drag to Rotate
    container.addEventListener('mousedown', (e) => {
        isDragging = true;
        isPaused = true; // Ensure paused while dragging
        startX = e.clientX;
        startRotation = currentRotation;
        container.style.cursor = 'grabbing';
        // Prevent default browser drag behavior (scrolling/ghost image)
        e.preventDefault();
    });

    window.addEventListener('mousemove', (e) => {
        if (!isDragging) return;
        const deltaX = e.clientX - startX;
        // Sensitivity factor 0.2
        currentRotation = startRotation + (deltaX * 0.2);
        stage.style.transform = `rotateY(${currentRotation}deg)`;
    });

    window.addEventListener('mouseup', () => {
        if (isDragging) {
            isDragging = false;
            container.style.cursor = 'grab';

            // Resume if cursor is not over container
            if (!container.matches(':hover')) {
                isPaused = false;
            }
        }
    });

    // Auto-hide Top Navigation when in Testimonials Section
    const testimonialsSection = document.querySelector('#testimonials');
    const header = document.querySelector('#header');

    if (testimonialsSection && header) {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    header.style.transform = 'translateY(-100%)';
                } else {
                    header.style.transform = 'translateY(0)';
                }
            });
        }, {
            threshold: 0.15,
            rootMargin: "-50px 0px 0px 0px"
        });
        observer.observe(testimonialsSection);
    }
});
