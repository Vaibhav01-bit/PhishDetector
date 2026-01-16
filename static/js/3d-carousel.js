document.addEventListener('DOMContentLoaded', () => {
    const stage = document.querySelector('.carousel-stage');
    const items = document.querySelectorAll('.testimonial-item');
    const numberOfItems = items.length;
    const angleIncrement = 360 / numberOfItems;
    // Calculate radius dynamically based on virtual item width (approx 400px for spacing) to avoid overlap
    const radius = Math.round((400 / 2) / Math.tan(Math.PI / numberOfItems)) + 70;

    let currentRotation = 0;
    let isPaused = false;
    let isFocused = false;
    let autoRotateSpeed = 0.15; // Speed of rotation
    let animationFrameId;

    // Arrange items in a circle
    items.forEach((item, index) => {
        const itemAngle = angleIncrement * index;
        // Store original transform components for easy reset
        item.dataset.baseAngle = itemAngle;
        item.dataset.baseRadius = radius;
        item.style.transform = `rotateY(${itemAngle}deg) translateZ(${radius}px)`;

        // Add click listener
        item.addEventListener('click', () => {
            // If already focused on this item, maybe un-focus?
            if (item.classList.contains('active')) {
                resetFocus();
                return;
            }
            focusOnItem(index, item);
        });
    });

    function loop() {
        if (!isPaused && !isFocused) {
            currentRotation -= autoRotateSpeed;
            stage.style.transform = `rotateY(${currentRotation}deg)`;
        }
        animationFrameId = requestAnimationFrame(loop);
    }

    // Start loop
    loop();

    function focusOnItem(index, item) {
        // Stop Loop processing (visual only) but keep running to resume later
        isFocused = true;

        // Remove active from any other and add dimming
        items.forEach(i => {
            i.classList.remove('active');
            if (i !== item) {
                i.classList.add('dimmed');
                // Optional: scale down non-focused items slightly
                const angle = i.dataset.baseAngle;
                i.style.transition = 'transform 0.8s ease, opacity 0.8s ease';
                i.style.transform = `rotateY(${angle}deg) translateZ(${radius}px) scale(0.95)`;
            }
        });

        // Add active to clicked
        item.classList.remove('dimmed');
        item.classList.add('active');

        // Calculate Target Rotation to bring this item to front (0 deg)
        const itemAngle = parseFloat(item.dataset.baseAngle);
        let targetRotation = -itemAngle;

        // Adjust targetRotation to be close to currentRotation
        const cycle = Math.round((currentRotation - targetRotation) / 360);
        targetRotation += cycle * 360;

        // Apply smooth transition via CSS
        stage.style.transition = 'transform 1s cubic-bezier(0.2, 0.8, 0.2, 1)';
        stage.style.transform = `rotateY(${targetRotation}deg)`;
        currentRotation = targetRotation; // Update current to new snapped position

        // Apply "Subtle Lift" Transform to the item
        item.style.transition = 'transform 0.8s cubic-bezier(0.34, 1.56, 0.64, 1)'; // Springy but gentle
        // Reduced lift (50px) and subtle scale (1.05)
        item.style.transform = `rotateY(${itemAngle}deg) translateZ(${radius + 50}px) scale(1.05)`;
    }

    function resetFocus() {
        isFocused = false;
        items.forEach((item) => {
            item.classList.remove('active');
            item.classList.remove('dimmed');
            // Reset to base ring position
            const angle = item.dataset.baseAngle;
            item.style.transition = 'transform 0.6s ease, opacity 0.6s ease';
            item.style.transform = `rotateY(${angle}deg) translateZ(${radius}px) scale(1)`;
        });

        // Resume rotation after a short delay or immediately?
        // Remove stage transition for continuous loop (to avoid jerk when restarting loop)
        // allows the loop to pick up from `currentRotation`
        setTimeout(() => {
            stage.style.transition = 'none'; // Back to instant updates for loop
        }, 1000); // Wait for reset animation
    }

    // Pause on hover (only if not focused)
    const container = document.querySelector('.carousel-container');
    container.addEventListener('mouseenter', () => {
        if (!isFocused) isPaused = true;
    });

    container.addEventListener('mouseleave', () => {
        if (!isFocused) isPaused = false;
    });

    // Optional: Click outside to reset
    document.addEventListener('click', (e) => {
        if (isFocused && !e.target.closest('.testimonial-item')) {
            resetFocus();
        }
    });

    // Auto-hide Top Navigation when in Testimonials Section
    const testimonialsSection = document.querySelector('#testimonials');
    const header = document.querySelector('#header');

    if (testimonialsSection && header) {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    // Hide Header when testimonials are visible
                    header.style.transform = 'translateY(-100%)';
                } else {
                    // Show Header when leaving testimonials
                    header.style.transform = 'translateY(0)';
                }
            });
        }, {
            threshold: 0.15, // Trigger when 15% of the section is visible
            rootMargin: "-50px 0px 0px 0px" // Slight offset to avoid flickering at very top
        });

        observer.observe(testimonialsSection);
    }
});
