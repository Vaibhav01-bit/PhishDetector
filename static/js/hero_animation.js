/**
 * 3D Global Network - Rotating Sphere Animation
 * Represents the World Wide Web and Global Cybersecurity
 */

const canvas = document.getElementById('hero-canvas');
const ctx = canvas.getContext('2d');

let width, height;
let dots = [];

// Configuration
const config = {
    sphereRadius: 280,
    dotCount: 180,
    rotationSpeed: 0.003,
    perspective: 800,
    connectionDistance: 60,
    colors: {
        palette: [
            'rgba(6, 182, 212, 1)',   // Cyan
            'rgba(139, 92, 246, 1)',  // Purple
            'rgba(59, 130, 246, 1)',  // Blue
            'rgba(20, 184, 166, 1)',  // Teal
            'rgba(236, 72, 153, 1)'   // Pink/Rose (for soft accent)
        ],
        bg: 'transparent'
    }
};

let rotation = { x: 0, y: 0 };
let mouse = { x: 0, y: 0 };
let targetRotationY = 0;

function resize() {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
    config.sphereRadius = Math.min(width, height) * 0.35; // Responsive size
}
window.addEventListener('resize', resize);
resize();

window.addEventListener('mousemove', (e) => {
    // Map mouse X to rotation speed
    const centerX = width / 2;
    targetRotationY = (e.clientX - centerX) * 0.0001;
});

/**
 * 3D Point Class
 */
class Dot {
    constructor() {
        // Random spherical coordinates
        this.theta = Math.random() * Math.PI * 2; // Longitude
        this.phi = Math.acos((Math.random() * 2) - 1); // Latitude (uniform distribution)

        this.x = 0;
        this.y = 0;
        this.z = 0;

        this.xProjected = 0;
        this.yProjected = 0;
        this.scaleProjected = 0;

        // Random Color from Palette
        this.colorString = config.colors.palette[Math.floor(Math.random() * config.colors.palette.length)];
    }

    rotate(angleY) {
        // 3D Rotation Matrix for Y axis
        // x' = x cos θ + z sin θ
        // z' = -x sin θ + z cos θ

        // We calculate positions from spherical coords directly to avoid accumulation errors
        // But for continuous rotation, we just increment theta
        this.theta += angleY;

        const r = config.sphereRadius;
        this.x = r * Math.sin(this.phi) * Math.cos(this.theta);
        this.y = r * Math.cos(this.phi);
        this.z = r * Math.sin(this.phi) * Math.sin(this.theta) + r; // +r to push back from camera
    }

    project() {
        // Simple Perspective Projection
        // The sphere follows rotation, but we translate Z to move it in front of camera
        const distance = config.perspective;
        // z is offset by radius to center it? Actually, let's keep z centered at 0 and add offset in projection

        // Recalculate Cartesian with current rotation
        const r = config.sphereRadius;
        const x3d = r * Math.sin(this.phi) * Math.cos(this.theta);
        const y3d = r * Math.cos(this.phi);
        const z3d = r * Math.sin(this.phi) * Math.sin(this.theta);

        // Camera offset
        const zCamera = z3d + config.perspective;

        this.scaleProjected = config.perspective / zCamera;
        this.xProjected = (x3d * this.scaleProjected) + width / 2;
        this.yProjected = (y3d * this.scaleProjected) + height / 2;

        // Store z3d for depth sorting/opacity
        this.z = z3d;
    }

    draw() {
        // Alpha based on depth (fade back side)
        // z3d goes from -radius to +radius. Front is -radius (closest)? No, we projected standard.
        // Let's assume standard right-hand: +Z is towards viewer?
        // Based on rotation math above: z = r * ... sin(theta).
        // Let's just use the scaleProjected. Larger scale = closer.

        const alpha = Math.max(0.1, (this.scaleProjected - 0.5) * 1.5);

        ctx.beginPath();
        ctx.arc(this.xProjected, this.yProjected, 2 * this.scaleProjected, 0, Math.PI * 2);
        // Use instance color with calculated opacity
        // Hack: replace '1)' with alpha
        ctx.fillStyle = this.colorString.replace('1)', `${alpha})`);
        ctx.fill();
    }
}


/**
 * Security Icon Class (Shields, Locks, Keys)
 */
class SecurityIcon {
    constructor() {
        this.reset();
        this.y = Math.random() * height; // Start anywhere
        this.iconType = Math.random() > 0.6 ? 'shield' : (Math.random() > 0.5 ? 'lock' : 'check'); // Random type
        // Random color
        this.baseColor = config.colors.palette[Math.floor(Math.random() * config.colors.palette.length)];
    }

    reset() {
        this.x = Math.random() * width;
        this.y = height + 50; // Start below screen
        this.speed = Math.random() * 0.4 + 0.2; // Slow gentle drift
        this.size = Math.random() * 25 + 20;
        this.opacity = 0;
        this.fadeIn = true;
        this.maxOpacity = Math.random() * 0.4 + 0.2; // 0.2 to 0.6 (Much more visible)
        this.wobble = Math.random() * Math.PI * 2;
        this.baseColor = config.colors.palette[Math.floor(Math.random() * config.colors.palette.length)];
    }

    update() {
        this.y -= this.speed;
        this.wobble += 0.02;
        this.x += Math.sin(this.wobble) * 0.5;

        // Fade in/out logic
        if (this.fadeIn) {
            this.opacity += 0.005;
            if (this.opacity >= this.maxOpacity) this.fadeIn = false;
        } else {
            // Start fading out when near top
            if (this.y < height * 0.2) {
                this.opacity -= 0.005;
            }
        }

        if (this.y < -50 || this.opacity < 0) {
            this.reset();
        }
    }

    draw() {
        ctx.save();
        ctx.translate(this.x, this.y);

        // Apply opacity to base color
        const color = this.baseColor.replace('1)', `${Math.max(0, this.opacity)})`);
        const fill = this.baseColor.replace('1)', `${Math.max(0, this.opacity * 0.1)})`);

        ctx.strokeStyle = color;
        ctx.fillStyle = fill;
        ctx.lineWidth = 2; // Thicker line

        // Removed heavy shadowBlur which was washing it out. kept minimal or none.
        ctx.shadowBlur = 0;

        const s = this.size;

        if (this.iconType === 'shield') {
            // Draw Shield
            ctx.beginPath();
            ctx.moveTo(0, s / 2);
            ctx.quadraticCurveTo(0, -s / 2, s / 2, -s / 2);
            ctx.quadraticCurveTo(s / 2, s / 4, 0, s);
            ctx.moveTo(0, s / 2);
            ctx.quadraticCurveTo(0, -s / 2, -s / 2, -s / 2);
            ctx.quadraticCurveTo(-s / 2, s / 4, 0, s);
            ctx.stroke();
        } else if (this.iconType === 'lock') {
            // Draw Lock
            const w = s * 0.7;
            const h = s * 0.6;
            ctx.strokeRect(-w / 2, 0, w, h);
            ctx.beginPath();
            ctx.arc(0, 0, w / 2 * 0.7, Math.PI, 0);
            ctx.stroke();
            ctx.beginPath();
            ctx.arc(0, h / 2, 2, 0, Math.PI * 2);
            ctx.moveTo(0, h / 2 + 2);
            ctx.lineTo(0, h / 2 + 6);
            ctx.stroke();
        } else {
            // Computed / Check icon
            ctx.beginPath();
            ctx.moveTo(-s / 2, 0);
            ctx.lineTo(-s / 6, s / 3);
            ctx.lineTo(s / 2, -s / 3);
            ctx.stroke();
        }

        ctx.restore();
    }
}

let securityIcons = [];

// Initialize
function init() {
    dots = [];
    for (let i = 0; i < config.dotCount; i++) {
        dots.push(new Dot());
    }

    // Init Icons
    securityIcons = [];
    for (let i = 0; i < 25; i++) { // Increase density
        securityIcons.push(new SecurityIcon());
    }
}

function animate() {
    requestAnimationFrame(animate);
    ctx.clearRect(0, 0, width, height);

    // Smooth interaction
    config.rotationSpeed += (targetRotationY - config.rotationSpeed) * 0.05;
    const currentSpeed = 0.003 + config.rotationSpeed; // Base speed + mouse influence

    // 1. Draw Background Icons (Floaters)
    securityIcons.forEach(icon => {
        icon.update();
        icon.draw();
    });

    // Update & Project
    dots.forEach(dot => {
        dot.rotate(currentSpeed);
        dot.project();
    });

    // Sort by depth (Z) so we draw back lines first?
    // Actually canvas composite handling is enough for simple dots, but for lines we might want z-sort.
    // dots.sort((a, b) => a.scaleProjected - b.scaleProjected); // Draw far to near

    // Draw Connections
    for (let i = 0; i < dots.length; i++) {
        for (let j = i + 1; j < dots.length; j++) {
            const d1 = dots[i];
            const d2 = dots[j];

            // Optimization: Only check distance in 3D or 2D? 3D is better for "surface" feeling
            // Distance on unit sphere is better, but Euclidean 3D distance is fine for close neighbors
            const dx = d1.xProjected - d2.xProjected;
            const dy = d1.yProjected - d2.yProjected;
            const dist2d = Math.sqrt(dx * dx + dy * dy);

            if (dist2d < config.connectionDistance * d1.scaleProjected) {
                // Opacity based on Z (hide back of sphere lines mostly)
                // if (d1.z < 0 && d2.z < 0) continue; // Skip lines entirely on the back hemisphere?

                // Better: Average z scale
                const scale = (d1.scaleProjected + d2.scaleProjected) / 2;
                const alpha = (1 - dist2d / (config.connectionDistance * scale)) * scale;

                // If both are on back side (scale < 1 roughly), reduce alpha heavily
                const isBack = scale < 0.9;
                if (isBack && alpha < 0.2) continue; // Optimization

                // Create Gradient for line
                const grad = ctx.createLinearGradient(d1.xProjected, d1.yProjected, d2.xProjected, d2.yProjected);

                // Apply alpha to the colors
                const c1 = d1.colorString.replace('1)', `${isBack ? alpha * 0.2 : alpha})`);
                const c2 = d2.colorString.replace('1)', `${isBack ? alpha * 0.2 : alpha})`);

                grad.addColorStop(0, c1);
                grad.addColorStop(1, c2);

                ctx.beginPath();
                ctx.moveTo(d1.xProjected, d1.yProjected);
                ctx.lineTo(d2.xProjected, d2.yProjected);
                ctx.strokeStyle = grad;
                ctx.lineWidth = 0.5 * scale;
                ctx.stroke();
            }
        }
    }

    // Draw Dots (on top of lines)
    dots.forEach(dot => {
        dot.draw();
    });
}

init();
animate();
