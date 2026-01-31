const VanillaTilt = (function () {
    'use strict';

    class VanillaTilt {
        constructor(element, settings = {}) {
            if (!(element instanceof Node)) {
                throw "Can't initialize VanillaTilt because " + element + " is not a Node.";
            }

            this.width = null;
            this.height = null;
            this.clientWidth = null;
            this.clientHeight = null;
            this.left = null;
            this.top = null;

            // DM: Default settings
            this.settings = Object.assign({
                max: 15,            // Max tilt rotation (degrees)
                perspective: 1000,  // Perspective depth
                scale: 1.05,        // Scale on hover
                speed: 400,         // Transition speed (ms)
                easing: "cubic-bezier(.03,.98,.52,.99)",
                glare: true,        // Enable glare effect
                "max-glare": 0.3,   // Opacity of glare
                gyroscope: false    // Disable gyro by default for cleaner mobile exp
            }, settings);

            this.element = element;
            this.init();
        }

        init() {
            this.addEventListeners();
        }

        addEventListeners() {
            this.onMouseEnterBind = this.onMouseEnter.bind(this);
            this.onMouseMoveBind = this.onMouseMove.bind(this);
            this.onMouseLeaveBind = this.onMouseLeave.bind(this);

            this.element.addEventListener("mouseenter", this.onMouseEnterBind);
            this.element.addEventListener("mouseleave", this.onMouseLeaveBind);
            this.element.addEventListener("mousemove", this.onMouseMoveBind);

            if (this.settings.glare) {
                this.prepareGlare();
            }
        }

        prepareGlare() {
            // Create glare element if it doesn't exist
            if (!this.element.querySelector(".js-tilt-glare")) {
                const glareDiv = document.createElement("div");
                glareDiv.classList.add("js-tilt-glare");

                const glareInner = document.createElement("div");
                glareInner.classList.add("js-tilt-glare-inner");

                glareDiv.appendChild(glareInner);
                this.element.appendChild(glareDiv);
            }

            this.glareElementWrapper = this.element.querySelector(".js-tilt-glare");
            this.glareElement = this.element.querySelector(".js-tilt-glare-inner");

            if (this.glareElementWrapper && this.glareElement) {
                // Style glare wrapper
                Object.assign(this.glareElementWrapper.style, {
                    position: "absolute",
                    top: "0",
                    left: "0",
                    width: "100%",
                    height: "100%",
                    overflow: "hidden",
                    "pointer-events": "none",
                    "border-radius": "inherit" // Match card border radius
                });

                // Style glare inner
                Object.assign(this.glareElement.style, {
                    position: "absolute",
                    top: "50%",
                    left: "50%",
                    "pointer-events": "none",
                    "background-image": "linear-gradient(0deg, rgba(255,255,255,0) 0%, rgba(255,255,255,1) 100%)",
                    width: "200%", // Oversize to cover rotation
                    height: "200%",
                    transform: "rotate(180deg) translate(-50%, -50%)",
                    "transform-origin": "0% 0%",
                    opacity: "0"
                });
            }
        }

        onMouseEnter(event) {
            this.updateElementPosition();
            this.element.style.transition = `transform ${this.settings.speed}ms ${this.settings.easing}`;
            if (this.glareElement) {
                this.glareElement.style.transition = `opacity ${this.settings.speed}ms ${this.settings.easing}`;
            }
        }

        onMouseMove(event) {
            if (this.updateElementPosition !== undefined) {
                this.updateElementPosition();
            }

            const x = (event.clientX - this.left) / this.width; // 0 to 1
            const y = (event.clientY - this.top) / this.height; // 0 to 1

            // Calculate rotation
            // X travels from 0 to 1. If 0 (left), we want negative rotation (rotateY).
            const rotateX = (this.settings.max * -1) + (y * this.settings.max * 2);
            const rotateY = (this.settings.max) - (x * this.settings.max * 2);

            this.element.style.transform =
                `perspective(${this.settings.perspective}px) ` +
                `rotateX(${rotateX}deg) ` +
                `rotateY(${rotateY}deg) ` +
                `scale3d(${this.settings.scale}, ${this.settings.scale}, ${this.settings.scale})`;

            if (this.settings.glare && this.glareElement) {
                const glareOpacity = (event.clientY - this.top) / this.height * this.settings["max-glare"];
                const glareAngle = (x * 90) - 45; // angle based on X position

                this.glareElement.style.transform = `rotate(${glareAngle}deg) translate(-50%, -50%)`;
                this.glareElement.style.opacity = `${glareOpacity}`;
            }
        }

        onMouseLeave(event) {
            this.element.style.transition = `transform ${this.settings.speed}ms ${this.settings.easing}`;
            this.element.style.transform = `perspective(${this.settings.perspective}px) rotateX(0deg) rotateY(0deg) scale3d(1, 1, 1)`;

            if (this.glareElement) {
                this.glareElement.style.transition = `opacity ${this.settings.speed}ms ${this.settings.easing}`;
                this.glareElement.style.opacity = "0";
            }
        }

        updateElementPosition() {
            const rect = this.element.getBoundingClientRect();
            this.width = this.element.offsetWidth;
            this.height = this.element.offsetHeight;
            this.left = rect.left;
            this.top = rect.top;
        }
    }

    return {
        init: function (elements, settings) {
            if (elements instanceof Node) {
                elements = [elements];
            }
            if (elements instanceof NodeList) {
                elements = [].slice.call(elements);
            }

            if (!(elements instanceof Array)) {
                return;
            }

            elements.forEach((element) => {
                if (!("vanillaTilt" in element)) {
                    element.vanillaTilt = new VanillaTilt(element, settings);
                }
            });
        }
    };
})();

// Auto-init on DOM Load for .benefit-card
document.addEventListener("DOMContentLoaded", function () {
    VanillaTilt.init(document.querySelectorAll(".benefit-card"), {
        max: 12,
        speed: 400,
        glare: true,
        "max-glare": 0.2,
        scale: 1.05
    });
});
