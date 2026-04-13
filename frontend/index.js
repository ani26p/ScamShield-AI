// ── ScamShield Index Scripts ──

document.addEventListener('DOMContentLoaded', () => {
    // Register GSAP ScrollTrigger
    if (window.gsap && window.ScrollTrigger) {
        gsap.registerPlugin(ScrollTrigger);
    }

    const hero = document.getElementById('hero');
    const heroGlow = document.getElementById('hero-glow');

    // Mouse movement reactivity for hero glow
    if (hero && heroGlow) {
        window.addEventListener('mousemove', (e) => {
            const { clientX, clientY } = e;
            hero.style.setProperty('--mouse-x', `${clientX}px`);
            hero.style.setProperty('--mouse-y', `${clientY}px`);

            const title = document.querySelector('.hero-title');
            if (title) {
                const moveX = (clientX - window.innerWidth / 2) / 80;
                const moveY = (clientY - window.innerHeight / 2) / 80;
                title.style.transform = `translate(${moveX}px, ${moveY}px)`;
            }
        });
    }

    // Search logic
    const urlInput = document.getElementById('url-input');
    const analyzeBtn = document.getElementById('analyze-btn');

    const handleSearch = () => {
        const url = urlInput.value.trim();
        if (url) {
            window.location.href = `analyze.html?url=${encodeURIComponent(url)}`;
        } else {
            urlInput.focus();
            urlInput.classList.add('error-pulse');
            setTimeout(() => urlInput.classList.remove('error-pulse'), 500);
        }
    };

    if (analyzeBtn) analyzeBtn.addEventListener('click', handleSearch);
    if (urlInput) {
        urlInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') handleSearch();
        });
    }

    // GSAP reveal animations
    if (window.gsap && window.ScrollTrigger) {
        // Hero reveal
        gsap.from('.pill-nav', { y: -100, opacity: 0, duration: 1, ease: 'back.out(1.7)', delay: 0.5 });

        // Features reveal
        gsap.utils.toArray('.feat-card').forEach((card, i) => {
            gsap.from(card, {
                opacity: 0,
                y: 60,
                duration: 1,
                delay: i * 0.1,
                ease: 'power3.out',
                scrollTrigger: {
                    trigger: card,
                    start: 'top 90%',
                }
            });
        });

        // Pipeline steps reveal
        gsap.utils.toArray('.pipe-step').forEach((step, i) => {
            gsap.from(step, {
                opacity: 0,
                x: -50,
                duration: 1,
                delay: i * 0.2,
                ease: 'power2.out',
                scrollTrigger: {
                    trigger: step,
                    start: 'top 85%',
                }
            });
        });

        // Dock active state update on scroll
        const sections = ['#hero', '#features', '#how-it-works', '#search'];
        sections.forEach(id => {
            ScrollTrigger.create({
                trigger: id,
                start: 'top center',
                end: 'bottom center',
                onEnter: () => updateDock(id),
                onEnterBack: () => updateDock(id)
            });
        });
    }

    // High-Performance Logo Loop Controller
    class LogoLoopController {
        constructor(selector, speed = 80) {
            this.container = document.querySelector(selector);
            if (!this.container) return;

            this.track = this.container.querySelector('.marquee-track');
            this.sequence = this.container.querySelector('.marquee-sequence');

            this.speed = speed;
            this.targetVelocity = speed;
            this.velocity = speed;
            this.offset = 0;
            this.lastTimestamp = null;
            this.isHovered = false;
            this.tau = 0.25; // Smoothing factor

            this.init();
        }

        init() {
            this.updateCopies();

            // Resize handler
            const ro = new ResizeObserver(() => this.updateCopies());
            ro.observe(this.container);

            // Interaction
            this.container.addEventListener('mouseenter', () => {
                this.isHovered = true;
                this.targetVelocity = 0; // Pause on hover
            });
            this.container.addEventListener('mouseleave', () => {
                this.isHovered = false;
                this.targetVelocity = this.speed;
            });

            // Start loop
            this.raf = requestAnimationFrame((t) => this.animate(t));
        }

        updateCopies() {
            const containerWidth = this.container.clientWidth;
            const sequenceWidth = this.sequence.offsetWidth;
            if (sequenceWidth <= 0) return;

            const needed = Math.ceil(containerWidth / sequenceWidth) + 2;
            const current = this.track.children.length;

            if (needed > current) {
                for (let i = 0; i < needed - current; i++) {
                    const clone = this.sequence.cloneNode(true);
                    clone.setAttribute('aria-hidden', 'true');
                    this.track.appendChild(clone);
                }
            }
        }

        animate(timestamp) {
            if (!this.lastTimestamp) this.lastTimestamp = timestamp;
            const delta = (timestamp - this.lastTimestamp) / 1000;
            this.lastTimestamp = timestamp;

            // Velocity interpolation (smoothing)
            const easingFactor = 1 - Math.exp(-delta / this.tau);
            this.velocity += (this.targetVelocity - this.velocity) * easingFactor;

            // Position update
            const sequenceWidth = this.sequence.offsetWidth;
            if (sequenceWidth > 0) {
                this.offset += this.velocity * delta;
                this.offset = ((this.offset % sequenceWidth) + sequenceWidth) % sequenceWidth;

                // transform3d for GPU acceleration
                this.track.style.transform = `translate3d(${-this.offset}px, 0, 0)`;
            }

            this.raf = requestAnimationFrame((t) => this.animate(t));
        }
    }

    // ── Elastic CardSwap Controller (Final Refinement) ──
    class CardSwapController {
        constructor(selector, options = {}) {
            this.container = document.querySelector(selector);
            if (!this.container) return;

            this.cards = Array.from(this.container.querySelectorAll('.card-swap-card'));
            if (this.cards.length < 2) return;

            // Config match from snippet
            this.cardDistance = options.cardDistance || 60;
            this.verticalDistance = options.verticalDistance || 70;
            this.delay = options.delay || 5000;
            this.skewAmount = options.skewAmount || 6;
            this.pauseOnHover = options.pauseOnHover || false;

            this.config = {
                ease: 'elastic.out(0.6,0.9)',
                durDrop: 2,
                durMove: 2,
                durReturn: 2,
                promoteOverlap: 0.9,
                returnDelay: 0.05
            };

            this.order = Array.from({ length: this.cards.length }, (_, i) => i);
            this.tl = null;
            this.interval = null;

            this.init();
        }

        makeSlot(i, total) {
            return {
                x: i * this.cardDistance,
                y: -i * this.verticalDistance,
                z: -i * this.cardDistance * 1.5,
                zIndex: total - i
            };
        }

        placeNow(el, slot, skew) {
            gsap.set(el, {
                x: slot.x,
                y: slot.y,
                z: slot.z,
                xPercent: -50,
                yPercent: -50,
                skewY: skew,
                transformOrigin: 'center center',
                zIndex: slot.zIndex,
                force3D: true
            });
        }

        init() {
            const total = this.cards.length;
            this.cards.forEach((el, i) => {
                this.placeNow(el, this.makeSlot(i, total), this.skewAmount);
            });

            this.startInterval();

            if (this.pauseOnHover) {
                this.container.addEventListener('mouseenter', () => this.pause());
                this.container.addEventListener('mouseleave', () => this.resume());
            }
        }

        startInterval() {
            this.interval = setInterval(() => this.swap(), this.delay);
        }

        pause() {
            if (this.tl) this.tl.pause();
            clearInterval(this.interval);
        }

        resume() {
            if (this.tl) this.tl.play();
            this.startInterval();
        }

        swap() {
            if (this.order.length < 2) return;

            const [front, ...rest] = this.order;
            const elFront = this.cards[front];
            this.tl = gsap.timeline();

            // 1. Drop down
            this.tl.to(elFront, {
                y: '+=500',
                duration: this.config.durDrop,
                ease: this.config.ease
            });

            // 2. Promote others
            this.tl.addLabel('promote', `-=${this.config.durDrop * this.config.promoteOverlap}`);
            rest.forEach((idx, i) => {
                const el = this.cards[idx];
                const slot = this.makeSlot(i, this.cards.length);
                this.tl.set(el, { zIndex: slot.zIndex }, 'promote');
                this.tl.to(el, {
                    x: slot.x,
                    y: slot.y,
                    z: slot.z,
                    duration: this.config.durMove,
                    ease: this.config.ease
                }, `promote+=${i * 0.15}`);
            });

            // 3. Return front to back
            const backSlot = this.makeSlot(this.cards.length - 1, this.cards.length);
            this.tl.addLabel('return', `promote+=${this.config.durMove * this.config.returnDelay}`);
            this.tl.call(() => {
                gsap.set(elFront, { zIndex: backSlot.zIndex });
            }, null, 'return');

            this.tl.to(elFront, {
                x: backSlot.x,
                y: backSlot.y,
                z: backSlot.z,
                duration: this.config.durReturn,
                ease: this.config.ease
            }, 'return');

            this.tl.call(() => {
                this.order = [...rest, front];
            });
        }
    }

    // ── Workflow Scroll Animation (Path Drawing & Step Reveal) ──
    function initWorkflowAnimation() {
        gsap.registerPlugin(ScrollTrigger);

        const pathFill = document.querySelector('#workflow-path-fill');
        if (pathFill) {
            // Draw the line as you scroll
            gsap.to(pathFill, {
                strokeDashoffset: 0,
                ease: "none",
                scrollTrigger: {
                    trigger: ".workflow-timeline",
                    start: "top center",
                    end: "bottom center",
                    scrub: 1
                }
            });
        }

        // Reveal steps on scroll
        const steps = document.querySelectorAll('.workflow-step-v2');
        steps.forEach((step, index) => {
            ScrollTrigger.create({
                trigger: step,
                start: "top 80%",
                onEnter: () => step.classList.add('is-active'),
                onLeaveBack: () => step.classList.remove('is-active')
            });
        });
    }

    // Initialize Components
    new LogoLoopController('#logo-loop', 60);
    new CardSwapController('#card-swap-container', {
        cardDistance: 60,
        verticalDistance: 70,
        delay: 5000,
        pauseOnHover: false
    });
    initWorkflowAnimation();
    new LogoLoopController('#reviews-loop', -40);

    function updateDock(id) {
        document.querySelectorAll('.dock-item').forEach(item => {
            item.classList.toggle('active', item.getAttribute('href') === id);
        });
    }

    // Dock Magnification Logic
    const dockItems = document.querySelectorAll('.dock-item');
    dockItems.forEach(item => {
        item.addEventListener('mousemove', (e) => {
            const rect = item.getBoundingClientRect();
            const offset = e.clientY - rect.top - rect.height / 2;
            const t = Math.abs(offset) / (rect.height / 2);
            const scale = 1.3 - (t * 0.3);
            item.style.transform = `scale(${scale}) translateX(${(1 - t) * 10}px)`;
        });
        item.addEventListener('mouseleave', () => {
            item.style.transform = 'scale(1) translateX(0)';
        });
    });
});
