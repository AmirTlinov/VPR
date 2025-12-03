/**
 * VPR Flagship Particle Globe
 *
 * Canvas 2D implementation with manual 3D->2D projection
 * No WebGL dependency - works in webkit2gtk
 *
 * Features:
 * - Fibonacci sphere particle distribution
 * - Smooth rotation with easing
 * - Mouse interaction (disperse on hover)
 * - State-based color transitions
 * - Depth-based particle sizing and opacity
 * - Connection lines between nearby particles
 */

class ParticleGlobe {
  constructor(container, options = {}) {
    this.container = container;
    this.options = {
      particleCount: 400,
      radius: 70,
      rotationSpeed: 0.003,
      mouseInfluence: 60,
      particleMinSize: 1.0,
      particleMaxSize: 3.0,
      connectionDistance: 25,
      connectionOpacity: 0.15,
      maxConnections: 150,
      ...options
    };

    // State
    this.state = 'disconnected'; // disconnected, connecting, connected, error
    this.rotation = { x: 0.4, y: 0, z: 0 };
    this.targetRotation = { x: 0.4, y: 0, z: 0 };
    this.mouse = { x: 0, y: 0, active: false };
    this.particles = [];
    this.time = 0;
    this.animationId = null;
    this.needsResize = true;       // Request resize on next frame

    // Colors per state [r, g, b]
    this.colors = {
      disconnected: {
        primary: [100, 140, 180],
        glow: [80, 120, 160],
        core: [200, 220, 255]
      },
      connecting: {
        primary: [255, 140, 60],
        glow: [255, 107, 53],
        core: [255, 220, 180]
      },
      connected: {
        primary: [40, 200, 140],
        glow: [16, 185, 129],
        core: [150, 255, 220]
      },
      error: {
        primary: [240, 80, 80],
        glow: [239, 68, 68],
        core: [255, 180, 180]
      }
    };

    this.currentColors = this.deepClone(this.colors.disconnected);
    this.targetColors = this.deepClone(this.colors.disconnected);

    this.init();
  }

  deepClone(obj) {
    return JSON.parse(JSON.stringify(obj));
  }

  init() {
    // Create canvas
    this.canvas = document.createElement('canvas');
    this.canvas.style.cssText = 'width: 100%; height: 100%; display: block;';
    this.container.innerHTML = '';
    this.container.appendChild(this.canvas);
    this.ctx = this.canvas.getContext('2d');

    // Set size synchronously for initial setup
    this._doResize();

    // Window resize listener - request resize on next frame
    window.addEventListener('resize', () => this.resize());

    // Mouse events
    this.canvas.addEventListener('mousemove', (e) => this.onMouseMove(e));
    this.canvas.addEventListener('mouseenter', () => { this.mouse.active = true; });
    this.canvas.addEventListener('mouseleave', () => { this.mouse.active = false; });

    // Generate particles on Fibonacci sphere
    this.generateParticles();

    // Start animation
    this.animate();
  }

  resize() {
    // Mark resize request; handled in animation loop to avoid jank
    this.needsResize = true;
  }

  _doResize() {
    const rect = this.container.getBoundingClientRect();
    const dpr = Math.min(window.devicePixelRatio || 1, 1.5);

    // Use fallback size if container is hidden/too small
    const newWidth = rect.width > 50 ? rect.width : 300;
    const newHeight = rect.height > 50 ? rect.height : 300;

    // Skip if dimensions haven't changed
    if (this.width === newWidth && this.height === newHeight && this.dpr === dpr) {
      return true;
    }

    this.width = newWidth;
    this.height = newHeight;
    this.dpr = dpr;

    // Set canvas buffer size
    this.canvas.width = Math.floor(this.width * dpr);
    this.canvas.height = Math.floor(this.height * dpr);

    // Set canvas CSS size to match container
    this.canvas.style.width = this.width + 'px';
    this.canvas.style.height = this.height + 'px';

    // Get fresh context after canvas resize
    this.ctx = this.canvas.getContext('2d');
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    // Center of canvas
    this.centerX = this.width / 2;
    this.centerY = this.height / 2;

    // Scale radius based on SMALLER dimension to keep globe circular
    const minDim = Math.min(this.width, this.height);
    this.options.radius = minDim * 0.38;

    // Scale dependent distances/sizes with radius so the globe does not look tiny on startup
    this.options.connectionDistance = Math.max(26, this.options.radius * 0.24);
    this.options.particleMinSize = Math.max(1.2, minDim * 0.0055);
    this.options.particleMaxSize = Math.max(this.options.particleMinSize + 1.4, minDim * 0.0085);

    return true;
  }

  generateParticles() {
    this.particles = [];
    const n = this.options.particleCount;
    const goldenAngle = Math.PI * (3 - Math.sqrt(5));

    for (let i = 0; i < n; i++) {
      const y = 1 - (i / (n - 1)) * 2; // y from 1 to -1
      const radiusAtY = Math.sqrt(1 - y * y);
      const theta = goldenAngle * i;

      const x = Math.cos(theta) * radiusAtY;
      const z = Math.sin(theta) * radiusAtY;

      this.particles.push({
        // Base position on unit sphere
        baseX: x,
        baseY: y,
        baseZ: z,
        // Current position (animated)
        x: x,
        y: y,
        z: z,
        // Offset for wave animation
        offset: Math.random() * Math.PI * 2,
        // Size variation
        sizeMultiplier: 0.6 + Math.random() * 0.8,
        // Velocity for dispersion
        vx: 0,
        vy: 0,
        vz: 0
      });
    }
  }

  onMouseMove(e) {
    const rect = this.canvas.getBoundingClientRect();
    this.mouse.x = e.clientX - rect.left - this.centerX;
    this.mouse.y = e.clientY - rect.top - this.centerY;
  }

  setState(state) {
    if (this.state === state) return;
    this.state = state;

    // Update target colors
    this.targetColors = this.deepClone(this.colors[state] || this.colors.disconnected);

    // Adjust rotation speed for connecting state
    if (state === 'connecting') {
      this.options.rotationSpeed = 0.012;
    } else {
      this.options.rotationSpeed = 0.003;
    }
  }

  rotatePoint(x, y, z) {
    // Rotate around Y axis
    let cosY = Math.cos(this.rotation.y);
    let sinY = Math.sin(this.rotation.y);
    let x1 = x * cosY - z * sinY;
    let z1 = x * sinY + z * cosY;

    // Rotate around X axis
    let cosX = Math.cos(this.rotation.x);
    let sinX = Math.sin(this.rotation.x);
    let y1 = y * cosX - z1 * sinX;
    let z2 = y * sinX + z1 * cosX;

    return { x: x1, y: y1, z: z2 };
  }

  project(x, y, z) {
    // Simple perspective projection
    const fov = 250;
    const scale = fov / (fov + z * 40);

    return {
      x: x * this.options.radius * scale + this.centerX,
      y: y * this.options.radius * scale + this.centerY,
      scale: scale,
      z: z
    };
  }

  lerpColor(current, target, factor) {
    return current.map((c, i) => c + (target[i] - c) * factor);
  }

  update() {
    this.time += 0.016; // ~60fps

    // Auto-rotate Y
    this.targetRotation.y += this.options.rotationSpeed;

    // Smooth rotation
    this.rotation.x += (this.targetRotation.x - this.rotation.x) * 0.05;
    this.rotation.y += (this.targetRotation.y - this.rotation.y) * 0.1;

    // Smooth color transition
    const colorLerp = 0.04;
    this.currentColors.primary = this.lerpColor(this.currentColors.primary, this.targetColors.primary, colorLerp);
    this.currentColors.glow = this.lerpColor(this.currentColors.glow, this.targetColors.glow, colorLerp);
    this.currentColors.core = this.lerpColor(this.currentColors.core, this.targetColors.core, colorLerp);

    // Update particles
    for (let p of this.particles) {
      // Breathing/wave effect
      const wave = Math.sin(this.time * 2 + p.offset) * 0.015;
      const breathingScale = 1 + wave;

      // Calculate target position
      let targetX = p.baseX * breathingScale;
      let targetY = p.baseY * breathingScale;
      let targetZ = p.baseZ * breathingScale;

      // Mouse influence (dispersion)
      if (this.mouse.active) {
        const rotated = this.rotatePoint(p.baseX, p.baseY, p.baseZ);
        const projected = this.project(rotated.x, rotated.y, rotated.z);

        const dx = projected.x - (this.mouse.x + this.centerX);
        const dy = projected.y - (this.mouse.y + this.centerY);
        const dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < this.options.mouseInfluence) {
          const force = (1 - dist / this.options.mouseInfluence) * 0.5;
          // Push outward from mouse
          p.vx += (p.baseX * force);
          p.vy += (p.baseY * force);
          p.vz += (p.baseZ * force);
        }
      }

      // Apply velocity with damping
      targetX += p.vx;
      targetY += p.vy;
      targetZ += p.vz;

      p.vx *= 0.85;
      p.vy *= 0.85;
      p.vz *= 0.85;

      // Return to base position
      p.x += (targetX - p.x) * 0.15;
      p.y += (targetY - p.y) * 0.15;
      p.z += (targetZ - p.z) * 0.15;
    }
  }

  draw() {
    const ctx = this.ctx;

    // Clear canvas completely (transparent background)
    ctx.clearRect(0, 0, this.width, this.height);

    // Draw outer glow
    this.drawGlow();

    // Transform and sort particles by Z (painter's algorithm)
    const projected = this.particles.map(p => {
      const rotated = this.rotatePoint(p.x, p.y, p.z);
      const proj = this.project(rotated.x, rotated.y, rotated.z);
      return { ...proj, particle: p };
    });

    projected.sort((a, b) => a.z - b.z);

    // Draw connections (only for nearby particles)
    this.drawConnections(projected);

    // Draw particles
    for (const p of projected) {
      this.drawParticle(p);
    }

    // Draw core glow
    this.drawCore();
  }

  drawGlow() {
    const ctx = this.ctx;
    const [r, g, b] = this.currentColors.glow;

    const gradient = ctx.createRadialGradient(
      this.centerX, this.centerY, 0,
      this.centerX, this.centerY, this.options.radius * 1.6
    );

    gradient.addColorStop(0, `rgba(${r}, ${g}, ${b}, 0.12)`);
    gradient.addColorStop(0.5, `rgba(${r}, ${g}, ${b}, 0.04)`);
    gradient.addColorStop(1, 'rgba(0, 0, 0, 0)');

    ctx.fillStyle = gradient;
    ctx.fillRect(0, 0, this.width, this.height);
  }

  drawCore() {
    const ctx = this.ctx;
    const [r, g, b] = this.currentColors.core;
    const pulse = 0.7 + Math.sin(this.time * 3) * 0.3;

    const gradient = ctx.createRadialGradient(
      this.centerX, this.centerY, 0,
      this.centerX, this.centerY, 12 * pulse
    );

    gradient.addColorStop(0, `rgba(${r}, ${g}, ${b}, 0.9)`);
    gradient.addColorStop(0.4, `rgba(${r}, ${g}, ${b}, 0.3)`);
    gradient.addColorStop(1, 'rgba(0, 0, 0, 0)');

    ctx.fillStyle = gradient;
    ctx.beginPath();
    ctx.arc(this.centerX, this.centerY, 18 * pulse, 0, Math.PI * 2);
    ctx.fill();
  }

  drawConnections(projected) {
    const ctx = this.ctx;
    const [r, g, b] = this.currentColors.primary;
    const connDist = this.options.connectionDistance;
    const connDistSq = connDist * connDist; // Avoid sqrt
    const maxConns = this.options.maxConnections;

    // Only draw connections for front-facing particles
    const frontParticles = projected.filter(p => p.z > -0.2);
    const len = frontParticles.length;

    ctx.lineWidth = 0.5;

    // Batch similar opacity lines together to reduce state changes
    let connectionCount = 0;

    for (let i = 0; i < len && connectionCount < maxConns; i++) {
      const p1 = frontParticles[i];

      for (let j = i + 1; j < len && connectionCount < maxConns; j++) {
        const p2 = frontParticles[j];

        const dx = p1.x - p2.x;
        const dy = p1.y - p2.y;
        const distSq = dx * dx + dy * dy;

        if (distSq < connDistSq) {
          const dist = Math.sqrt(distSq);
          const opacity = (1 - dist / connDist) *
                          this.options.connectionOpacity *
                          Math.min(p1.scale, p2.scale);

          ctx.beginPath();
          ctx.moveTo(p1.x, p1.y);
          ctx.lineTo(p2.x, p2.y);
          ctx.strokeStyle = `rgba(${r}, ${g}, ${b}, ${opacity.toFixed(2)})`;
          ctx.stroke();

          connectionCount++;
        }
      }
    }
  }

  drawParticle(p) {
    const ctx = this.ctx;
    const [r, g, b] = this.currentColors.primary;

    // Size based on depth and particle's own size
    const baseSize = this.options.particleMinSize +
                     (this.options.particleMaxSize - this.options.particleMinSize) * p.scale;
    const size = baseSize * p.particle.sizeMultiplier;

    // Opacity based on depth (back particles are dimmer)
    const depthOpacity = 0.25 + p.scale * 0.75;

    // Draw outer glow as simple circle (much faster than gradient)
    ctx.globalAlpha = depthOpacity * 0.3;
    ctx.fillStyle = `rgb(${r}, ${g}, ${b})`;
    ctx.beginPath();
    ctx.arc(p.x, p.y, size * 2, 0, Math.PI * 2);
    ctx.fill();

    // Draw main particle
    ctx.globalAlpha = depthOpacity * 0.8;
    ctx.beginPath();
    ctx.arc(p.x, p.y, size, 0, Math.PI * 2);
    ctx.fill();

    // Core dot (white highlight)
    ctx.globalAlpha = depthOpacity * 0.9;
    ctx.fillStyle = '#fff';
    ctx.beginPath();
    ctx.arc(p.x, p.y, size * 0.35, 0, Math.PI * 2);
    ctx.fill();

    ctx.globalAlpha = 1;
  }

  animate() {
    if (this.needsResize) {
      const resized = this._doResize();
      // Keep requesting resize until container is visible and applied
      this.needsResize = !resized;
    }

    this.update();
    this.draw();

    this.animationId = requestAnimationFrame(() => this.animate());
  }

  destroy() {
    if (this.animationId) {
      cancelAnimationFrame(this.animationId);
    }
  }
}

// Export for use in app.js
window.ParticleGlobe = ParticleGlobe;
