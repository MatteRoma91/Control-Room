/**
 * Subtle particle field for Control Room (dark mode accent).
 * Respects prefers-reduced-motion and pauses when tab is hidden.
 */
(function () {
  var canvas = document.getElementById('cr-particles');
  if (!canvas) return;

  var reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduced) {
    canvas.style.display = 'none';
    return;
  }

  var ctx = canvas.getContext('2d');
  if (!ctx) return;

  var particles = [];
  var count = 80;
  var rafId = null;
  var running = true;

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }

  function Particle() {
    this.x = Math.random() * canvas.width;
    this.y = Math.random() * canvas.height;
    this.size = Math.random() * 2.5 + 0.5;
    this.speedX = (Math.random() - 0.5) * 0.35;
    this.speedY = (Math.random() - 0.5) * 0.35;
    var isDark = document.documentElement.classList.contains('dark');
    var r = isDark ? Math.floor(Math.random() * 60 + 80) : Math.floor(Math.random() * 40 + 100);
    var g = isDark ? Math.floor(Math.random() * 80 + 160) : Math.floor(Math.random() * 60 + 140);
    var b = isDark ? Math.floor(Math.random() * 40 + 215) : Math.floor(Math.random() * 30 + 180);
    this.color = 'rgba(' + r + ',' + g + ',' + b + ',' + (Math.random() * 0.35 + 0.15) + ')';
  }

  Particle.prototype.update = function () {
    this.x += this.speedX;
    this.y += this.speedY;
    if (this.x > canvas.width) this.x = 0;
    if (this.x < 0) this.x = canvas.width;
    if (this.y > canvas.height) this.y = 0;
    if (this.y < 0) this.y = canvas.height;
  };

  Particle.prototype.draw = function () {
    ctx.fillStyle = this.color;
    ctx.beginPath();
    ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
    ctx.fill();
  };

  function initParticles() {
    particles = [];
    for (var i = 0; i < count; i++) particles.push(new Particle());
  }

  function animate() {
    if (!running) return;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    for (var i = 0; i < particles.length; i++) {
      particles[i].update();
      particles[i].draw();
    }
    rafId = requestAnimationFrame(animate);
  }

  function start() {
    if (running) return;
    running = true;
    animate();
  }

  function stop() {
    running = false;
    if (rafId) cancelAnimationFrame(rafId);
  }

  resize();
  initParticles();
  animate();

  window.addEventListener('resize', function () {
    resize();
    initParticles();
  }, { passive: true });

  document.addEventListener('visibilitychange', function () {
    if (document.hidden) stop();
    else start();
  });

  window.addEventListener('cr-theme-change', function () {
    initParticles();
  });
})();
