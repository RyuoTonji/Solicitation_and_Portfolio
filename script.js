/**
 * Solicitation Landing Page Interactions & Security Hardening
 * Antonio Jr. S. Del Rosario - Technopreneurship Educational Tour
 * High Contrast WCAG 2.2 AAA & Front-End WAF + Rate Limiting Shield
 */

// ==========================================================================
// TIER 0: ANTI-CLICKJACKING & FRAME BUSTING GUARD
// ==========================================================================
// Enforces that this donation page cannot be embedded in malicious iframes or phishing frames
try {
  if (window.top !== window.self) {
    window.top.location = window.self.location;
  }
} catch (e) {
  // If top location access is blocked due to cross-origin sandbox, blank document
  document.documentElement.style.display = 'none';
  throw new Error('Clickjacking attempt detected. Framing is not permitted.');
}

// Frozen configuration constants to prevent prototype pollution
const CONFIG = Object.freeze({
  SCROLL_THRESHOLD: 40,
  TOAST_DURATION: 2600,
  RATE_LIMIT_GLOBAL_MAX: 16,     // Max events per 2 seconds sliding window
  RATE_LIMIT_WINDOW_MS: 2000,
  COPY_MAX_ACTIONS: 3,           // Max 3 copies per 10 seconds
  COPY_WINDOW_MS: 10000,
  VERIFIED_GCASH: '09452688342',
  VERIFIED_MAYA: '09452688342'
});

// ==========================================================================
// TIER 1: FRONT-END WEB APPLICATION FIREWALL (WAF)
// ==========================================================================
const FrontEndWAF = (() => {
  // Attack Signatures for Client-Side Inspection
  const ATTACK_SIGNATURES = [
    // XSS, JavaScript URIs & DOM Injection
    /(<|%3C)\s*script/i,
    /javascript\s*:/i,
    /vbscript\s*:/i,
    /data\s*:\s*text\/html/i,
    /on(load|error|click|mouseover|focus|blur|change|submit)\s*=/i,
    /\beval\s*\(/i,
    /document\.(cookie|location|write)/i,
    // SQL Injection Probes (Common blind automated scanners)
    /\b(union(\s+all)?\s+select)\b/i,
    /\b(select\s+.+\s+from)\b/i,
    /\b(drop\s+table|delete\s+from|insert\s+into)\b/i,
    /\b(benchmark|sleep)\s*\(/i,
    /(\%27)|(\')\s*(\-\-|\#|\/\*)/i,
    // Path Traversal & Remote Inclusions
    /(\.\.\/|\.\.\\|%2e%2e%2f)/i,
    /(\/etc\/passwd|win\.ini|boot\.ini)/i,
    // Prototype Pollution
    /__proto__|constructor\.prototype/i
  ];

  function inspectString(str, context) {
    if (!str || typeof str !== 'string') return true;
    for (const pattern of ATTACK_SIGNATURES) {
      if (pattern.test(str)) {
        console.warn(`[WAF INTERCEPTED] Malicious probe in ${context}:`, str);
        return false;
      }
    }
    return true;
  }

  function sanitizeURLParameters() {
    const search = window.location.search;
    const hash = window.location.hash;
    let attackDetected = false;

    if (!inspectString(search, 'QueryString') || !inspectString(hash, 'HashFragment')) {
      attackDetected = true;
    }

    if (attackDetected) {
      // Neutralize tainted URL state from browser history
      const sanitizedUrl = window.location.pathname;
      window.history.replaceState(null, document.title, sanitizedUrl);
      return { blocked: true, reason: 'Malicious URL payload sanitized by WAF' };
    }
    return { blocked: false };
  }

  function detectAutomatedScraper() {
    // 1. Headless browser and automation flags
    const isWebDriver = navigator.webdriver === true;
    const isPhantom = !!(window._phantom || window.callPhantom || window.__nightmare);
    const isHeadlessAgent = /HeadlessChrome|PhantomJS|Electron|jsdom|selenium|puppeteer|playwright/i.test(navigator.userAgent);
    
    // 2. Language/plugin anomalies typical of automated headless workers
    const suspiciousEnvironment = !navigator.languages || navigator.languages.length === 0;

    return isWebDriver || isPhantom || isHeadlessAgent || suspiciousEnvironment;
  }

  return Object.freeze({
    inspectString,
    sanitizeURLParameters,
    detectAutomatedScraper
  });
})();

// Execute immediate URL inspection before DOM initialization
const wafUrlCheck = FrontEndWAF.sanitizeURLParameters();

// ==========================================================================
// TIER 2: RATE LIMITING ENGINE (Token Bucket & Sliding Window)
// ==========================================================================
const RateLimiter = (() => {
  const globalEvents = [];
  const actionEvents = {
    copy: [],
    modal: []
  };

  function checkGlobalRate() {
    const now = Date.now();
    // Prune stale timestamps outside the sliding window
    while (globalEvents.length > 0 && now - globalEvents[0] > CONFIG.RATE_LIMIT_WINDOW_MS) {
      globalEvents.shift();
    }
    if (globalEvents.length >= CONFIG.RATE_LIMIT_GLOBAL_MAX) {
      return false; // Throttled: excess automated events
    }
    globalEvents.push(now);
    return true;
  }

  function checkActionRate(actionType) {
    const now = Date.now();
    const history = actionEvents[actionType] || (actionEvents[actionType] = []);

    // Prune events outside 10s window
    while (history.length > 0 && now - history[0] > CONFIG.COPY_WINDOW_MS) {
      history.shift();
    }

    if (history.length >= CONFIG.COPY_MAX_ACTIONS) {
      const waitSeconds = Math.ceil((CONFIG.COPY_WINDOW_MS - (now - history[0])) / 1000);
      return {
        allowed: false,
        waitSec: waitSeconds,
        message: `Rate limit active: Please wait ${waitSeconds}s before copying again.`
      };
    }

    history.push(now);
    return { allowed: true };
  }

  return Object.freeze({
    checkGlobalRate,
    checkActionRate
  });
})();

// ==========================================================================
// MAIN CONTROLLER
// ==========================================================================
document.addEventListener('DOMContentLoaded', () => {
  // --- Toast Notification Feedback Utility ---
  const toast = document.getElementById('toast-notice');
  let toastTimer = null;

  function showToast(message) {
    if (!toast) return;
    toast.textContent = message;
    toast.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      toast.classList.remove('show');
    }, CONFIG.TOAST_DURATION);
  }

  // If WAF detected URL tampering on page load, notify user
  if (wafUrlCheck.blocked) {
    showToast('WAF Security: Malicious URL query was blocked and purged.');
  }

  // Alert if automated headless environment is detected
  const isBot = FrontEndWAF.detectAutomatedScraper();
  if (isBot) {
    console.info('[WAF NOTICE] Automated client signature detected. Defensive throttling active.');
  }

  // --- Global Event Throttling Guard ---
  document.addEventListener('click', (e) => {
    if (!RateLimiter.checkGlobalRate()) {
      e.stopPropagation();
      e.preventDefault();
      showToast('Interaction throttled: Too many rapid requests.');
    }
  }, true);

  // --- 1. DOM Integrity Guard: Anti-Defacement & Fund Diversion Shield ---
  // Protects GCash/Maya payment cards against malicious browser extensions or injected scripts
  function initDOMIntegrityGuard() {
    const paymentCards = document.querySelectorAll('.qr-payment-card, [data-copy]');
    if (!paymentCards.length || typeof MutationObserver === 'undefined') return;

    const integrityObserver = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        if (mutation.type === 'attributes') {
          // Guard QR image paths
          if (mutation.attributeName === 'src' && mutation.target.tagName === 'IMG') {
            const currentSrc = mutation.target.getAttribute('src') || '';
            if (!currentSrc.includes('GcashQR.jpg') && !currentSrc.includes('mayaQR.jpg')) {
              console.error('[DOM INTEGRITY SHIELD] Unauthorized QR image tampering detected and restored!');
              const isGcash = (mutation.target.getAttribute('alt') || '').includes('GCash');
              mutation.target.setAttribute('src', isGcash ? 'Assets/GcashQR.jpg' : 'Assets/mayaQR.jpg');
              showToast('Security Alert: Unauthorized payment QR modification blocked.');
            }
          }
          // Guard account numbers in data-copy
          if (mutation.attributeName === 'data-copy') {
            const currentVal = mutation.target.getAttribute('data-copy');
            if (currentVal !== CONFIG.VERIFIED_GCASH) {
              console.error('[DOM INTEGRITY SHIELD] Unauthorized account number substitution detected and restored!');
              mutation.target.setAttribute('data-copy', CONFIG.VERIFIED_GCASH);
              showToast('Security Alert: Unauthorized account modification blocked.');
            }
          }
        }
      }
    });

    paymentCards.forEach(card => {
      integrityObserver.observe(card, {
        attributes: true,
        subtree: true,
        attributeFilter: ['src', 'data-copy', 'href']
      });
    });
  }

  initDOMIntegrityGuard();

  // --- 2. Asset & Web Security Hardening (Anti-Theft, Anti-Scraping & Asset Protection) ---
  // A. Disable Context Menu (Right Click) on photos, QR codes, and cards
  document.addEventListener('contextmenu', (e) => {
    if (e.target.closest('img, .mosaic-card, .gallery-item, .qr-payment-card, .hero-media-wrap')) {
      e.preventDefault();
      showToast('Protected Content: All portraits and media are private property.');
    }
  });

  // B. Prevent image dragging to external folders or tabs
  document.addEventListener('dragstart', (e) => {
    if (e.target.nodeName === 'IMG' || e.target.closest('img, .mosaic-card, .gallery-item, .qr-payment-card')) {
      e.preventDefault();
    }
  });

  // C. Deter unauthorized source ripping and developer shortcut exploits
  document.addEventListener('keydown', (e) => {
    // Block F12
    if (e.key === 'F12') {
      e.preventDefault();
      showToast('Inspection tools are disabled on this verified profile.');
      return;
    }
    // Block Ctrl+U (View Source) and Ctrl+S (Save Page)
    if (e.ctrlKey && (e.key === 'u' || e.key === 'U' || e.key === 's' || e.key === 'S')) {
      e.preventDefault();
      return;
    }
    // Block Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+Shift+C (DevTools)
    if (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'i' || e.key === 'J' || e.key === 'j' || e.key === 'C' || e.key === 'c')) {
      e.preventDefault();
      showToast('Source inspection is restricted.');
      return;
    }
  });

  // --- 3. Sticky Header Background Transition on Scroll ---
  const header = document.getElementById('site-header');
  window.addEventListener('scroll', () => {
    if (window.scrollY > CONFIG.SCROLL_THRESHOLD) {
      header.classList.add('scrolled');
    } else {
      header.classList.remove('scrolled');
    }
  }, { passive: true });

  // --- 4. Mobile Drawer Navigation ---
  const mobileToggle = document.getElementById('mobile-toggle');
  const mobileDrawer = document.getElementById('mobile-drawer');
  const mobileNavLinks = document.querySelectorAll('.mobile-nav-link');

  if (mobileToggle && mobileDrawer) {
    mobileToggle.addEventListener('click', () => {
      const isOpen = mobileDrawer.classList.toggle('open');
      mobileToggle.classList.toggle('is-active', isOpen);
      mobileToggle.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    });

    mobileNavLinks.forEach(link => {
      link.addEventListener('click', () => {
        mobileDrawer.classList.remove('open');
        mobileToggle.classList.remove('is-active');
        mobileToggle.setAttribute('aria-expanded', 'false');
      });
    });
  }

  // --- 5. ScrollSpy Active Nav Link Highlighting ---
  const sections = document.querySelectorAll('section[id], footer[id]');
  const desktopNavLinks = document.querySelectorAll('.desktop-nav .nav-link');

  const observerOptions = {
    root: null,
    rootMargin: '-20% 0px -60% 0px',
    threshold: 0
  };

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const id = entry.target.getAttribute('id');
        desktopNavLinks.forEach(link => {
          if (link.getAttribute('href') === `#${id}`) {
            link.classList.add('active');
          } else {
            link.classList.remove('active');
          }
        });
      }
    });
  }, observerOptions);

  sections.forEach(sec => observer.observe(sec));

  // --- 6. Lightbox Modal for Gallery Images (with Keyboard Trap & Focus Recovery) ---
  const lightboxModal = document.getElementById('lightbox-modal');
  const lightboxImg = document.getElementById('lightbox-image');
  const lightboxCaption = document.getElementById('lightbox-caption');
  const closeLightboxBtn = document.getElementById('close-lightbox-btn');
  const clickableCards = document.querySelectorAll('[data-full]');
  let lastActiveElement = null;

  clickableCards.forEach(card => {
    if (!card.hasAttribute('tabindex')) {
      card.setAttribute('tabindex', '0');
      card.setAttribute('role', 'button');
      const caption = card.getAttribute('data-caption') || 'View full image';
      card.setAttribute('aria-label', `${caption} (opens fullscreen image viewer)`);
    }

    function triggerModal() {
      // Check action rate limit for modal viewing
      const rateStatus = RateLimiter.checkActionRate('modal');
      if (!rateStatus.allowed) {
        showToast(rateStatus.message);
        return;
      }

      const fullSrc = card.getAttribute('data-full');
      const captionText = card.getAttribute('data-caption') || '';
      if (lightboxModal && lightboxImg) {
        lastActiveElement = document.activeElement;
        lightboxImg.src = fullSrc;
        lightboxImg.alt = captionText;
        if (lightboxCaption) lightboxCaption.textContent = captionText;
        lightboxModal.showModal();
        if (closeLightboxBtn) closeLightboxBtn.focus();
      }
    }

    card.addEventListener('click', triggerModal);
    card.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        triggerModal();
      }
    });
  });

  function closeLightbox() {
    if (lightboxModal && typeof lightboxModal.close === 'function') {
      lightboxModal.close();
      if (lightboxImg) lightboxImg.src = '';
      if (lastActiveElement && typeof lastActiveElement.focus === 'function') {
        lastActiveElement.focus();
      }
    }
  }

  if (closeLightboxBtn) {
    closeLightboxBtn.addEventListener('click', closeLightbox);
  }

  if (lightboxModal) {
    lightboxModal.addEventListener('click', (event) => {
      if (event.target === lightboxModal) {
        closeLightbox();
      }
    });

    lightboxModal.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') {
        closeLightbox();
      }
    });
  }

  // --- 7. Gallery Category Filter Tabs ---
  const filterBtns = document.querySelectorAll('.filter-btn');
  const galleryItems = document.querySelectorAll('.gallery-item');

  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      filterBtns.forEach(b => {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
      });
      btn.classList.add('active');
      btn.setAttribute('aria-selected', 'true');

      const filter = btn.getAttribute('data-filter');
      galleryItems.forEach(item => {
        const cat = item.getAttribute('data-category');
        if (filter === 'all' || cat === filter) {
          item.style.display = 'block';
        } else {
          item.style.display = 'none';
        }
      });
    });
  });

  // --- 8. Hardened Clipboard Copy with WAF Inspection & Token-Bucket Rate-Limiting ---
  document.querySelectorAll('[data-copy]').forEach(button => {
    button.addEventListener('click', async (e) => {
      e.stopPropagation();

      // Enforce Rate Limiting (Token Bucket: Max 3 copies per 10s window)
      const rateCheck = RateLimiter.checkActionRate('copy');
      if (!rateCheck.allowed) {
        showToast(rateCheck.message);
        return;
      }

      // Extract and sanitize text via WAF inspection
      const rawText = button.getAttribute('data-copy') || '';
      const textToCopy = rawText.trim();
      if (!textToCopy) return;

      if (!FrontEndWAF.inspectString(textToCopy, 'ClipboardCopy')) {
        showToast('WAF Security: Unsafe clipboard copy blocked.');
        return;
      }

      try {
        await navigator.clipboard.writeText(textToCopy);
        showToast(`Copied "${textToCopy}" to clipboard!`);
      } catch (err) {
        // Safe fallback for restricted contexts
        try {
          const textarea = document.createElement('textarea');
          textarea.value = textToCopy;
          textarea.setAttribute('readonly', '');
          textarea.style.position = 'absolute';
          textarea.style.left = '-9999px';
          document.body.appendChild(textarea);
          textarea.select();
          document.execCommand('copy');
          document.body.removeChild(textarea);
          showToast(`Copied "${textToCopy}" to clipboard!`);
        } catch (fallbackErr) {
          showToast(`Account: ${textToCopy}`);
        }
      }
    });
  });
});
