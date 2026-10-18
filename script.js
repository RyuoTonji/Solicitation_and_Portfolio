/**
 * Solicitation Landing Page Interactions & Security Hardening
 * Antonio Jr. S. Del Rosario - Technopreneurship Educational Tour
 * Built with WCAG 2.2 AAA Contrast and Anti-Threat & Asset Protection
 */

// --- 0. Security Guard: Anti-Clickjacking & Frame Busting ---
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
  COPY_COOLDOWN: 400
});

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

  // --- 1. Asset & Web Security Hardening (Anti-Theft, Anti-Scraping & Asset Protection) ---
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

  // --- 2. Sticky Header Background Transition on Scroll ---
  const header = document.getElementById('site-header');
  window.addEventListener('scroll', () => {
    if (window.scrollY > CONFIG.SCROLL_THRESHOLD) {
      header.classList.add('scrolled');
    } else {
      header.classList.remove('scrolled');
    }
  }, { passive: true });

  // --- 3. Mobile Drawer Navigation ---
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

  // --- 4. ScrollSpy Active Nav Link Highlighting ---
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

  // --- 5. Lightbox Modal for Gallery Images (with Keyboard Trap & Focus Recovery) ---
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

  // --- 6. Gallery Category Filter Tabs ---
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

  // --- 7. Hardened Clipboard Copy with Rate-Limiting & Toast Feedback ---
  let lastCopyTimestamp = 0;

  document.querySelectorAll('[data-copy]').forEach(button => {
    button.addEventListener('click', async (e) => {
      e.stopPropagation();
      const now = Date.now();
      if (now - lastCopyTimestamp < CONFIG.COPY_COOLDOWN) {
        return; // Prevent flood / spamming clicks
      }
      lastCopyTimestamp = now;

      // Extract and sanitize text
      const rawText = button.getAttribute('data-copy') || '';
      const textToCopy = rawText.trim();
      if (!textToCopy) return;

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
