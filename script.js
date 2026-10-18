/**
 * Solicitation Landing Page Interactions
 * Antonio Jr. S. Del Rosario - Technopreneurship Educational Tour
 */

document.addEventListener('DOMContentLoaded', () => {
  // --- 1. Sticky Header Background Transition on Scroll ---
  const header = document.getElementById('site-header');
  window.addEventListener('scroll', () => {
    if (window.scrollY > 40) {
      header.classList.add('scrolled');
    } else {
      header.classList.remove('scrolled');
    }
  }, { passive: true });

  // --- 2. Mobile Drawer Navigation ---
  const mobileToggle = document.getElementById('mobile-toggle');
  const mobileDrawer = document.getElementById('mobile-drawer');
  const mobileNavLinks = document.querySelectorAll('.mobile-nav-link');

  if (mobileToggle && mobileDrawer) {
    mobileToggle.addEventListener('click', () => {
      const isOpen = mobileDrawer.classList.toggle('open');
      mobileToggle.classList.toggle('is-active', isOpen);
      mobileToggle.setAttribute('aria-expanded', isOpen);
    });

    mobileNavLinks.forEach(link => {
      link.addEventListener('click', () => {
        mobileDrawer.classList.remove('open');
        mobileToggle.classList.remove('is-active');
        mobileToggle.setAttribute('aria-expanded', 'false');
      });
    });
  }

  // --- 3. ScrollSpy Active Nav Link Highlighting ---
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

  // --- 4. Lightbox Modal for Gallery Images ---
  const lightboxModal = document.getElementById('lightbox-modal');
  const lightboxImg = document.getElementById('lightbox-image');
  const lightboxCaption = document.getElementById('lightbox-caption');
  const closeLightboxBtn = document.getElementById('close-lightbox-btn');
  const clickableCards = document.querySelectorAll('[data-full]');

  clickableCards.forEach(card => {
    card.addEventListener('click', () => {
      const fullSrc = card.getAttribute('data-full');
      const captionText = card.getAttribute('data-caption') || '';
      if (lightboxModal && lightboxImg) {
        lightboxImg.src = fullSrc;
        lightboxImg.alt = captionText;
        if (lightboxCaption) lightboxCaption.textContent = captionText;
        lightboxModal.showModal();
      }
    });
  });

  function closeLightbox() {
    if (lightboxModal && typeof lightboxModal.close === 'function') {
      lightboxModal.close();
      if (lightboxImg) lightboxImg.src = '';
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
  }

  // --- 5. Gallery Category Filter Tabs ---
  const filterBtns = document.querySelectorAll('.filter-btn');
  const galleryItems = document.querySelectorAll('.gallery-item');

  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      filterBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

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

  // --- 6. Clipboard Copy & Toast Feedback ---
  const toast = document.getElementById('toast-notice');
  let toastTimer = null;

  function showToast(message) {
    if (!toast) return;
    toast.textContent = message;
    toast.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      toast.classList.remove('show');
    }, 2500);
  }

  document.querySelectorAll('[data-copy]').forEach(button => {
    button.addEventListener('click', async (e) => {
      e.stopPropagation();
      const textToCopy = button.getAttribute('data-copy');
      try {
        await navigator.clipboard.writeText(textToCopy);
        showToast(`Copied "${textToCopy}" to clipboard!`);
      } catch (err) {
        // Fallback for older browsers
        const textarea = document.createElement('textarea');
        textarea.value = textToCopy;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        showToast(`Copied "${textToCopy}" to clipboard!`);
      }
    });
  });
});
