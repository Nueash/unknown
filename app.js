/* ==========================================================================
   Shreshthaa Multi Speciality Dental Clinic — Main JavaScript Logic
   Security hardened: XSS-safe DOM construction, input validation,
   rate limiting, duplicate-submit prevention, allowlist enforcement.
   ========================================================================== */

'use strict';

/* ── Security helpers ──────────────────────────────────────────────────── */

/** Escape HTML entities so no raw user input is ever written as markup */
function escapeHtml(str) {
    if (typeof str !== 'string') return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}

/** Strip everything except safe name characters */
function sanitizeName(val) {
    return val.replace(/[^a-zA-Z\u0900-\u097F\s.'-]/g, '').slice(0, 80);
}

/** Accept only 10-digit Indian mobile numbers */
function isValidPhone(val) {
    return /^[6-9]\d{9}$/.test(val.replace(/\s/g, ''));
}

/** Hard allowlist for service dropdown values */
const ALLOWED_SERVICES = new Set([
    'Tooth Pain / Consultation',
    'Root Canal Treatment',
    'Teeth Cleaning & Scaling',
    'Crowns & Bridges',
    'Tooth Filling',
    'Dental Implants',
    'General Dental Checkup',
    'Tooth Pain Relief',
    'Teeth Cleaning',
    'Filling',
    'Implants / Consultation',
    'Checkup',
]);

/** Hard allowlist for time-slot dropdown values */
const ALLOWED_TIMES = new Set([
    'Morning (9:00 AM - 12:00 PM)',
    'Afternoon (12:00 PM - 4:00 PM)',
    'Evening (4:00 PM - 7:00 PM)',
    'Night (7:00 PM - 9:30 PM)',
    'Morning',
    'Afternoon',
    'Evening',
    'Night',
]);

/** Simple rate-limiter: max 3 submissions per 5 minutes per session */
const _submissionLog = [];
function isRateLimited() {
    const now = Date.now();
    const window = 5 * 60 * 1000; // 5 minutes
    const recentCount = _submissionLog.filter(t => now - t < window).length;
    if (recentCount >= 3) return true;
    _submissionLog.push(now);
    return false;
}

/** Prevent past dates being selected */
function getMinDate() {
    return new Date().toISOString().split('T')[0];
}

function getTomorrowDate() {
    return new Date(Date.now() + 86400000).toISOString().split('T')[0];
}

/* ── Safe DOM element builder (no innerHTML with user data) ────────────── */
function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    if (attrs) {
        Object.entries(attrs).forEach(([k, v]) => {
            if (k === 'className') node.className = v;
            else if (k === 'style') node.style.cssText = v;
            else node.setAttribute(k, v);
        });
    }
    children.forEach(child => {
        if (child == null) return;
        node.appendChild(typeof child === 'string'
            ? document.createTextNode(child)
            : child);
    });
    return node;
}

/* ── Static treatment data (no user input — safe for innerHTML) ─────────── */
const treatmentDetailsData = {
    'modal-rct': {
        title: 'Root Canal Treatment (RCT)',
        tag: 'Painless & Tooth-Saving Procedure',
        description: 'Root Canal Treatment is designed to eliminate infection inside the tooth pulp and preserve your natural tooth, avoiding extraction. Under Dr. Sushma Reddy\u2019s care in Kharmanghat, RCT is performed with advanced rotary technology under localized anesthesia.',
        steps: [
            'Comprehensive X-ray diagnosis to evaluate canal anatomy.',
            'Gentle local anesthesia to ensure 100% painless procedure.',
            'Thorough cleaning & disinfection of infected root canals.',
            'Sealing with biocompatible gutta-percha material.',
            'Crown placement (Zirconia/Ceramic) for structural protection.'
        ],
        duration: '1 to 2 visits (approx. 45 mins each)',
        idealFor: 'Severe toothache, sensitivity to hot/cold, pain while chewing, deep cavity.'
    },
    'modal-pain': {
        title: 'Emergency Tooth Pain Relief',
        tag: 'Same-Day Urgent Care in Kharmanghat',
        description: 'Sudden toothache can disrupt sleep and daily life. At Shreshthaa Dental, we prioritise emergency cases to provide immediate diagnostic relief, infection control, and pain management.',
        steps: [
            'Immediate clinical exam & digital radiographic scan.',
            'Instant pain-relieving medication & localised intervention.',
            'Clear treatment plan explanation (Filling, RCT, or extraction if un-restorable).'
        ],
        duration: '30 to 45 minutes',
        idealFor: 'Swollen gums, throbbing toothache, wisdom tooth pain, cracked tooth.'
    },
    'modal-cleaning': {
        title: 'Teeth Cleaning & Ultrasonic Scaling',
        tag: 'Preventive Oral Hygiene & Fresh Breath',
        description: 'Regular brushing cannot remove hardened dental calculus (tartar). Ultrasonic scaling gently removes plaque deposits around the gumline, preventing gingivitis, gum recession, and bad breath.',
        steps: [
            'Ultrasonic scaler vibrations to loosen hardened tartar deposits.',
            'Sub-gingival plaque rinse for gum health.',
            'Prophylaxis polishing with fluoride paste for stain removal.'
        ],
        duration: '30 to 40 minutes',
        idealFor: 'Bleeding gums, yellowing teeth, bad breath, 6-month routine care.'
    },
    'modal-crowns': {
        title: 'Dental Crowns & Fixed Bridges',
        tag: 'Durable Restoration & Aesthetic Match',
        description: 'Custom ceramic or zirconia crowns cap weak, fractured, or post-RCT teeth to restore 100% chewing strength. Fixed dental bridges replace missing teeth seamlessly.',
        steps: [
            'Tooth preparation and digital shade matching.',
            'Precision impression for custom laboratory fabrication.',
            'Permanent cementation of high-strength crown.'
        ],
        duration: '2 appointments over 3 to 5 days',
        idealFor: 'Weakened teeth post-RCT, fractured teeth, replacing missing teeth.'
    },
    'modal-preventive': {
        title: 'Preventive Care & Composite Fillings',
        tag: 'Aesthetic Tooth-Colored Restorations',
        description: 'Catch cavities early before they reach the nerve! Composite fillings match your natural enamel colour perfectly, restoring tooth structure invisibly and durably.',
        steps: [
            'Plaque & decay removal under magnification.',
            'Bonding with tooth-coloured composite resin.',
            'Light curing and bite polishing for immediate chewing.'
        ],
        duration: '30 minutes per tooth',
        idealFor: 'Black spots, early decay, food lodgement, chipped enamel.'
    },
    'modal-implants': {
        title: 'Dental Implants & Alignment Consultations',
        tag: 'Permanent Root Replacement & Smile Alignment',
        description: 'Dental implants provide a permanent, artificial titanium root topped with a crown, functioning exactly like a natural tooth. We also offer consultations for braces and clear aligners.',
        steps: [
            '3D imaging & bone density assessment.',
            'Precision implant placement under gentle anesthesia.',
            'Osseointegration healing followed by final crown placement.'
        ],
        duration: 'Multi-phase treatment with custom timeline',
        idealFor: 'Missing single or multiple teeth, loose dentures, misaligned teeth.'
    }
};

const estimatorData = {
    'symptom-pain': {
        title: 'Severe Toothache or Deep Cavity',
        recommendation: 'Root Canal Treatment (RCT) or Deep Composite Filling',
        duration: '1 \u2013 2 Visits (45 mins per session)',
        roadmap: 'Digital X-ray assessment \u2192 Gentle localised anesthesia \u2192 Cleaning infected canal \u2192 High-durability Crown placement.',
        note: 'Dr. Sushma Reddy will aim to save your natural tooth whenever possible.'
    },
    'symptom-cleaning': {
        title: 'Yellow Teeth / Tartar / Bleeding Gums',
        recommendation: 'Ultrasonic Teeth Cleaning & Polishing',
        duration: 'Single Visit (approx. 35 mins)',
        roadmap: 'Ultrasonic plaque scaling \u2192 Gum inflammation rinse \u2192 Teeth polishing for smooth, stain-free smile.',
        note: 'Recommended every 6 months for complete gum disease prevention.'
    },
    'symptom-missing': {
        title: 'Missing Single or Multiple Teeth',
        recommendation: 'Dental Implant or Fixed Ceramic Bridge',
        duration: 'Custom multi-step timeline based on bone health',
        roadmap: 'Consultation & 3D scan \u2192 Implant root placement / Bridge preparation \u2192 Custom crown fitting.',
        note: 'Restores 100% natural chewing capability and smile confidence.'
    },
    'symptom-checkup': {
        title: 'Routine Oral Checkup & Minor Cavities',
        recommendation: 'Comprehensive Exam & Tooth-Colored Composite Fillings',
        duration: 'Single Visit (approx. 30 mins)',
        roadmap: 'Clinical exam under magnification \u2192 Light cavity removal \u2192 Invisible composite filling.',
        note: 'Prevents minor decay from escalating into painful root canal issues.'
    }
};

document.addEventListener('DOMContentLoaded', () => {

    /* ── 1. Mobile Menu ─────────────────────────────────────────────────── */
    const mobileToggle = document.getElementById('mobileToggle');
    const navMenu = document.getElementById('navMenu');

    if (mobileToggle && navMenu) {
        mobileToggle.addEventListener('click', () => {
            navMenu.classList.toggle('active');
            mobileToggle.classList.toggle('active');
            const expanded = navMenu.classList.contains('active');
            mobileToggle.setAttribute('aria-expanded', String(expanded));
        });

        navMenu.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', () => {
                navMenu.classList.remove('active');
                mobileToggle.classList.remove('active');
                mobileToggle.setAttribute('aria-expanded', 'false');
            });
        });

        document.addEventListener('click', (e) => {
            if (!navMenu.contains(e.target) && !mobileToggle.contains(e.target)
                && navMenu.classList.contains('active')) {
                navMenu.classList.remove('active');
                mobileToggle.classList.remove('active');
                mobileToggle.setAttribute('aria-expanded', 'false');
            }
        });
    }

    /* ── 2. Booking Modal ───────────────────────────────────────────────── */
    const bookingModal = document.getElementById('bookingModal');
    const openBookingBtns = document.querySelectorAll('.open-booking-btn');
    const closeModalBtn = document.getElementById('closeModalBtn');

    function openBookingModal() {
        if (!bookingModal) return;
        bookingModal.classList.add('active');
        bookingModal.setAttribute('aria-hidden', 'false');
        document.body.style.overflow = 'hidden';
        const modalDate = document.getElementById('modalDate');
        if (modalDate) {
            modalDate.setAttribute('min', getMinDate());
            if (!modalDate.value) modalDate.value = getTomorrowDate();
        }
    }

    function closeBookingModal() {
        if (!bookingModal) return;
        bookingModal.classList.remove('active');
        bookingModal.setAttribute('aria-hidden', 'true');
        document.body.style.overflow = '';
    }

    openBookingBtns.forEach(btn => btn.addEventListener('click', openBookingModal));
    closeModalBtn?.addEventListener('click', closeBookingModal);
    bookingModal?.addEventListener('click', e => { if (e.target === bookingModal) closeBookingModal(); });

    // Close modals on Escape key
    document.addEventListener('keydown', e => {
        if (e.key === 'Escape') { closeBookingModal(); closeDetailModal(); }
    });

    /* ── 3. Treatment Detail Modal (XSS-safe DOM construction) ─────────── */
    const detailModal = document.getElementById('detailModal');
    const detailModalContent = document.getElementById('detailModalContent');
    const closeDetailBtn = document.getElementById('closeDetailBtn');

    function closeDetailModal() {
        if (!detailModal) return;
        detailModal.classList.remove('active');
        detailModal.setAttribute('aria-hidden', 'true');
        document.body.style.overflow = '';
    }

    function buildDetailContent(data, modalKey) {
        // All data is from the static JS object above — no user input involved.
        // We still use DOM construction to be defensive.
        const wrap = el('div', { className: 'modal-detail-body' });

        wrap.appendChild(el('span', { className: 'modal-detail-tag' }, data.tag));
        wrap.appendChild(el('h3', {}, data.title));
        wrap.appendChild(el('p', {}, data.description));

        const stepsWrap = el('div', { className: 'modal-steps-list' });
        stepsWrap.appendChild(el('h4', {}, 'Procedure Step-by-Step:'));
        const ol = el('ol');
        data.steps.forEach(step => ol.appendChild(el('li', {}, step)));
        stepsWrap.appendChild(ol);
        wrap.appendChild(stepsWrap);

        const grid = el('div', { className: 'result-grid', style: 'margin-bottom:1.5rem' });
        const d1 = el('div', { className: 'result-box-item' });
        d1.appendChild(el('strong', {}, 'Estimated Duration'));
        d1.appendChild(el('p', {}, data.duration));
        const d2 = el('div', { className: 'result-box-item', style: 'grid-column:span 2' });
        d2.appendChild(el('strong', {}, 'Recommended For'));
        d2.appendChild(el('p', {}, data.idealFor));
        grid.appendChild(d1);
        grid.appendChild(d2);
        wrap.appendChild(grid);

        const actions = el('div', { style: 'display:flex;gap:1rem;flex-wrap:wrap' });
        const bookBtn = el('button', { className: 'btn btn-primary btn-block open-booking-from-modal', style: 'flex:1' },
            'Book Appointment for ' + data.title);
        const callBtn = el('a', { href: 'tel:9704831481', className: 'btn btn-outline', style: 'flex:1' },
            'Call Clinic: 97048 31481');
        actions.appendChild(bookBtn);
        actions.appendChild(callBtn);
        wrap.appendChild(actions);

        bookBtn.addEventListener('click', () => {
            closeDetailModal();
            openBookingModal();
            const modalService = document.getElementById('modalService');
            if (modalService) {
                const map = {
                    'modal-rct': 'Root Canal Treatment',
                    'modal-pain': 'Tooth Pain Relief',
                    'modal-cleaning': 'Teeth Cleaning',
                    'modal-crowns': 'Crowns & Bridges',
                    'modal-preventive': 'Filling',
                    'modal-implants': 'Implants / Consultation',
                };
                if (map[modalKey]) modalService.value = map[modalKey];
            }
        });

        return wrap;
    }

    document.querySelectorAll('.open-details-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const modalKey = btn.getAttribute('data-modal');
            // Allowlist the modal key
            if (!treatmentDetailsData.hasOwnProperty(modalKey)) return;
            const data = treatmentDetailsData[modalKey];
            if (data && detailModalContent && detailModal) {
                detailModalContent.textContent = ''; // clear safely
                detailModalContent.appendChild(buildDetailContent(data, modalKey));
                detailModal.classList.add('active');
                detailModal.setAttribute('aria-hidden', 'false');
                document.body.style.overflow = 'hidden';
            }
        });
    });

    closeDetailBtn?.addEventListener('click', closeDetailModal);
    detailModal?.addEventListener('click', e => { if (e.target === detailModal) closeDetailModal(); });

    /* ── 4. Estimator (XSS-safe DOM construction) ───────────────────────── */
    const estimatorTabs = document.querySelectorAll('.estimator-tab');
    const estimatorResult = document.getElementById('estimatorResult');

    function buildEstimatorContent(data) {
        const frag = document.createDocumentFragment();

        const header = el('div', { style: 'margin-bottom:1.25rem' });
        header.appendChild(el('h3', {
            style: 'font-family:var(--font-heading);color:var(--primary-navy);font-size:1.3rem;margin-bottom:0.35rem'
        }, data.title));
        header.appendChild(el('p', { style: 'font-size:0.95rem;color:var(--text-muted)' }, data.note));
        frag.appendChild(header);

        const grid = el('div', { className: 'result-grid', style: 'margin-bottom:1.5rem' });
        [['Recommended Procedure', data.recommendation],
         ['Estimated Duration', data.duration],
         ['Consultation Roadmap', data.roadmap]].forEach(([label, value]) => {
            const box = el('div', { className: 'result-box-item' });
            box.appendChild(el('strong', {}, label));
            box.appendChild(el('p', {}, value));
            grid.appendChild(box);
        });
        frag.appendChild(grid);

        const footer = el('div', {
            style: 'display:flex;gap:1rem;align-items:center;justify-content:space-between;flex-wrap:wrap'
        });
        footer.appendChild(el('span', {
            style: 'font-weight:700;color:var(--accent-emerald);font-size:0.95rem'
        }, '\u2713 Consultation Available at Shreshthaa Dental Kharmanghat'));

        const bookBtn = el('button', { className: 'btn btn-primary open-booking-btn' },
            'Book Consultation for This Issue');
        bookBtn.addEventListener('click', openBookingModal);
        footer.appendChild(bookBtn);
        frag.appendChild(footer);

        return frag;
    }

    function updateEstimator(symptomKey) {
        // Allowlist the key
        if (!estimatorData.hasOwnProperty(symptomKey)) return;
        const data = estimatorData[symptomKey];
        if (data && estimatorResult) {
            estimatorResult.textContent = ''; // clear safely
            estimatorResult.appendChild(buildEstimatorContent(data));
        }
    }

    estimatorTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            estimatorTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            const symptomKey = tab.getAttribute('data-symptom');
            updateEstimator(symptomKey);
        });
    });

    updateEstimator('symptom-pain');

    /* ── 5. FAQ Accordion ───────────────────────────────────────────────── */
    document.querySelectorAll('.faq-question').forEach(q => {
        q.addEventListener('click', () => q.parentElement.classList.toggle('active'));
    });

    /* ── 6. Appointment Form — validated, sanitized, rate-limited ────────── */
    function handleFormSubmit(event, nameId, phoneId, serviceId, dateId, timeId, notesId) {
        event.preventDefault();

        // Rate limiting
        if (isRateLimited()) {
            alert('Too many requests. Please wait a few minutes before submitting again.');
            return;
        }

        // Read and sanitize inputs
        const rawName    = document.getElementById(nameId)?.value.trim() ?? '';
        const rawPhone   = document.getElementById(phoneId)?.value.trim() ?? '';
        const rawService = document.getElementById(serviceId)?.value ?? '';
        const rawDate    = document.getElementById(dateId)?.value ?? '';
        const rawTime    = document.getElementById(timeId)?.value ?? '';
        const rawNotes   = notesId ? (document.getElementById(notesId)?.value.trim() ?? '') : '';

        const name    = sanitizeName(rawName);
        const phone   = rawPhone.replace(/\s/g, '').slice(0, 10);
        const service = rawService;
        const date    = rawDate;
        const time    = rawTime;
        // Limit notes to 300 characters, strip HTML-like content
        const notes   = rawNotes.replace(/<[^>]*>/g, '').slice(0, 300);

        // ── Validation ────────────────────────────────────────────────────
        if (!name || name.length < 2) {
            alert('Please enter a valid patient name (at least 2 characters).');
            return;
        }

        if (!isValidPhone(phone)) {
            alert('Please enter a valid 10-digit Indian mobile number starting with 6, 7, 8, or 9.');
            return;
        }

        if (!ALLOWED_SERVICES.has(service)) {
            alert('Please select a valid treatment from the list.');
            return;
        }

        if (!date) {
            alert('Please select a preferred appointment date.');
            return;
        }

        // Block past dates
        if (date < getMinDate()) {
            alert('Appointment date cannot be in the past. Please select today or a future date.');
            return;
        }

        if (!ALLOWED_TIMES.has(time)) {
            alert('Please select a valid time slot from the list.');
            return;
        }

        // ── Build WhatsApp message (encode all user input) ─────────────────
        const waText = encodeURIComponent(
            'Hello Dr. Sushma Reddy / Shreshthaa Dental Clinic,\n\n' +
            'I would like to request a dental appointment:\n' +
            '\u2022 Patient Name: ' + name + '\n' +
            '\u2022 Phone: ' + phone + '\n' +
            '\u2022 Required Service: ' + service + '\n' +
            '\u2022 Preferred Date: ' + date + '\n' +
            '\u2022 Preferred Time Slot: ' + time + '\n' +
            (notes ? '\u2022 Notes/Concern: ' + notes + '\n\n' : '\n') +
            'Please confirm my appointment slot. Thank you!'
        );

        // Validate the WhatsApp URL before opening (no open-redirect)
        const waUrl = 'https://wa.me/919704831481?text=' + waText;
        let parsedUrl;
        try {
            parsedUrl = new URL(waUrl);
        } catch {
            alert('Unable to generate WhatsApp link. Please call the clinic directly.');
            return;
        }
        if (parsedUrl.hostname !== 'wa.me') {
            alert('Invalid redirect. Please call the clinic directly.');
            return;
        }

        closeBookingModal();

        const confirmDialog = confirm(
            'Thank you, ' + escapeHtml(name) + '! Your appointment request is ready.\n\n' +
            'Would you like to open WhatsApp now to send your details to Shreshthaa Dental Clinic?'
        );

        if (confirmDialog) {
            // Open in new tab — noopener set programmatically
            const win = window.open(waUrl, '_blank', 'noopener,noreferrer');
            if (!win) {
                alert('Pop-up was blocked. Please allow pop-ups for this page or call 97048 31481 directly.');
            }
        } else {
            alert('Your request for ' + escapeHtml(service) + ' on ' + date +
                  ' has been noted. Our team will call you shortly.');
        }

        event.target.reset();
    }

    // Wire up both forms
    document.getElementById('inlineBookingForm')?.addEventListener('submit', e => {
        handleFormSubmit(e, 'inlineName', 'inlinePhone', 'inlineService', 'inlineDate', 'inlineTime', 'inlineNotes');
    });

    document.getElementById('modalBookingForm')?.addEventListener('submit', e => {
        handleFormSubmit(e, 'modalName', 'modalPhone', 'modalService', 'modalDate', 'modalTime', null);
    });

    // Set date constraints
    const inlineDate = document.getElementById('inlineDate');
    if (inlineDate) {
        inlineDate.setAttribute('min', getMinDate());
        if (!inlineDate.value) inlineDate.value = getTomorrowDate();
    }

    // Dynamic footer year
    const yearSpan = document.getElementById('year');
    if (yearSpan) yearSpan.textContent = new Date().getFullYear();
});
