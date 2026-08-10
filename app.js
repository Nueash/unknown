/* ==========================================================================
   Arc Dental — Main JavaScript Logic
   Security hardened: XSS-safe DOM construction, input validation,
   rate limiting, duplicate-submit prevention, allowlist enforcement.
   ========================================================================== */

'use strict';

/* ── Security & Helper Functions ───────────────────────────────────────── */

/** Escape HTML entities */
function escapeHtml(str) {
    if (typeof str !== 'string') return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}

/** Strip unsafe characters for names */
function sanitizeName(val) {
    return val.replace(/[^a-zA-Z\u0900-\u097F\s.'-]/g, '').slice(0, 80);
}

/** Accept 10-digit Indian mobile numbers */
function isValidPhone(val) {
    return /^[6-9]\d{9}$/.test(val.replace(/\s/g, ''));
}

/** Hard allowlist for service dropdown values */
const ALLOWED_SERVICES = new Set([
    'Pediatric Dentistry',
    'Pediatric / Kids Dentistry',
    'Invisible Braces',
    'Invisible Braces & Aligners',
    'Dental Implants',
    'Dental Implants & Rehabilitation',
    'Root Canal Treatment',
    'Root Canal Treatment (RCT)',
    'Cosmetic Dentistry',
    'Cosmetic Dentistry & Whitening',
    'General Dental Checkup',
    'Tooth Pain / Consultation',
    'Teeth Cleaning'
]);

/** Hard allowlist for time-slot dropdown values */
const ALLOWED_TIMES = new Set([
    'Morning (9:00 AM - 12:00 PM)',
    'Afternoon (12:00 PM - 4:00 PM)',
    'Evening (4:00 PM - 7:00 PM)',
    'Night (7:00 PM - 9:00 PM)',
    'Morning',
    'Afternoon',
    'Evening',
    'Night'
]);

/** Rate limiter: max 3 submissions per 5 minutes */
const _submissionLog = [];
function isRateLimited() {
    const now = Date.now();
    const windowMs = 5 * 60 * 1000;
    const recentCount = _submissionLog.filter(t => now - t < windowMs).length;
    if (recentCount >= 3) return true;
    _submissionLog.push(now);
    return false;
}

function getMinDate() {
    return new Date().toISOString().split('T')[0];
}

function getTomorrowDate() {
    return new Date(Date.now() + 86400000).toISOString().split('T')[0];
}

/* ── DOM Element Builder ────────────────────────────────────────────────── */
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
        node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
    });
    return node;
}

/* ── Static Treatment Details Data ─────────────────────────────────────── */
const treatmentDetailsData = {
    'modal-kids': {
        title: 'Pediatric & Kids Dentistry',
        tag: '100% Painless & Fear-Free Child Care',
        description: 'Dr. Rebecca is a highly acclaimed specialist in pediatric dentistry. We ensure children have a joyful, comfortable, and zero-pain experience during cavity fillings, preventive fluoride treatments, and habit counseling.',
        steps: [
            'Friendly pediatric consultation & gentle oral assessment.',
            'Pain-free localized numbing techniques for child comfort.',
            'Preventive cavity sealing & protective fluoride coating.',
            'Positive reinforcement & fun oral hygiene education.'
        ],
        duration: '30 to 45 minutes',
        idealFor: 'Children, toddlers, teens, cavity prevention, thumb sucking habits, tooth pain.'
    },
    'modal-aligners': {
        title: 'Invisible Braces & Aligners',
        tag: 'Modern Wire-Free Smile Straightening',
        description: 'Achieve a straight, confident smile without bulky metal braces. Clear aligners are custom-made transparent trays that gently align your teeth. Removable, virtually invisible, and comfortable.',
        steps: [
            '3D digital intraoral scan & smile design simulation.',
            'Custom fabrication of clear aligner tray sets.',
            'Progressive tray changes every 2 weeks.',
            'Final retention phase for long-lasting alignment.'
        ],
        duration: '6 to 14 months (custom digital plan)',
        idealFor: 'Crooked teeth, gaps, crowding, adults & teens seeking discreet braces.'
    },
    'modal-implants': {
        title: 'Dental Implants & Full Mouth Rehabilitation',
        tag: 'Permanent Root & Crown Replacement',
        description: 'Dental implants replace missing tooth roots with bio-compatible titanium posts topped with realistic ceramic crowns. Restores 100% natural bite strength and aesthetics.',
        steps: [
            'Digital 3D CBCT scan & jawbone evaluation.',
            'Precision surgical implant placement under gentle anesthesia.',
            'Healing & osseointegration bonding phase.',
            'Custom shade-matched Zirconia crown fitting.'
        ],
        duration: 'Multi-phase treatment with custom timeline',
        idealFor: 'Single or multiple missing teeth, loose dentures, full mouth restoration.'
    },
    'modal-rct': {
        title: 'Root Canal Treatment (RCT)',
        tag: 'Painless Single-Visit Tooth Saving',
        description: 'Painless rotary root canal therapy saves infected teeth from extraction. Dr. Rebecca eliminates deep pulp infection while ensuring total patient comfort.',
        steps: [
            'Digital X-ray diagnosis to inspect root canals.',
            'Gentle localized anesthesia ensuring zero pain.',
            'Rotary cleaning & thorough canal disinfection.',
            'Sealing with biocompatible gutta-percha & crown placement.'
        ],
        duration: '1 to 2 visits (approx. 45 mins each)',
        idealFor: 'Severe toothache, sensitivity to hot/cold, deep decay, chewing pain.'
    },
    'modal-cosmetic': {
        title: 'Cosmetic Dentistry & Teeth Whitening',
        tag: 'Aesthetic Smile Transformations',
        description: 'Enhance your natural smile with professional laser teeth whitening, aesthetic composite bonding, tooth-colored fillings, and porcelain veneers.',
        steps: [
            'Smile analysis & shade selection.',
            'Gentle enamel cleaning & whitening gel application.',
            'Laser activation for instant shade brightening.',
            'Polishing for lasting shine.'
        ],
        duration: '45 to 60 minutes',
        idealFor: 'Yellowed teeth, tea/coffee stains, chipped enamel, smile makeovers.'
    }
};

/* ── Static Treatment Guide / Estimator Data ────────────────────────────── */
const estimatorData = {
    'symptom-kids': {
        title: 'Kids Dental Checkup / Cavity Care',
        recommendation: 'Pediatric Dental Exam & Painless Composite Sealing',
        duration: 'Single Visit (approx. 30 mins)',
        roadmap: 'Gentle clinical exam \u2192 Kid-friendly cavity cleaning \u2192 Tooth-colored composite filling \u2192 Preventive fluoride coating.',
        note: 'Dr. Rebecca is specialized in effortless, fear-free dental care for children.'
    },
    'symptom-aligners': {
        title: 'Crooked Teeth or Gap Alignment',
        recommendation: 'Invisible Aligners / Clear Braces',
        duration: 'Custom 6 \u2013 12 Months Digital Alignment',
        roadmap: '3D Intraoral scan \u2192 Digital smile preview \u2192 Custom clear tray set delivery \u2192 Periodic quick checkups.',
        note: '100% transparent and removable — no metal wires or food restrictions.'
    },
    'symptom-missing': {
        title: 'Missing Tooth Replacement',
        recommendation: 'Bio-compatible Dental Implant or Fixed Bridge',
        duration: 'Multi-phase custom timeline',
        roadmap: 'Consultation & 3D scan \u2192 Implant placement \u2192 Permanent Zirconia Crown attachment.',
        note: 'Restores 100% natural chewing strength and jawbone health.'
    },
    'symptom-pain': {
        title: 'Severe Tooth Pain / Infection',
        recommendation: 'Painless Rotary Root Canal Treatment (RCT)',
        duration: '1 \u2013 2 Sessions (45 mins each)',
        roadmap: 'Digital X-ray \u2192 Gentle localized anesthesia \u2192 Canal cleaning & sealing \u2192 Protective Crown fitting.',
        note: 'Instant pain relief while preserving your natural tooth structure.'
    }
};

document.addEventListener('DOMContentLoaded', () => {

    /* ── 1. Mobile Navigation ───────────────────────────────────────────── */
    const mobileToggle = document.getElementById('mobileToggle');
    const navMenu = document.getElementById('navMenu');

    if (mobileToggle && navMenu) {
        mobileToggle.addEventListener('click', () => {
            navMenu.classList.toggle('active');
            mobileToggle.classList.toggle('active');
            mobileToggle.setAttribute('aria-expanded', String(navMenu.classList.contains('active')));
        });

        navMenu.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', () => {
                navMenu.classList.remove('active');
                mobileToggle.classList.remove('active');
                mobileToggle.setAttribute('aria-expanded', 'false');
            });
        });

        document.addEventListener('click', (e) => {
            if (!navMenu.contains(e.target) && !mobileToggle.contains(e.target) && navMenu.classList.contains('active')) {
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

    document.addEventListener('keydown', e => {
        if (e.key === 'Escape') { closeBookingModal(); closeDetailModal(); }
    });

    /* ── 3. Treatment Detail Modal ─────────────────────────────────────── */
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
        const callBtn = el('a', { href: 'tel:+9198496333188', className: 'btn btn-outline', style: 'flex:1' },
            'Call Clinic: +91 98496 333188');
        actions.appendChild(bookBtn);
        actions.appendChild(callBtn);
        wrap.appendChild(actions);

        bookBtn.addEventListener('click', () => {
            closeDetailModal();
            openBookingModal();
            const modalService = document.getElementById('modalService');
            if (modalService) {
                const map = {
                    'modal-kids': 'Pediatric Dentistry',
                    'modal-aligners': 'Invisible Braces',
                    'modal-implants': 'Dental Implants',
                    'modal-rct': 'Root Canal Treatment',
                    'modal-cosmetic': 'Cosmetic Dentistry',
                };
                if (map[modalKey]) modalService.value = map[modalKey];
            }
        });

        return wrap;
    }

    document.querySelectorAll('.open-details-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const modalKey = btn.getAttribute('data-modal');
            if (!treatmentDetailsData.hasOwnProperty(modalKey)) return;
            const data = treatmentDetailsData[modalKey];
            if (data && detailModalContent && detailModal) {
                detailModalContent.textContent = '';
                detailModalContent.appendChild(buildDetailContent(data, modalKey));
                detailModal.classList.add('active');
                detailModal.setAttribute('aria-hidden', 'false');
                document.body.style.overflow = 'hidden';
            }
        });
    });

    closeDetailBtn?.addEventListener('click', closeDetailModal);
    detailModal?.addEventListener('click', e => { if (e.target === detailModal) closeDetailModal(); });

    /* ── 4. Estimator ───────────────────────────────────────────────────── */
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
        }, '\u2713 Consultation Available at Arc Dental Kharmanghat'));

        const bookBtn = el('button', { className: 'btn btn-primary open-booking-btn' },
            'Book Consultation for This Issue');
        bookBtn.addEventListener('click', openBookingModal);
        footer.appendChild(bookBtn);
        frag.appendChild(footer);

        return frag;
    }

    function updateEstimator(symptomKey) {
        if (!estimatorData.hasOwnProperty(symptomKey)) return;
        const data = estimatorData[symptomKey];
        if (data && estimatorResult) {
            estimatorResult.textContent = '';
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

    updateEstimator('symptom-kids');

    /* ── 5. FAQ Accordion ───────────────────────────────────────────────── */
    document.querySelectorAll('.faq-question').forEach(q => {
        q.addEventListener('click', () => q.parentElement.classList.toggle('active'));
    });

    /* ── 6. Form Handler & WhatsApp Integration ─────────────────────────── */
    function handleFormSubmit(event, nameId, phoneId, serviceId, dateId, timeId, notesId) {
        event.preventDefault();

        if (isRateLimited()) {
            alert('Too many requests. Please wait a few minutes before submitting again.');
            return;
        }

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
        const notes   = rawNotes.replace(/<[^>]*>/g, '').slice(0, 300);

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

        if (date < getMinDate()) {
            alert('Appointment date cannot be in the past. Please select today or a future date.');
            return;
        }

        if (!ALLOWED_TIMES.has(time)) {
            alert('Please select a valid time slot from the list.');
            return;
        }

        // WhatsApp message redirecting to +9198496333188
        const waText = encodeURIComponent(
            'Hi Arc Dental, I want to book an appointment\n\n' +
            '• Patient Name: ' + name + '\n' +
            '• Phone: ' + phone + '\n' +
            '• Required Service: ' + service + '\n' +
            '• Preferred Date: ' + date + '\n' +
            '• Preferred Time Slot: ' + time + '\n' +
            (notes ? '• Notes/Concern: ' + notes + '\n\n' : '\n') +
            'Please confirm my appointment slot. Thank you!'
        );

        const waUrl = 'https://wa.me/9198496333188?text=' + waText;

        closeBookingModal();

        const confirmDialog = confirm(
            'Thank you, ' + escapeHtml(name) + '! Your appointment request is ready.\n\n' +
            'Would you like to open WhatsApp now to send your appointment details directly to Arc Dental?'
        );

        if (confirmDialog) {
            const win = window.open(waUrl, '_blank', 'noopener,noreferrer');
            if (!win) {
                alert('Pop-up was blocked. Please allow pop-ups for this page or call +91 98496 333188 directly.');
            }
        } else {
            alert('Your request for ' + escapeHtml(service) + ' on ' + date +
                  ' has been noted. Our team will call you shortly at ' + phone + '!');
        }

        event.target.reset();
    }

    document.getElementById('inlineBookingForm')?.addEventListener('submit', e => {
        handleFormSubmit(e, 'inlineName', 'inlinePhone', 'inlineService', 'inlineDate', 'inlineTime', 'inlineNotes');
    });

    document.getElementById('modalBookingForm')?.addEventListener('submit', e => {
        handleFormSubmit(e, 'modalName', 'modalPhone', 'modalService', 'modalDate', 'modalTime', null);
    });

    const inlineDate = document.getElementById('inlineDate');
    if (inlineDate) {
        inlineDate.setAttribute('min', getMinDate());
        if (!inlineDate.value) inlineDate.value = getTomorrowDate();
    }

    const yearSpan = document.getElementById('year');
    if (yearSpan) yearSpan.textContent = new Date().getFullYear();
});
