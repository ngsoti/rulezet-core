;(function () {

    /* ── Particle network canvas in hero ── */
    const heroCanvas = document.getElementById('history-hero-canvas')
    if (heroCanvas) {
        const ctx = heroCanvas.getContext('2d')
        const C = '13, 110, 253'
        let pts = [], raf

        const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches

        function resize() {
            heroCanvas.width  = heroCanvas.offsetWidth  || heroCanvas.parentElement.offsetWidth
            heroCanvas.height = heroCanvas.offsetHeight || heroCanvas.parentElement.offsetHeight
        }

        function initPts() {
            const n = Math.max(22, Math.floor(heroCanvas.width * heroCanvas.height / 10000))
            pts = Array.from({ length: n }, () => ({
                x:  Math.random() * heroCanvas.width,
                y:  Math.random() * heroCanvas.height,
                vx: (Math.random() - 0.5) * (reduced ? 0 : 0.3),
                vy: (Math.random() - 0.5) * (reduced ? 0 : 0.3),
                r:  Math.random() * 1.5 + 0.7,
            }))
        }

        function frame() {
            ctx.clearRect(0, 0, heroCanvas.width, heroCanvas.height)

            for (const p of pts) {
                p.x += p.vx; p.y += p.vy
                if (p.x < 0 || p.x > heroCanvas.width)  p.vx *= -1
                if (p.y < 0 || p.y > heroCanvas.height) p.vy *= -1
            }

            for (let i = 0; i < pts.length; i++) {
                for (let j = i + 1; j < pts.length; j++) {
                    const dx = pts[i].x - pts[j].x
                    const dy = pts[i].y - pts[j].y
                    const d  = Math.sqrt(dx * dx + dy * dy)
                    if (d < 115) {
                        ctx.strokeStyle = `rgba(${C}, ${0.13 * (1 - d / 115)})`
                        ctx.lineWidth   = 0.75
                        ctx.beginPath()
                        ctx.moveTo(pts[i].x, pts[i].y)
                        ctx.lineTo(pts[j].x, pts[j].y)
                        ctx.stroke()
                    }
                }
            }

            for (const p of pts) {
                ctx.fillStyle = `rgba(${C}, 0.22)`
                ctx.beginPath()
                ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2)
                ctx.fill()
            }

            if (!reduced) raf = requestAnimationFrame(frame)
        }

        const ro = new ResizeObserver(() => { resize(); initPts() })
        ro.observe(heroCanvas.parentElement)

        resize(); initPts(); frame()
    }

    /* ── Scroll-reveal for timeline items ── */
    const items = document.querySelectorAll('.timeline-item')
    items.forEach((el, i) => {
        el.classList.add(i % 2 === 0 ? 'from-left' : 'from-right')
    })

    if ('IntersectionObserver' in window) {
        const obs = new IntersectionObserver(entries => {
            entries.forEach(entry => {
                if (!entry.isIntersecting) return
                const el  = entry.target
                const dot = el.querySelector('.timeline-dot')
                el.classList.add('anim-visible')
                if (dot) setTimeout(() => dot.classList.add('dot-active'), 250)
                obs.unobserve(el)
            })
        }, { threshold: 0.12, rootMargin: '0px 0px -50px 0px' })

        items.forEach(el => obs.observe(el))
    } else {
        items.forEach(el => {
            el.classList.add('anim-visible')
            const dot = el.querySelector('.timeline-dot')
            if (dot) dot.classList.add('dot-active')
        })
    }

    /* ── Timeline progress line ── */
    const lineFill = document.getElementById('timeline-line-fill')
    const lineGlow = document.getElementById('timeline-line-glow')
    const container = document.querySelector('.timeline-container')

    if (lineFill && container) {
        function updateLine() {
            const rect = container.getBoundingClientRect()
            const vh   = window.innerHeight
            const pct  = Math.max(0, Math.min(1, (vh - rect.top) / (rect.height + vh)))
            lineFill.style.height = (pct * 100) + '%'
            if (lineGlow) lineGlow.style.top = (pct * rect.height) + 'px'
        }
        window.addEventListener('scroll', updateLine, { passive: true })
        updateLine()
    }

    /* ── Lightbox ── */
    const overlay = document.createElement('div')
    overlay.className = 'lb-overlay'
    overlay.innerHTML = `
        <div class="lb-inner">
            <button class="lb-close" aria-label="Close">&times;</button>
            <img class="lb-img" src="" alt="">
            <div class="lb-caption"></div>
        </div>
    `
    document.body.appendChild(overlay)

    const lbImg     = overlay.querySelector('.lb-img')
    const lbCaption = overlay.querySelector('.lb-caption')

    function openLb(src, alt, captionParts) {
        lbImg.src = src; lbImg.alt = alt

        lbCaption.textContent = ''
        if (captionParts && captionParts.title) {
            const strong = document.createElement('strong')
            strong.textContent = captionParts.title
            lbCaption.appendChild(strong)

            if (captionParts.badge) {
                lbCaption.appendChild(document.createTextNode(' — ' + captionParts.badge))
            }

            lbCaption.appendChild(document.createElement('br'))

            const span = document.createElement('span')
            span.style.opacity = '.65'
            span.textContent = captionParts.period || ''
            lbCaption.appendChild(span)
        }

        overlay.style.display = 'flex'
        requestAnimationFrame(() => overlay.classList.add('lb-open'))
        document.body.style.overflow = 'hidden'
    }

    function closeLb() {
        overlay.classList.remove('lb-open')
        document.body.style.overflow = ''
        setTimeout(() => { overlay.style.display = 'none'; lbImg.src = '' }, 260)
    }

    overlay.style.display = 'none'

    // Close on overlay background click
    overlay.addEventListener('click', e => { if (e.target === overlay) closeLb() })
    overlay.querySelector('.lb-close').addEventListener('click', closeLb)
    document.addEventListener('keydown', e => {
        if (e.key === 'Escape' && overlay.classList.contains('lb-open')) closeLb()
    })

    // Delegate clicks on .timeline-img-wrap
    document.addEventListener('click', e => {
        const wrap = e.target.closest('.timeline-img-wrap')
        if (!wrap) return
        const img     = wrap.querySelector('img')
        const item    = wrap.closest('.timeline-item')
        const card    = item  && item.querySelector('.timeline-card')
        const title   = card  && card.querySelector('h4')
        const period  = card  && card.querySelector('.text-muted.small')
        const badge   = card  && card.querySelector('.badge')

        if (!img) return
        const caption = title
            ? { title: title.textContent, badge: badge ? badge.textContent : '', period: period ? period.textContent : '' }
            : null
        openLb(img.src, img.alt, caption)
    })

})()
