/**
 * sanitize.js — shared DOMPurify config for user-authored markdown/HTML.
 *
 * Comments, blog posts, and proposal/PR discussion messages are rendered
 * client-side via marked + DOMPurify and injected with v-html. DOMPurify's
 * default config still allows <form>/<input>/<style> and the style/action
 * attributes, which is enough to build a full-page phishing overlay (fixed
 * position, high z-index, opaque background) with a login form posting
 * credentials to an attacker-controlled host — no <script> tag required.
 * Forbid the tags/attributes that make that possible.
 */

export const SANITIZE_CONFIG = {
    FORBID_TAGS: ['form', 'input', 'button', 'select', 'textarea', 'option',
                  'fieldset', 'legend', 'datalist', 'output', 'label', 'style'],
    FORBID_ATTR: ['style', 'action', 'method', 'formaction', 'target'],
}

let _purify = null
export async function getPurify() {
    if (!_purify) {
        const m = await import('/static/js/purify.min.js')
        _purify = m.default || window.DOMPurify
    }
    return _purify
}

let _marked = null
async function getMarked() {
    if (!_marked) {
        const m = await import('/static/js/marked.min.js')
        _marked = m.marked || m.default || window.marked
    }
    return _marked
}

export async function sanitizeHtml(html) {
    const purify = await getPurify()
    return purify.sanitize(html, SANITIZE_CONFIG)
}

export async function renderMarkdown(text) {
    if (!text) return ''
    const mk = await getMarked()
    const html = mk.parse ? mk.parse(text) : mk(text)
    return sanitizeHtml(html)
}
