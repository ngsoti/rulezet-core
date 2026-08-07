/**
 * Shared utilities for tag rendering.
 * Backwards-compatible with tags that have icon values stored either with
 * or without the 'fa-' prefix.
 */

function getTextColor(hex) {
    if (!hex || hex.length < 7) return 'black';
    hex = hex.slice(1);
    const r = parseInt(hex.substring(0, 2), 16);
    const g = parseInt(hex.substring(2, 4), 16);
    const b = parseInt(hex.substring(4, 6), 16);
    const avg = ((2 * r) + b + (3 * g)) / 6;
    return avg < 128 ? 'white' : 'black';
}

// Module-scope, not rebuilt on every mapIcon() call — this runs once per
// rendered tag (potentially thousands in a large list), so re-allocating
// this literal every call was pure waste.
const _ICON_MAP = {
    'android': '<i class="fab fa-android"></i>',
    'battery-full': '<i class="fas fa-battery-full"></i>',
    'btc': '<i class="fab fa-btc"></i>',
    'bug': '<i class="fas fa-bug"></i>',
    'bullseye': '<i class="fas fa-bullseye"></i>',
    'cart-arrow-down': '<i class="fas fa-cart-arrow-down"></i>',
    'certificate': '<i class="fas fa-certificate"></i>',
    'chess-pawn': '<i class="fas fa-chess-pawn"></i>',
    'cloud': '<i class="fas fa-cloud"></i>',
    'database': '<i class="fas fa-database"></i>',
    'dollar-sign': '<i class="fas fa-dollar-sign"></i>',
    'door-open': '<i class="fas fa-door-open"></i>',
    'eye': '<i class="fas fa-eye"></i>',
    'file-code': '<i class="fas fa-file-code"></i>',
    'fire': '<i class="fas fa-fire"></i>',
    'gavel': '<i class="fas fa-gavel"></i>',
    'globe': '<i class="fas fa-globe"></i>',
    'globe-europe': '<i class="fas fa-globe-europe"></i>',
    'industry': '<i class="fas fa-industry"></i>',
    'internet-explorer': '<i class="fab fa-internet-explorer"></i>',
    'key': '<i class="fas fa-key"></i>',
    'layer-group': '<i class="fas fa-layer-group"></i>',
    'link': '<i class="fas fa-link"></i>',
    'map': '<i class="fas fa-map"></i>',
    'mobile': '<i class="fas fa-mobile"></i>',
    'optin-monster': '<i class="fab fa-optin-monster"></i>',
    'plane': '<i class="fas fa-plane"></i>',
    'shield-alt': '<i class="fas fa-shield-alt"></i>',
    'shield-virus': '<i class="fas fa-shield-virus"></i>',
    'sitemap': '<i class="fas fa-sitemap"></i>',
    'skull-crossbones': '<i class="fas fa-skull-crossbones"></i>',
    'user-ninja': '<i class="fas fa-user-ninja"></i>',
    'user-secret': '<i class="fas fa-user-secret"></i>',
    'user-shield': '<i class="fas fa-user-shield"></i>',
    'wheelchair': '<i class="fas fa-wheelchair"></i>',
    'tag': '<i class="fas fa-tag"></i>',
    'atom': '<i class="fas fa-atom"></i>',
    'list': '<i class="fas fa-list"></i>',
};
const _ICON_CACHE = new Map();

function mapIcon(iconName) {
    if (!iconName) return '<i class="fas fa-atom"></i>';

    const cached = _ICON_CACHE.get(iconName);
    if (cached !== undefined) return cached;

    // tolerate both 'fa-bug' and 'bug' as input
    let key = String(iconName).trim();
    if (key.startsWith('fa-')) key = key.slice(3);

    let html = _ICON_MAP[key];
    if (!html) {
        // Fallback: only allow FontAwesome icon name characters (letters, digits, hyphens)
        const safeKey = key.replace(/[^a-z0-9-]/gi, '');
        html = `<i class="fas fa-${safeKey}"></i>`;
    }
    _ICON_CACHE.set(iconName, html);
    return html;
}


function truncateText(text, maxLength = 300) {
    if (!text) return '';
    return text.length > maxLength ? text.substring(0, maxLength) + '…' : text;
}

export { truncateText, getTextColor, mapIcon };