import { getTextColor, mapIcon } from '../utils/galaxie.js';

/**
 * TagBadge
 * Renders a tag as a split pill: [icon] [label]
 *
 * The label respects the user-controlled `showNamespace` prop:
 *   showNamespace = true  → 'tlp:clear'   /   'ms-caro-malware-full:malware-type=Trojan'
 *   showNamespace = false → 'clear'       /   'Trojan'
 *
 * Every segment of the raw tag name is shown when showNamespace is true —
 * including the predicate and the 'misp-galaxy:' prefix for galaxy tags —
 * so what's displayed always matches the exact tag being referenced.
 */
const TagBadge = {
    props: {
        tag: { type: Object, required: true },
        size: { type: String, default: 'md' },
        showNamespace: { type: Boolean, default: true },
    },
    setup(props) {
        const { computed } = Vue;

        function valueOf(name) {
            if (!name) return '';
            const m = name.match(/="(.+)"$/);
            if (m) return m[1];
            if (name.includes(':')) return name.split(':').slice(1).join(':');
            return name;
        }

        function fullLabel(name) {
            if (!name) return '';
            const colonIdx = name.indexOf(':');
            if (colonIdx === -1) return name;
            const rawNs = name.slice(0, colonIdx);
            const rest  = name.slice(colonIdx + 1);
            const eqIdx = rest.indexOf('=');
            if (eqIdx === -1) return `${rawNs}:${rest}`;
            const pred = rest.slice(0, eqIdx);
            return `${rawNs}:${pred}=${valueOf(name)}`;
        }

        const label = computed(() => props.showNamespace ? fullLabel(props.tag.name) : valueOf(props.tag.name));

        return { getTextColor, mapIcon, label };
    },
    template: `
        <span class="tag-split shadow-sm on-hover-zoom" :class="'tag-' + size">
            <span class="tag-left" v-html="mapIcon(tag.icon)"></span>
            <span class="tag-right" :style="{ backgroundColor: tag.color || '#6c757d' }" :title="tag.name">
                <span :style="{ color: getTextColor(tag.color || '#6c757d') }">{{ label }}</span>
            </span>
        </span>
    `
};

export default TagBadge;