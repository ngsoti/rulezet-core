import { getTextColor, mapIcon } from './utils/galaxie.js';

const SingleTagDisplay = {
    props: {
        tag: { type: Object, required: true },
        showNamespace: { type: Boolean, default: true },
    },
    delimiters: ['[[', ']]'],
    setup(props) {
        function namespaceOf(name) {
            if (!name || !name.includes(':')) return '';
            if (name.startsWith('misp-galaxy:') && name.includes('=')) {
                return name.split(':')[1].split('=')[0];
            }
            return name.split(':')[0];
        }

        function valueOf(name) {
            if (!name) return '';
            const m = name.match(/="(.+)"$/);
            if (m) return m[1];
            if (name.includes(':')) return name.split(':').slice(1).join(':');
            return name;
        }

        function label(tag) {
            const ns = namespaceOf(tag.name);
            const val = valueOf(tag.name);
            if (props.showNamespace && ns) return `${ns}:${val}`;
            return val;
        }

        const wrapperEl    = Vue.ref(null);
        const showTooltip  = Vue.ref(false);
        const tooltipStyle = Vue.ref({});

        const TIP_WIDTH = 320;
        const TIP_GAP   = 10;
        let hideTimer   = null;

        function computePos() {
            if (!wrapperEl.value) return;
            const rect = wrapperEl.value.getBoundingClientRect();
            let left = rect.left + rect.width / 2 - TIP_WIDTH / 2;
            left = Math.max(8, Math.min(left, window.innerWidth - TIP_WIDTH - 8));
            tooltipStyle.value = {
                position:   'fixed',
                top:        (rect.top - TIP_GAP) + 'px',
                left:       left + 'px',
                transform:  'translateY(-100%)',
                bottom:     'auto',
                visibility: 'visible',
                opacity:    '0',
                zIndex:     '9999',
                width:      TIP_WIDTH + 'px',
                transition: 'opacity 0.2s ease, transform 0.2s ease',
            };
        }

        function onEnter() {
            clearTimeout(hideTimer);
            computePos();
            showTooltip.value = true;
            Vue.nextTick(() => {
                tooltipStyle.value = { ...tooltipStyle.value, opacity: '1' };
            });
        }

        function onLeave() {
            hideTimer = setTimeout(() => { showTooltip.value = false; }, 120);
        }

        function onTooltipEnter() {
            clearTimeout(hideTimer);
        }

        function onTooltipLeave() {
            hideTimer = setTimeout(() => { showTooltip.value = false; }, 120);
        }

        function goToTagRules() {
            window.location.href = `/rule/rules_list?tags=${encodeURIComponent(props.tag.name)}`;
        }

        return {
            getTextColor, mapIcon, label,
            wrapperEl, showTooltip, tooltipStyle,
            onEnter, onLeave, onTooltipEnter, onTooltipLeave, goToTagRules,
        };
    },
    template: `
        <div class="tag-wrapper d-inline-block" ref="wrapperEl" @mouseenter="onEnter" @mouseleave="onLeave">
            <span class="tag-split shadow-sm on-hover-zoom" style="cursor:pointer" @click="goToTagRules" title="View all rules with this tag">
                <span class="tag-left" v-html="mapIcon(tag.icon)"></span>
                <span class="tag-right" :style="{ backgroundColor: tag.color || '#6c757d' }" :title="tag.name">
                    <span :style="{ color: getTextColor(tag.color || '#6c757d') }" class="fw-bold">
                        [[ label(tag) ]]
                    </span>
                </span>
            </span>

            <teleport to="body">
                <div v-if="showTooltip"
                     class="tag-tooltip"
                     :style="tooltipStyle"
                     @mouseenter="onTooltipEnter"
                     @mouseleave="onTooltipLeave">
                    <div class="tooltip-header" :style="{ borderLeft: '4px solid ' + (tag.color || '#6c757d') }">
                        <span v-html="mapIcon(tag.icon)" class="me-2 text-white"></span>
                        <strong class="text-white">[[ tag.name ]]</strong>
                    </div>
                    <div class="tooltip-body">
                        <div class="description-container">
                            <div class="description-scroll text-white-50">
                                [[ tag.description || 'No description available.' ]]
                            </div>
                        </div>
                        <div class="d-flex justify-content-between mt-2 pt-2 border-top border-white border-opacity-10" style="font-size:0.7rem;">
                            <span class="text-white-50">
                                <i :class="tag.visibility === 'public' ? 'fas fa-eye me-1' : 'fas fa-eye-slash me-1'"></i>
                                [[ tag.visibility || 'private' ]]
                            </span>
                            <span v-if="tag.created_at" class="text-white-50">
                                <i class="far fa-calendar-alt me-1"></i>[[ tag.created_at ]]
                            </span>
                        </div>
                    </div>
                    <div class="tooltip-arrow"></div>
                </div>
            </teleport>
        </div>
    `
};

export default SingleTagDisplay;
