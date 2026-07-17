/**
 * WidgetFrame — shared chrome for every dashboard widget (KPI / chart / list / ...).
 * Owns only the header (icon, title, reload, settings, remove) and the
 * settings popover toggle — each widget type owns its own data-fetching and
 * body markup via the default slot, and its own settings form via the
 * "settings" slot.
 *
 * Props:
 *   title    String
 *   icon     String   font-awesome class, e.g. 'fa-shield-halved'
 *   loading  Boolean  spins the reload button
 *
 * Emits:
 *   reload         — user clicked the reload button
 *   remove         — user confirmed removing this widget
 *   save-settings  — user clicked "Save" inside the settings popover
 */
const { ref } = Vue

const WidgetFrame = {
    props: {
        title:   { type: String, default: '' },
        icon:    { type: String, default: 'fa-chart-simple' },
        loading: { type: Boolean, default: false },
    },
    emits: ['reload', 'remove', 'save-settings'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const showSettings = ref(false)

        function toggleSettings() { showSettings.value = !showSettings.value }
        function saveSettings() {
            showSettings.value = false
            emit('save-settings')
        }
        function confirmRemove() {
            if (confirm('Remove this widget from your dashboard?')) emit('remove')
        }

        return { showSettings, toggleSettings, saveSettings, confirmRemove }
    },
    template: `
    <div class="dw-widget h-100 d-flex flex-column">
        <div class="dw-widget-header">
            <span class="dw-widget-title">
                <i :class="'fa-solid ' + icon + ' me-2'"></i>[[ title ]]
            </span>
            <div class="dw-widget-actions">
                <button type="button" class="dw-widget-btn" title="Reload" @click="$emit('reload')" :disabled="loading">
                    <i class="fa-solid fa-arrows-rotate" :class="{ 'fa-spin': loading }"></i>
                </button>
                <button type="button" class="dw-widget-btn" title="Settings" @click="toggleSettings">
                    <i class="fa-solid fa-gear"></i>
                </button>
                <button type="button" class="dw-widget-btn dw-widget-btn--danger" title="Remove" @click="confirmRemove">
                    <i class="fa-solid fa-xmark"></i>
                </button>
            </div>
        </div>

        <div class="dw-widget-body flex-grow-1 position-relative">
            <div v-if="loading" class="dw-widget-loading">
                <i class="fa-solid fa-arrows-rotate fa-spin"></i>
            </div>
            <slot></slot>
        </div>

        <div v-if="showSettings" class="dw-widget-settings">
            <slot name="settings"></slot>
            <div class="dw-widget-settings-actions">
                <button type="button" class="btn btn-sm btn-outline-secondary rounded-pill px-3" @click="showSettings = false">Cancel</button>
                <button type="button" class="btn btn-sm btn-primary rounded-pill px-3" @click="saveSettings">Save</button>
            </div>
        </div>
    </div>
    `,
}

export default WidgetFrame
