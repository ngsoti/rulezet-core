/**
 * ai-thinking-steps.js — Shared "AI is thinking" step display.
 *
 * Renders the shared step protocol every AI agent action streams
 * (AI_00_FOUNDATION.md §10, ~/Documents/Rulezet/IA-Integration-plan/):
 * a small ordered list of {stage, text} events, one row per stage, instead
 * of a raw terminal log. Meant to read like a real assistant narrating what
 * it's doing — "Reading the rule…", "Thinking through a fix…" — not attempt
 * counters.
 *
 * Props:
 *   steps   Array   Required. [{ stage, text }] in the order received —
 *                    stage is one of STAGE_META's keys below (an unknown
 *                    stage falls back to a generic dot, so new agents can
 *                    introduce their own stages without a component change).
 *   active  Boolean Whether the flow is still running (default: false) —
 *                    while true, the LAST step pulses instead of sitting
 *                    static, unless it's already a terminal stage
 *                    (done/failed/error).
 *
 * Each stage's icon is a Font Awesome placeholder (AI_MASCOT_CONCEPT.md) —
 * once the mascot exists, swap the <i> in ats-icon for an <img> of that
 * stage's pose, keyed the same way, without touching any caller.
 */

const TERMINAL_STAGES = new Set(['done', 'failed', 'error'])

const STAGE_META = {
    reading:    { icon: 'fa-magnifying-glass',    tone: 'blue'   },
    thinking:   { icon: 'fa-brain',               tone: 'purple' },
    writing:    { icon: 'fa-pen-fancy',           tone: 'blue'   },
    validating: { icon: 'fa-check-double',        tone: 'blue'   },
    searching:  { icon: 'fa-database',            tone: 'blue'   },
    done:       { icon: 'fa-circle-check',        tone: 'green'  },
    failed:     { icon: 'fa-circle-xmark',        tone: 'red'    },
    error:      { icon: 'fa-triangle-exclamation', tone: 'red'   },
}
const DEFAULT_META = { icon: 'fa-circle-notch', tone: 'blue' }

function metaFor(stage) {
    return STAGE_META[stage] || DEFAULT_META
}

export default {
    name: 'AIThinkingSteps',

    props: {
        steps:  { type: Array,   default: () => [] },
        active: { type: Boolean, default: false },
    },

    setup(props) {
        function isCurrent(index) {
            return props.active && index === props.steps.length - 1 && !TERMINAL_STAGES.has(props.steps[index]?.stage)
        }
        function toneClass(stage) {
            return 'ats-icon--' + metaFor(stage).tone
        }
        function iconClass(stage) {
            return metaFor(stage).icon
        }
        return { isCurrent, toneClass, iconClass }
    },

    template: `
<div v-if="steps.length" class="ats">
    <div v-for="(step, i) in steps" :key="i"
         class="ats-item"
         :class="{ 'ats-item--current': isCurrent(i), 'ats-item--last': i === steps.length - 1 }">
        <div class="ats-rail">
            <div class="ats-icon" :class="toneClass(step.stage)">
                <i class="fa-solid" :class="[iconClass(step.stage), { 'fa-spin': isCurrent(i) && step.stage === 'thinking' }]"></i>
            </div>
            <div v-if="i < steps.length - 1" class="ats-line"></div>
        </div>
        <div class="ats-text" :class="{ 'ats-text--pulse': isCurrent(i) }">{{ step.text }}</div>
    </div>
</div>
    `,
}
