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
 * Stages with a matching Rulezy mascot pose (AI_MASCOT_CONCEPT.md) render
 * that pose as a small image instead of a Font Awesome icon — see `image`
 * in STAGE_META below (`app/static/images/rulezy/*.png`). A stage with no
 * pose (writing/failed) keeps its Font Awesome icon; this is a per-stage
 * choice, not an all-or-nothing swap, since only some poses have a clean
 * conceptual match to a pipeline stage.
 *
 * 'error' is special-cased: it's not something an agent streams (the
 * protocol's own failure state is 'failed') — it's pushed locally by a
 * caller's fetch `catch` block when the request never made it to/from the
 * server at all (network drop, etc). It gets Rulezy's own "uh oh" reaction
 * and its text is read as Rulezy startled by what just happened, not a
 * calm status line — see displayText()/isError() below.
 */

import { MASCOT_ENABLED } from './mascot.js'

const TERMINAL_STAGES = new Set(['done', 'failed', 'error'])

const RULEZY = '/static/images/rulezy/'

const STAGE_META = {
    reading:    { icon: 'fa-magnifying-glass',    tone: 'blue',   image: RULEZY + 'db.png' },
    thinking:   { icon: 'fa-brain',               tone: 'purple', image: RULEZY + 'reflexion.png' },
    writing:    { icon: 'fa-pen-fancy',           tone: 'blue' },
    validating: { icon: 'fa-check-double',        tone: 'blue',   image: RULEZY + 'rule-fixer.png' },
    searching:  { icon: 'fa-database',            tone: 'blue',   image: RULEZY + 'lookup.png' },
    done:       { icon: 'fa-circle-check',        tone: 'green',  image: RULEZY + 'armcross.png' },
    failed:     { icon: 'fa-circle-xmark',        tone: 'red'   },
    error:      { icon: 'fa-triangle-exclamation', tone: 'red',    image: RULEZY + 'reflexion.png' },
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
        function imageFor(stage) {
            return MASCOT_ENABLED ? metaFor(stage).image : null
        }
        function isError(stage) {
            return stage === 'error'
        }
        function displayText(step) {
            return isError(step.stage) ? `Aieeee, j'ai eu ça : ${step.text}` : step.text
        }
        return { isCurrent, toneClass, iconClass, imageFor, isError, displayText }
    },

    template: `
<div v-if="steps.length" class="ats">
    <div v-for="(step, i) in steps" :key="i"
         class="ats-item"
         :class="{ 'ats-item--current': isCurrent(i), 'ats-item--last': i === steps.length - 1 }">
        <div class="ats-rail">
            <div class="ats-icon" :class="[toneClass(step.stage), { 'ats-icon--mascot': imageFor(step.stage) }]">
                <img v-if="imageFor(step.stage)" :src="imageFor(step.stage)" alt="" class="ats-mascot">
                <i v-else class="fa-solid" :class="[iconClass(step.stage), { 'fa-spin': isCurrent(i) && step.stage === 'thinking' }]"></i>
            </div>
            <div v-if="i < steps.length - 1" class="ats-line"></div>
        </div>
        <div class="ats-text" :class="{ 'ats-text--pulse': isCurrent(i), 'ats-text--error': isError(step.stage) }">
            {{ displayText(step) }}<span v-if="isCurrent(i)" class="ats-dots" aria-hidden="true"><span></span><span></span><span></span></span>
        </div>
    </div>
</div>
    `,
}
