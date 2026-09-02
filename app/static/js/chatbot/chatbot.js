/**
 * chatbot.js — floating assistant widget, prototype.
 * Mounts on #chatbot-widget in base.html.
 *
 * Talks to /chatbot/message, which itself talks to a self-hosted Ollama
 * instance — no API key, no billing. The model replies with a small
 * structured action ("create_rule" | "create_bundle" | "ask" | "chat"),
 * which the backend executes by calling straight into rule_core/bundle_core.
 * This widget only renders the conversation; it has no idea what the model
 * can or can't do beyond showing whatever reply text comes back.
 */

import { MASCOT_ENABLED } from '/static/js/components/mascot.js'

const { createApp, ref, nextTick } = Vue

function csrf() {
    return document.getElementById('csrf_token')?.value || ''
}

// Phrases known to hit a real search_rules filter reliably (see
// _maybe_search_rules_shortcut in chatbot_core.py) — the "try an example"
// dice button picks one at random so a user can see it actually work
// instead of guessing at phrasing.
const CHAT_EXAMPLES = [
    'Do you have rules for CVE-2024-3094?',
    'Do we have rules from https://github.com/Yara-Rules/rules?',
    'Show me rules tagged tlp:clear',
    'Do you have rules for attack technique T1055?',
    'Show me yara rules',
    'Do you have rules to detect Mimikatz?',
    'Take me to my rules',
]

const ChatbotWidget = {
    delimiters: ['[[', ']]'],
    setup() {
        const open     = ref(false)
        const draft    = ref('')
        const loading  = ref(false)
        const messages = ref([
            { role: 'assistant', content: "Hey, I'm Rulezy! Tell me to whip up a rule or a bundle, or send me hunting through the rule list — by tag, CVE, ATT&CK technique, author, a GitHub source, you name it. Or just say hi." },
        ])
        const messagesEl = ref(null)
        const inputEl    = ref(null)
        // Groups every message sent during this widget session into one row on
        // the admin conversation-history page — assigned by the backend on the
        // first reply, then reused for every message after that.
        const conversationId = ref(null)

        // Sent-message recall (Up/Down, like a shell history) — oldest first.
        const sentHistory  = ref([])
        const historyCursor = ref(null)  // null = live typing; 0 = most recent sent message, 1 = one before that, ...

        let lastExampleIndex = null
        function fillExample() {
            let idx = Math.floor(Math.random() * CHAT_EXAMPLES.length)
            if (CHAT_EXAMPLES.length > 1 && idx === lastExampleIndex) {
                idx = (idx + 1) % CHAT_EXAMPLES.length
            }
            lastExampleIndex = idx
            draft.value = CHAT_EXAMPLES[idx]
            historyCursor.value = null
            autoGrow()
            nextTick(() => inputEl.value?.focus())
        }

        async function scrollToBottom() {
            await nextTick()
            if (messagesEl.value) messagesEl.value.scrollTop = messagesEl.value.scrollHeight
        }

        async function autoGrow() {
            await nextTick()
            const el = inputEl.value
            if (!el) return
            el.style.height = 'auto'
            el.style.height = Math.min(el.scrollHeight, 200) + 'px'
        }

        function recallOlder(e) {
            const el = inputEl.value
            // Only hijack Up when the cursor is already on the first line —
            // otherwise Up should just move the cursor within the multi-line text.
            if (el && el.selectionStart !== 0) return
            if (!sentHistory.value.length) return
            e.preventDefault()
            historyCursor.value = historyCursor.value === null
                ? sentHistory.value.length - 1
                : Math.max(0, historyCursor.value - 1)
            draft.value = sentHistory.value[historyCursor.value]
            nextTick(() => { autoGrow(); if (el) el.setSelectionRange(0, 0) })
        }

        function recallNewer(e) {
            const el = inputEl.value
            if (historyCursor.value === null) return
            if (el && el.selectionStart !== draft.value.length) return
            e.preventDefault()
            if (historyCursor.value >= sentHistory.value.length - 1) {
                historyCursor.value = null
                draft.value = ''
            } else {
                historyCursor.value++
                draft.value = sentHistory.value[historyCursor.value]
            }
            autoGrow()
        }

        function onEnterKey(e) {
            if (e.shiftKey) return  // Shift+Enter -> let the textarea insert a newline
            e.preventDefault()
            send()
        }

        async function send() {
            const text = draft.value.trim()
            if (!text || loading.value) return

            sentHistory.value.push(text)
            historyCursor.value = null

            messages.value.push({ role: 'user', content: text })
            draft.value = ''
            loading.value = true
            autoGrow()
            scrollToBottom()

            // Only role/content ever gets sent back as history — link/error are
            // purely for this widget's own rendering.
            const history = messages.value
                .filter(m => m.role === 'user' || m.role === 'assistant')
                .slice(0, -1)
                .map(m => ({ role: m.role, content: m.content }))

            try {
                const res = await fetch('/chatbot/message', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf() },
                    body: JSON.stringify({ message: text, history, conversation_id: conversationId.value }),
                })
                const data = await res.json()
                if (data.conversation_uuid) conversationId.value = data.conversation_uuid
                messages.value.push({
                    role: 'assistant',
                    content: data.reply || (res.ok ? '...' : 'Something went wrong.'),
                    link: data.link || null,
                    links: data.links || null,
                    error: !res.ok,
                })
                // search_rules: let the user read the confirmation for a beat,
                // then actually navigate — this is a redirect, not just a link.
                // (data.links means several equally-valid options were proposed
                // instead — e.g. more than one format named at once — so there's
                // no single "the" destination to auto-navigate to.)
                if (res.ok && data.redirect) {
                    setTimeout(() => { window.location.href = data.redirect }, 600)
                }
            } catch (e) {
                messages.value.push({ role: 'assistant', content: 'Could not reach the server.', error: true })
            } finally {
                loading.value = false
                scrollToBottom()
            }
        }

        return { open, draft, loading, messages, messagesEl, inputEl, send, autoGrow, recallOlder, recallNewer, onEnterKey, fillExample, MASCOT_ENABLED }
    },

    template: `
<div>
    <!-- ── Collapsed button ── -->
    <button v-if="!open" class="chatbot-fab" @click="open = true" title="Chat assistant">
        <img v-if="MASCOT_ENABLED" src="/static/images/rulezy/chatbot.png" alt="" class="chatbot-fab__mascot">
        <i v-else class="fa-solid fa-comment-dots"></i>
    </button>

    <!-- ── Expanded panel ── -->
    <div v-else class="chatbot-panel">
        <div class="chatbot-header">
            <img v-if="MASCOT_ENABLED" src="/static/images/rulezy/chatbot.png" alt="" class="chatbot-header__mascot">
            <i v-else class="fa-solid fa-comment-dots"></i>
            <span class="chatbot-header__title">Rulezy <span class="chatbot-badge">prototype</span></span>
            <button type="button" class="chatbot-btn" @click="fillExample" title="Try an example that works" :disabled="loading">
                <i class="fa-solid fa-dice"></i>
            </button>
            <button class="chatbot-btn" @click="open = false" title="Close"><i class="fa-solid fa-xmark"></i></button>
        </div>

        <div class="chatbot-messages" ref="messagesEl">
            <div v-for="(m, i) in messages" :key="i" :class="['chatbot-msg', m.role === 'user' ? 'chatbot-msg--user' : 'chatbot-msg--bot', m.error ? 'chatbot-msg--error' : '']">
                <div class="chatbot-msg__bubble">
                    [[ m.content ]]
                    <a v-if="m.link" :href="m.link" class="chatbot-msg__link">Open <i class="fa-solid fa-arrow-up-right-from-square"></i></a>
                    <div v-if="m.links" class="chatbot-msg__links">
                        <a v-for="l in m.links" :key="l.url" :href="l.url" class="chatbot-msg__link">[[ l.label ]] <i class="fa-solid fa-arrow-up-right-from-square"></i></a>
                    </div>
                </div>
            </div>
            <div v-if="loading" class="chatbot-msg chatbot-msg--bot chatbot-msg--thinking">
                <span v-if="MASCOT_ENABLED" class="rulezy-say" tabindex="0">
                    <img src="/static/images/rulezy/reflexion.png" alt="" class="chatbot-thinking__mascot">
                    <span class="rulezy-say__bubble" style="max-width:180px;">Give me a sec, I'm doing very serious robot thinking.</span>
                </span>
                <i v-else class="fa-solid fa-circle-notch fa-spin"></i>
                <div class="chatbot-msg__bubble chatbot-typing"><span></span><span></span><span></span></div>
            </div>
        </div>

        <form class="chatbot-input-row" @submit.prevent="send">
            <textarea
                ref="inputEl"
                v-model="draft"
                class="chatbot-input"
                rows="1"
                placeholder="Create a rule, make a bundle... (Shift+Enter for a new line)"
                :disabled="loading"
                @input="autoGrow"
                @keydown.enter="onEnterKey"
                @keydown.up="recallOlder"
                @keydown.down="recallNewer"
            ></textarea>
            <button type="submit" class="chatbot-send" :disabled="loading || !draft.trim()">
                <i class="fa-solid fa-paper-plane"></i>
            </button>
        </form>
    </div>
</div>
`,
}

createApp(ChatbotWidget).mount('#chatbot-widget')
