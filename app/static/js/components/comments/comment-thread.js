/**
 * comment-thread.js — Recursive comment thread component.
 * Uses Vue 3 Composition API, ES modules, delimiters [[...]].
 *
 * Deep-link: pass ?comment=<id> in the URL to auto-scroll, expand ancestors,
 * and highlight the target comment.
 */
const { ref, computed, onMounted, nextTick } = Vue
import { apiFetch } from '/static/js/constants.js'
import { create_message } from '/static/js/toaster.js'
import UserChip from '/static/js/components/UserChip.js'
import ReportModal from '/static/js/components/ReportModal.js'

const TOAST = { SUCCESS: 'success', WARNING: 'warning', ERROR: 'danger', INFO: 'info' }

// ── Deep-link shared state ─────────────────────────────────────────────────
// Populated by CommentThread on mount; read by every CommentItem on mount.
const DEEP_LINK = Vue.reactive({
    targetId: null,       // integer ID of the comment to highlight
    ancestorIds: new Set(),  // IDs of comments that need auto-expand (ancestors of target)
})

// ── Helper ─────────────────────────────────────────────────────────────────

function fmt_date(dateStr) {
    if (!dateStr) return ''
    return new Date(dateStr).toLocaleDateString('en-US', {
        year: 'numeric', month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit',
    })
}

// ── CommentItem ────────────────────────────────────────────────────────────

const CommentItem = {
    name: 'CommentItem',
    delimiters: ['[[', ']]'],
    props: {
        comment: { type: Object, required: true },
        canCreate: { type: Boolean, default: false },
        canEditOwn: { type: Boolean, default: false },
        canDeleteOwn: { type: Boolean, default: false },
        canModerate: { type: Boolean, default: false },
        currentUserId: { type: Number, default: 0 },
        csrfToken: { type: String, default: '' },
    },
    setup(props) {
        const collapsed = ref(false)
        const showReplyForm = ref(false)
        const showEditForm = ref(false)
        const replyContent = ref('')
        const editContent = ref(props.comment.content)
        const submitting = ref(false)
        const highlighted = ref(false)

        const replies = ref([])
        const repliesPage = ref(1)
        const repliesTotal = ref(props.comment.reply_count || 0)
        const repliesLoaded = ref(false)
        const repliesLoading = ref(false)

        const likeCount = ref(props.comment.like_count || 0)
        const dislikeCount = ref(props.comment.dislike_count || 0)
        const userReaction = ref(props.comment.user_reaction || null)
        const isDeleted = ref(props.comment.is_deleted || false)
        const content = ref(props.comment.content)
        const isPublic = ref(props.comment.is_public)
        const githubIssueUrl = ref(props.comment.github_issue_url || null)
        const githubIssueNumber = ref(props.comment.github_issue_number || null)
        const creatingIssue = ref(false)

        const canEdit = computed(() =>
            !isDeleted.value && (
                (props.canEditOwn && props.comment.created_by === props.currentUserId) ||
                props.canModerate
            )
        )
        const canDelete = computed(() =>
            !isDeleted.value && (
                (props.canDeleteOwn && props.comment.created_by === props.currentUserId) ||
                props.canModerate
            )
        )
        const canRestore = computed(() => props.canModerate && isDeleted.value)

        async function loadReplies(reset = false) {
            if (repliesLoading.value) return
            if (reset) {
                replies.value = []
                repliesPage.value = 1
                repliesLoaded.value = false
            }
            repliesLoading.value = true
            const res = await apiFetch(
                `/api/comments/?object_type=${props.comment.object_type}&object_id=${props.comment.object_id}&parent_id=${props.comment.id}&page=${repliesPage.value}&per_page=20`
            )
            if (res.ok) {
                const d = await res.json()
                replies.value = [...replies.value, ...d.items]
                repliesTotal.value = d.total
                repliesLoaded.value = true
                repliesPage.value++
            }
            repliesLoading.value = false
        }

        async function submitReply() {
            if (!replyContent.value.trim()) return
            submitting.value = true
            const res = await apiFetch('/api/comments/', 'POST', {
                object_type: props.comment.object_type,
                object_id: props.comment.object_id,
                content: replyContent.value,
                parent_id: props.comment.id,
            })
            const d = await res.json()
            if (res.ok) {
                replyContent.value = ''
                showReplyForm.value = false
                repliesTotal.value += 1
                replies.value.push(d.comment)
                repliesLoaded.value = true
                create_message(d.message, TOAST.SUCCESS)
            } else {
                create_message(d.message || 'Failed', TOAST.ERROR)
            }
            submitting.value = false
        }

        async function submitEdit() {
            if (!editContent.value.trim()) return
            submitting.value = true
            const res = await apiFetch(`/api/comments/${props.comment.uuid}`, 'PUT', {
                content: editContent.value,
            })
            const d = await res.json()
            if (res.ok) {
                content.value = d.comment.content
                showEditForm.value = false
                create_message(d.message, TOAST.SUCCESS)
            } else {
                create_message(d.message || 'Failed', TOAST.ERROR)
            }
            submitting.value = false
        }

        async function doDelete() {
            if (!confirm('Delete this comment?')) return
            const res = await apiFetch(`/api/comments/${props.comment.uuid}`, 'DELETE')
            const d = await res.json()
            if (res.ok) {
                isDeleted.value = true
                content.value = '[deleted]'
                create_message(d.message, TOAST.WARNING)
            } else {
                create_message(d.message || 'Failed', TOAST.ERROR)
            }
        }

        async function doHardDelete() {
            const replyCount = repliesTotal.value || 0
            const msg = replyCount > 0
                ? `Permanently delete this comment AND its ${replyCount} reply/replies? This cannot be undone.`
                : 'Permanently delete this comment? This cannot be undone.'
            if (!confirm(msg)) return
            const res = await apiFetch(`/api/comments/${props.comment.uuid}/hard_delete`, 'DELETE')
            const d = await res.json()
            if (res.ok) {
                isDeleted.value = true
                content.value = '[permanently deleted]'
                create_message(d.message, TOAST.WARNING)
            } else {
                create_message(d.message || 'Hard delete failed', TOAST.ERROR)
            }
        }

        async function doRestore() {
            const res = await apiFetch(`/api/comments/${props.comment.uuid}/restore`, 'POST', {})
            const d = await res.json()
            if (res.ok) {
                isDeleted.value = false
                content.value = d.comment.content
                create_message(d.message, TOAST.SUCCESS)
            } else {
                create_message(d.message || 'Failed', TOAST.ERROR)
            }
        }

        async function createGithubIssue() {
            if (creatingIssue.value || githubIssueUrl.value) return
            if (!confirm('File this comment as a new issue on the official rulezet-core GitHub repo?')) return
            creatingIssue.value = true
            const res = await apiFetch(`/api/comments/${props.comment.uuid}/create_issue`, 'POST', {})
            const d = await res.json()
            if (res.ok) {
                githubIssueUrl.value = d.issue_url
                githubIssueNumber.value = d.issue_number
                create_message(d.message, TOAST.SUCCESS)
            } else {
                create_message(d.message || 'Failed to create issue', TOAST.ERROR)
            }
            creatingIssue.value = false
        }

        async function doReact(reaction) {
            const res = await apiFetch(`/api/comments/${props.comment.uuid}/react`, 'POST', { reaction })
            const d = await res.json()
            if (res.ok) {
                likeCount.value = d.like_count
                dislikeCount.value = d.dislike_count
                userReaction.value = d.user_reaction
            } else {
                create_message(d.message || 'Failed', TOAST.ERROR)
            }
        }

        function startEdit() {
            editContent.value = content.value
            showEditForm.value = true
        }

        const hasMoreReplies = computed(() =>
            repliesLoaded.value && replies.value.length < repliesTotal.value
        )

        // ── Deep-link: auto-expand ancestors / highlight target ────────────
        onMounted(async () => {
            if (!DEEP_LINK.targetId) return

            if (DEEP_LINK.targetId === props.comment.id) {
                // This IS the target comment — highlight and scroll
                await nextTick()
                const el = document.getElementById(`comment-${props.comment.id}`)
                if (el) {
                    collapsed.value = false
                    el.scrollIntoView({ behavior: 'smooth', block: 'center' })
                }
                highlighted.value = true
                // Remove class after animation so re-navigation works
                setTimeout(() => { highlighted.value = false }, 3000)

            } else if (DEEP_LINK.ancestorIds.has(props.comment.id)) {
                // This comment is an ancestor — auto-expand its replies
                collapsed.value = false
                await loadReplies()
            }
        })

        return {
            collapsed, showReplyForm, showEditForm,
            replyContent, editContent, submitting, highlighted,
            replies, repliesTotal, repliesLoaded, repliesLoading,
            likeCount, dislikeCount, userReaction,
            isDeleted, content, isPublic,
            githubIssueUrl, githubIssueNumber, creatingIssue,
            canEdit, canDelete, canRestore, hasMoreReplies,
            loadReplies, submitReply, submitEdit, doDelete, doHardDelete, doRestore, doReact,
            createGithubIssue, startEdit, fmt_date,
        }
    },
    template: `
<div class="cm-item" :id="'comment-' + comment.id" :class="{
    'cm-item--deleted':     isDeleted,
    'cm-item--private':     !isPublic,
    'cm-item--collapsed':   collapsed,
    'cm-item--highlighted': highlighted,
}">
    <div class="cm-header">
        <user-chip
            v-if="comment.author?.id"
            :user-id="comment.author.id"
            :username="comment.author.name || ''"
            :avatar="comment.author.avatar ? '/static/uploads/avatars/' + comment.author.avatar : null"
            size="sm">
        </user-chip>
        <span v-else class="cm-author">Unknown</span>

        <span v-if="comment.is_admin" class="cm-admin-badge" title="This comment was posted by a site administrator">
            <i class="fas fa-shield-alt"></i>Admin
        </span>

        <span v-if="comment.created_by === currentUserId" class="cm-you-badge" title="This comment was posted by you">
            <i class="fas fa-user"></i>You
        </span>

        <span class="cm-date">[[ fmt_date(comment.created_at) ]]</span>
        <span v-if="!isPublic" class="cm-private-badge">
            <i class="fas fa-lock" style="font-size:.6rem;"></i>Private
        </span>
        <button class="cm-collapse-btn" @click="collapsed = !collapsed"
                :title="collapsed ? 'Expand' : 'Collapse'">
            <i :class="collapsed ? 'fas fa-chevron-down' : 'fas fa-chevron-up'"></i>
        </button>
    </div>

    <div class="cm-body">[[ content ]]</div>

    <div v-if="!showEditForm" class="cm-actions">
        <button class="cm-react-btn"
                :class="{ 'cm-react-btn--active cm-react-btn--like': userReaction === 'like' }"
                @click="doReact('like')"
                :disabled="!currentUserId">
            <i class="fas fa-thumbs-up"></i> [[ likeCount ]]
        </button>
        <button class="cm-react-btn"
                :class="{ 'cm-react-btn--active cm-react-btn--dislike': userReaction === 'dislike' }"
                @click="doReact('dislike')"
                :disabled="!currentUserId">
            <i class="fas fa-thumbs-down"></i> [[ dislikeCount ]]
        </button>

        <button v-if="canCreate && !isDeleted" class="cm-action-btn"
                @click="showReplyForm = !showReplyForm">
            <i class="fas fa-reply"></i> Reply
        </button>
        <button v-if="canEdit" class="cm-action-btn" @click="startEdit">
            <i class="fas fa-pen"></i> Edit
        </button>
        <button v-if="canDelete" class="cm-action-btn" style="color:var(--text-muted);" @click="doDelete">
            <i class="fas fa-trash"></i> Delete
        </button>
        <button v-if="canRestore" class="cm-action-btn" style="color:#16a34a;" @click="doRestore">
            <i class="fas fa-rotate-left"></i> Restore
        </button>
        <button v-if="canModerate" class="cm-action-btn" style="color:#dc3545;" @click="doHardDelete"
                title="Permanently delete this comment and all its replies">
            <i class="fas fa-skull"></i> Hard delete
        </button>
        <a v-if="canModerate && githubIssueUrl" class="cm-action-btn" style="color:#6f42c1;"
           :href="githubIssueUrl" target="_blank" rel="noopener" title="View the filed GitHub issue">
            <i class="fab fa-github"></i> Issue #[[ githubIssueNumber ]]
        </a>
        <button v-else-if="canModerate && !isDeleted" class="cm-action-btn" style="color:#6f42c1;"
                :disabled="creatingIssue" @click="createGithubIssue"
                title="File this comment as an issue on the official rulezet-core GitHub repo">
            <i v-if="creatingIssue" class="fas fa-spinner fa-spin"></i>
            <i v-else class="fab fa-github"></i> [[ creatingIssue ? 'Filing…' : 'Create issue' ]]
        </button>
        <report-modal v-if="currentUserId && !isDeleted && currentUserId !== comment.created_by"
            object-type="comment"
            :object-id="comment.id"
            object-label="comment"
            :csrf-token="csrfToken">
            <template #trigger="{ open }">
                <button class="cm-action-btn" @click="open" title="Report this comment">
                    <i class="fas fa-flag"></i> Report
                </button>
            </template>
        </report-modal>
    </div>

    <!-- Edit form -->
    <div v-if="showEditForm" class="cm-edit-form">
        <textarea class="form-control form-control-sm" v-model="editContent" rows="3"></textarea>
        <div class="cm-form-actions">
            <button class="btn btn-primary btn-sm" :disabled="submitting" @click="submitEdit">
                <span v-if="submitting"><i class="fas fa-spinner fa-spin me-1"></i>Saving…</span>
                <span v-else>Save</span>
            </button>
            <button class="btn btn-outline-secondary btn-sm" @click="showEditForm = false">Cancel</button>
        </div>
    </div>

    <!-- Reply form -->
    <div v-if="showReplyForm" class="cm-reply-form">
        <textarea class="form-control form-control-sm" v-model="replyContent"
                  rows="3" placeholder="Write a reply…"></textarea>
        <div class="cm-form-actions">
            <button class="btn btn-primary btn-sm" :disabled="submitting || !replyContent.trim()"
                    @click="submitReply">
                <span v-if="submitting"><i class="fas fa-spinner fa-spin me-1"></i>Posting…</span>
                <span v-else>Post reply</span>
            </button>
            <button class="btn btn-outline-secondary btn-sm" @click="showReplyForm = false; replyContent = ''">Cancel</button>
        </div>
    </div>

    <!-- Replies -->
    <div v-if="!collapsed" class="cm-indent">
        <button v-if="!repliesLoaded && repliesTotal > 0" class="cm-load-more"
                @click="loadReplies()">
            <i class="fas fa-comments me-1"></i>
            <span v-if="repliesLoading"><i class="fas fa-spinner fa-spin"></i></span>
            <span v-else>Show [[ repliesTotal ]] repl[[ repliesTotal === 1 ? 'y' : 'ies' ]]</span>
        </button>

        <comment-item v-for="reply in replies" :key="reply.uuid"
            :comment="reply"
            :can-create="canCreate"
            :can-edit-own="canEditOwn"
            :can-delete-own="canDeleteOwn"
            :can-moderate="canModerate"
            :current-user-id="currentUserId"
            :csrf-token="csrfToken" />

        <button v-if="hasMoreReplies" class="cm-load-more" @click="loadReplies()"
                :disabled="repliesLoading">
            <span v-if="repliesLoading"><i class="fas fa-spinner fa-spin me-1"></i>Loading…</span>
            <span v-else><i class="fas fa-ellipsis me-1"></i>Load more replies ([[ repliesTotal - replies.length ]] remaining)</span>
        </button>
    </div>
</div>
    `,
}

// Self-referential for recursion (also includes UserChip and ReportModal)
CommentItem.components = { CommentItem, UserChip, ReportModal }

// ── CommentThread ──────────────────────────────────────────────────────────

const CommentThread = {
    name: 'CommentThread',
    delimiters: ['[[', ']]'],
    components: { CommentItem },
    props: {
        objectType: { type: String, required: true },
        objectId: { type: Number, required: true },
        canCreate: { type: Boolean, default: false },
        canEditOwn: { type: Boolean, default: false },
        canDeleteOwn: { type: Boolean, default: false },
        canModerate: { type: Boolean, default: false },
        currentUserId: { type: Number, default: 0 },
        csrfToken: { type: String, default: '' },
    },
    setup(props) {
        const comments = ref([])
        const page = ref(1)
        const total = ref(0)
        const loading = ref(false)
        const newContent = ref('')
        const submitting = ref(false)
        const sentinelRef = ref(null)
        const hasNext = ref(false)

        async function loadComments(reset = false) {
            if (loading.value) return
            if (reset) {
                comments.value = []
                page.value = 1
                hasNext.value = false
            }
            loading.value = true
            const res = await apiFetch(
                `/api/comments/?object_type=${props.objectType}&object_id=${props.objectId}&page=${page.value}&per_page=20`
            )
            if (res.ok) {
                const d = await res.json()
                comments.value = [...comments.value, ...d.items]
                total.value = d.total
                hasNext.value = d.has_next
                page.value++
            }
            loading.value = false
        }

        async function submitComment() {
            if (!newContent.value.trim()) return
            submitting.value = true
            const res = await apiFetch('/api/comments/', 'POST', {
                object_type: props.objectType,
                object_id: props.objectId,
                content: newContent.value,
            })
            const d = await res.json()
            if (res.ok) {
                newContent.value = ''
                comments.value.unshift(d.comment)
                total.value += 1
                create_message(d.message, TOAST.SUCCESS)
            } else {
                create_message(d.message || 'Failed', TOAST.ERROR)
            }
            submitting.value = false
        }

        function setupSentinel() {
            if (!sentinelRef.value) return
            const observer = new IntersectionObserver((entries) => {
                if (entries[0].isIntersecting && hasNext.value && !loading.value) {
                    loadComments()
                }
            }, { threshold: 0.1 })
            observer.observe(sentinelRef.value)
        }

        onMounted(async () => {
            // ── Deep-link: resolve BEFORE loading comments so CommentItem
            // mounted hooks see DEEP_LINK already populated ────────────────
            const urlParams = new URLSearchParams(window.location.search)
            const targetId = parseInt(urlParams.get('comment'))
            let rootId = null

            if (targetId) {
                // Always set targetId so CommentItem can scroll/highlight even if
                // resolve fails (e.g. comment exists but ancestors are unknown).
                DEEP_LINK.targetId = targetId
                DEEP_LINK.ancestorIds = new Set()
                rootId = targetId  // fallback: treat the comment itself as root

                try {
                    const res = await apiFetch(`/api/comments/resolve/${targetId}`)
                    if (res.ok) {
                        const info = await res.json()
                        DEEP_LINK.ancestorIds = new Set(info.ancestors || [])
                        rootId = info.root_id || targetId
                    }
                } catch (_) { /* network error — keep fallback */ }
            }

            // Load first page of comments
            await loadComments()

            // Keep loading pages until the root ancestor is in the list
            if (rootId) {
                let found = comments.value.some(c => c.id === rootId)
                while (!found && hasNext.value && !loading.value) {
                    await loadComments()
                    found = comments.value.some(c => c.id === rootId)
                }
            }

            await nextTick()
            setupSentinel()
            // CommentItem onMounted hooks trigger scroll/highlight/expand from here
        })

        return {
            comments, total, loading, newContent, submitting,
            sentinelRef, hasNext,
            loadComments, submitComment, setupSentinel,
        }
    },
    template: `
<div>
    <!-- New comment form -->
    <div v-if="canCreate" class="cm-new-form mb-3">
        <p class="cm-new-form-title"><i class="fas fa-comment me-1"></i>Leave a comment</p>
        <textarea class="form-control form-control-sm mb-2" v-model="newContent"
                  rows="3" placeholder="Write a comment…"></textarea>
        <button class="btn btn-primary btn-sm"
                :disabled="submitting || !newContent.trim()"
                @click="submitComment">
            <span v-if="submitting"><i class="fas fa-spinner fa-spin me-1"></i>Posting…</span>
            <span v-else><i class="fas fa-paper-plane me-1"></i>Post comment</span>
        </button>
    </div>

    <!-- Comment count -->
    <p v-if="total > 0" style="font-size:.82rem; color:var(--text-muted); margin-bottom:.5rem;">
        [[ total ]] comment[[ total === 1 ? '' : 's' ]]
    </p>

    <!-- Thread -->
    <div class="cm-thread">
        <comment-item
            v-for="c in comments"
            :key="c.uuid"
            :comment="c"
            :can-create="canCreate"
            :can-edit-own="canEditOwn"
            :can-delete-own="canDeleteOwn"
            :can-moderate="canModerate"
            :current-user-id="currentUserId"
            :csrf-token="csrfToken" />
    </div>

    <!-- Loading indicator -->
    <div v-if="loading" class="text-center py-3">
        <div class="spinner-border spinner-border-sm text-secondary" role="status"></div>
    </div>

    <!-- Empty state -->
    <div v-if="!loading && comments.length === 0" class="cm-empty">
        <i class="fas fa-comments"></i>
        No comments yet. Be the first to comment!
    </div>

    <!-- Infinite scroll sentinel -->
    <div ref="sentinelRef" id="cm-sentinel" style="height:1px;"></div>
</div>
    `,
}

export default CommentThread
