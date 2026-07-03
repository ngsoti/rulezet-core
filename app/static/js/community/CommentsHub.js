/**
 * CommentsHub — cross-object comment directory.
 *
 * Built on the shared DataTable component (search, card/table view toggle,
 * click-to-sort column headers, shared pagination across both views), with a
 * RuleList-style filter panel on top: include-replies scope switch, "mine only"
 * participation switch, min-comment-count threshold and a date range.
 *
 * Expanded groups embed the real CommentThread component (capped preview via
 * its per-page / auto-load props) so comments render identically to detail
 * pages; deep links (?comment=<id>) jump into the full thread in context.
 *
 * Data source: GET /api/comments/hub
 */
import DataTable from '/static/js/components/table/data-table.js'
import CommentThread from '/static/js/components/comments/comment-thread.js'
import UserChip from '/static/js/components/UserChip.js'

const { ref, reactive, computed, watch, nextTick } = Vue

const PREVIEW_PER_PAGE = 3

const TYPE_META = {
    rule:      { icon: 'fa-solid fa-shield-halved', label: 'Rule' },
    bundle:    { icon: 'fa-solid fa-box',           label: 'Bundle' },
    blog_post: { icon: 'fa-solid fa-newspaper',     label: 'Blog post' },
}

const CATEGORY_ICON = {
    comment:  'fa-regular fa-comment',
    proposal: 'fa-solid fa-code-pull-request',
}

const COLUMNS = [
    { key: 'title',         label: 'Title',          sortable: true },
    { key: 'object_type',   label: 'Type',           sortable: true, width: '190px' },
    { key: 'comment_count', label: 'Comments',       sortable: true, width: '110px' },
    { key: 'participants',  label: 'Participants',   width: '150px' },
    { key: 'last_activity', label: 'Last activity',  sortable: true, width: '170px' },
    { key: 'latest',        label: 'Latest comment', truncate: true },
]

export default {
    name: 'CommentsHub',
    delimiters: ['[[', ']]'],
    components: {
        'data-table': DataTable,
        'comment-thread': CommentThread,
        'user-chip': UserChip,
    },
    props: {
        currentUserId:      { type: Number,  default: 0 },
        currentUserIsAdmin: { type: Boolean, default: false },
        csrfToken:          { type: String,  default: '' },
        // Locks the view to the current user's own threads (account page's
        // "My comments" tab) — hides the "Mine only" switch since it's implied.
        forceMineOnly:      { type: Boolean, default: false },
    },
    setup(props) {
        const includeReplies = ref(false)
        const mineOnly       = ref(props.forceMineOnly)
        // Input ref debounces into the applied ref so the fetchUrl watcher
        // doesn't refetch on every keystroke.
        const minCommentsInput = ref('')
        const minComments      = ref('')
        const dateFrom       = ref('')
        const dateTo         = ref('')
        const filtersOpen    = ref(false)

        const dtRef = ref(null)
        // Card-view accordion state (table view uses DataTable's own expand)
        const cardExpanded = reactive({})
        // Which category (simple comments vs a specific suggested edit) is
        // shown in the preview, per item — only relevant when an item folds
        // together more than one source (a rule with proposal discussions).
        const selectedCategoryKey = reactive({})

        const activeFilterCount = computed(() =>
            (includeReplies.value ? 1 : 0) +
            (!props.forceMineOnly && mineOnly.value ? 1 : 0) +
            (minComments.value ? 1 : 0) +
            (dateFrom.value ? 1 : 0) +
            (dateTo.value ? 1 : 0)
        )

        const fetchUrl = computed(() => {
            const params = new URLSearchParams({
                scope:        includeReplies.value ? 'all' : 'main',
                mine:         mineOnly.value ? '1' : '',
                min_comments: minComments.value || '',
                date_from:    dateFrom.value,
                date_to:      dateTo.value,
            })
            return `/api/comments/hub?${params}`
        })

        function refetch() {
            Object.keys(cardExpanded).forEach(k => delete cardExpanded[k])
            nextTick(() => dtRef.value && dtRef.value.fetchData())
        }

        watch(fetchUrl, refetch)

        let _mct = null
        watch(minCommentsInput, val => {
            clearTimeout(_mct)
            _mct = setTimeout(() => { minComments.value = val }, 350)
        })

        function resetFilters() {
            includeReplies.value = false
            mineOnly.value = props.forceMineOnly
            minCommentsInput.value = ''
            minComments.value = ''
            dateFrom.value = ''
            dateTo.value = ''
        }

        function typeMeta(g) {
            return TYPE_META[g.object_type] || { icon: 'fa-regular fa-comment', label: g.object_type }
        }

        function latestExcerpt(g) {
            return (g.preview && g.preview[0]) ? g.preview[0].excerpt : '—'
        }

        function isCardOpen(g) {
            return !!cardExpanded[g.id]
        }

        function toggleCard(g) {
            cardExpanded[g.id] = !cardExpanded[g.id]
        }

        // ── Sub-category selection (rule = simple comments + N proposal threads) ──
        function activeCategory(item) {
            const cats = item.categories || []
            if (!cats.length) return null
            const key = selectedCategoryKey[item.id]
            return cats.find(c => c.key === key) || cats[0]
        }

        function selectCategory(item, cat) {
            selectedCategoryKey[item.id] = cat.key
        }

        function categoryIcon(cat) {
            return CATEGORY_ICON[cat.kind] || 'fa-regular fa-comment'
        }

        // Deep link for "Open full thread": the active category's own link
        // when there's more than one (so picking a proposal sub-tab jumps to
        // THAT proposal's page), else the group's own resolved link — needed
        // for blog posts, whose category bucket has no slug-aware link.
        function ctaLink(item) {
            const cats = item.categories || []
            if (cats.length <= 1) return item.link
            const active = activeCategory(item)
            return (active && active.link) || item.link
        }

        function fmtDate(iso) {
            if (!iso) return '—'
            const d = new Date(iso)
            if (isNaN(d)) return iso
            return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
        }

        return {
            includeReplies, mineOnly, minCommentsInput, dateFrom, dateTo,
            filtersOpen, activeFilterCount, fetchUrl, dtRef,
            columns: COLUMNS, PREVIEW_PER_PAGE,
            typeMeta, latestExcerpt, isCardOpen, toggleCard, fmtDate,
            activeCategory, selectCategory, categoryIcon, ctaLink,
            resetFilters,
        }
    },
    template: `
<div class="rl-wrapper chub-wrapper">

    <!-- ── Grouped list (shared dataset for both card and table modes) ── -->
    <data-table
        ref="dtRef"
        :fetch-url="fetchUrl"
        mode="manage"
        :columns="columns"
        default-view="table"
        :initial-per-page="20"
        initial-sort="last_activity"
        initial-dir="desc">

        <!-- Filters button, inline with the table/card view toggle -->
        <template #toolbar-start>
            <button class="dt-toolbar-btn"
                    :class="{ 'dt-toolbar-btn--active': filtersOpen }"
                    @click="filtersOpen = !filtersOpen"
                    :aria-expanded="filtersOpen">
                <i class="fa-solid fa-filter"></i>
                <span>Filters</span>
                <span v-if="activeFilterCount > 0" class="rl-filter-badge ms-1">[[ activeFilterCount ]]</span>
            </button>
        </template>

        <!-- Filter panel, spanning below the whole toolbar row -->
        <template #below-toolbar>
            <div v-show="filtersOpen" class="rl-filter-panel">
                <div class="rl-fp-row">

                    <div class="form-check form-switch chub-scope-switch" title="Also count and search inside replies">
                        <input class="form-check-input" type="checkbox" id="chubIncludeReplies" role="switch"
                               v-model="includeReplies">
                        <label class="form-check-label" for="chubIncludeReplies">Include replies</label>
                    </div>

                    <div class="form-check form-switch chub-scope-switch" title="Only threads where you posted at least one comment">
                        <input class="form-check-input" type="checkbox" id="chubMineOnly" role="switch"
                               v-model="mineOnly">
                        <label class="form-check-label" for="chubMineOnly">Mine only</label>
                    </div>

                    <div class="rl-fp-item d-flex align-items-center gap-2">
                        <span class="rl-fp-multi-label mb-0">
                            <i class="fa-regular fa-comment text-primary"></i> Min comments
                        </span>
                        <input type="number" min="0" class="rl-fp-select chub-min-comments" v-model="minCommentsInput"
                               placeholder="e.g. 3" aria-label="Minimum comment count">
                    </div>

                    <div class="rl-fp-item d-flex align-items-center gap-2">
                        <span class="rl-fp-multi-label mb-0">
                            <i class="fa-regular fa-calendar text-primary"></i> From
                        </span>
                        <input type="date" class="rl-fp-select" v-model="dateFrom" aria-label="Comments from date">
                    </div>

                    <div class="rl-fp-item d-flex align-items-center gap-2">
                        <span class="rl-fp-multi-label mb-0">
                            <i class="fa-regular fa-calendar text-primary"></i> To
                        </span>
                        <input type="date" class="rl-fp-select" v-model="dateTo" aria-label="Comments to date">
                    </div>

                    <button v-if="activeFilterCount > 0" class="rl-fp-reset" @click="resetFilters">
                        <i class="fas fa-rotate-left"></i> Reset
                    </button>

                </div>
            </div>
        </template>

        <!-- Card header title (card view): linked + search-highlighted -->
        <template #card-title="{ item, highlight }">
            <a :href="item.link" class="chub-title dt-card-title text-truncate" :title="item.title"
               style="flex:1;min-width:0;display:block;"
               @click.stop v-html="highlight(item.title)">
            </a>
        </template>

        <!-- Title cell (table view) -->
        <template #cell-title="{ item, highlight }">
            <a :href="item.link" class="chub-title d-block text-truncate" :title="item.title"
               @click.stop v-html="highlight(item.title)">
            </a>
            <span v-if="item.is_private" class="badge chub-badge chub-badge--private"
                  title="Private bundle — only visible to you (owner) or admins">
                <i class="fa-solid fa-lock me-1"></i>Private
            </span>
        </template>

        <!-- Type cell -->
        <template #cell-object_type="{ item }">
            <a :href="item.link" class="d-inline-flex align-items-center gap-2 text-decoration-none"
               :title="'Open ' + typeMeta(item).label.toLowerCase()">
                <span class="chub-type-icon chub-type-icon--sm"
                      :class="'chub-type-icon--' + item.object_type">
                    <i :class="typeMeta(item).icon"></i>
                </span>
                <span class="badge chub-badge" :class="'chub-badge--' + item.object_type">
                    [[ typeMeta(item).label ]]
                </span>
            </a>
            <span v-if="item.categories && item.categories.length > 1" class="badge chub-badge chub-badge--proposal ms-1"
                  title="This rule also has suggested-edit discussions">
                <i class="fa-solid fa-code-pull-request me-1"></i>+[[ item.categories.length - 1 ]]
            </span>
        </template>

        <!-- Comment count cell -->
        <template #cell-comment_count="{ item }">
            <a :href="item.link" class="badge rounded-pill chub-count text-decoration-none" title="Open thread">
                <i class="fa-regular fa-comment me-1"></i>[[ item.comment_count ]]
            </a>
        </template>

        <!-- Participants cell: avatar-only stacked chips -->
        <template #cell-participants="{ item }">
            <span class="chub-participants" @click.stop>
                <span v-for="p in item.participants" :key="p.id" class="chub-participant">
                    <user-chip :user-id="p.id" :username="p.name" :avatar="p.avatar"
                               size="sm" :show-name="false"></user-chip>
                </span>
                <span v-if="item.participant_count > item.participants.length"
                      class="chub-participant chub-participant--more"
                      :title="(item.participant_count - item.participants.length) + ' more participant(s)'">
                    +[[ item.participant_count - item.participants.length ]]
                </span>
                <span v-if="item.participant_count === 0" style="color:var(--subtle-text-color);">—</span>
            </span>
        </template>

        <!-- Last activity cell -->
        <template #cell-last_activity="{ item }">
            <span class="text-nowrap" style="color:var(--subtle-text-color);font-size:.8rem;">
                [[ fmtDate(item.last_activity) ]]
            </span>
        </template>

        <!-- Latest comment excerpt cell -->
        <template #cell-latest="{ item, highlight }">
            <span :title="latestExcerpt(item)" style="color:var(--subtle-text-color);font-size:.82rem;"
                  v-html="highlight(latestExcerpt(item))">
            </span>
        </template>

        <!-- Expanded row (table view): category picker (if this rule also has
             suggested-edit discussions) + real CommentThread, capped preview -->
        <template #expand="{ item }">
            <div class="chub-preview-wrap p-3">

                <div v-if="item.categories && item.categories.length > 1" class="chub-category-picker mb-3">
                    <button v-for="cat in item.categories" :key="cat.key"
                            class="chub-category-chip"
                            :class="{ 'is-active': activeCategory(item).key === cat.key }"
                            @click="selectCategory(item, cat)">
                        <i :class="categoryIcon(cat)"></i>
                        [[ cat.label ]]
                        <span class="chub-category-chip__count">[[ cat.count ]]</span>
                    </button>
                </div>

                <comment-thread
                    :key="activeCategory(item).key"
                    :object-type="activeCategory(item).object_type"
                    :object-id="activeCategory(item).object_id"
                    :can-create="false"
                    :can-edit-own="true"
                    :can-delete-own="true"
                    :can-moderate="currentUserIsAdmin"
                    :current-user-id="currentUserId"
                    :csrf-token="csrfToken"
                    :per-page="PREVIEW_PER_PAGE"
                    :auto-load="false">
                </comment-thread>
                <div class="pt-2">
                    <a :href="ctaLink(item)" class="btn btn-sm btn-primary rounded-pill px-3">
                        <i class="fa-solid fa-comments me-1"></i>Open full thread
                        <span v-if="item.comment_count > PREVIEW_PER_PAGE">&nbsp;([[ item.comment_count ]])</span>
                    </a>
                </div>
            </div>
        </template>

        <!-- Card body (card view): badges + meta + accordion preview -->
        <template #card-body="{ item }">
            <div class="d-flex align-items-center gap-2 flex-wrap">
                <a :href="item.link" class="d-inline-flex align-items-center gap-2 text-decoration-none"
                   :title="'Open ' + typeMeta(item).label.toLowerCase()">
                    <span class="chub-type-icon chub-type-icon--sm"
                          :class="'chub-type-icon--' + item.object_type">
                        <i :class="typeMeta(item).icon"></i>
                    </span>
                    <span class="badge chub-badge" :class="'chub-badge--' + item.object_type">
                        [[ typeMeta(item).label ]]
                    </span>
                </a>
                <span v-if="item.categories && item.categories.length > 1" class="badge chub-badge chub-badge--proposal"
                      title="This rule also has suggested-edit discussions">
                    <i class="fa-solid fa-code-pull-request me-1"></i>+[[ item.categories.length - 1 ]]
                </span>
                <span v-if="item.is_private" class="badge chub-badge chub-badge--private">
                    <i class="fa-solid fa-lock me-1"></i>Private
                </span>
                <a :href="item.link" class="badge rounded-pill chub-count text-decoration-none ms-auto" title="Open thread">
                    <i class="fa-regular fa-comment me-1"></i>[[ item.comment_count ]]
                </a>
            </div>

            <div class="d-flex align-items-center gap-2 flex-wrap mt-2">
                <span class="chub-participants" @click.stop>
                    <span v-for="p in item.participants" :key="p.id" class="chub-participant">
                        <user-chip :user-id="p.id" :username="p.name" :avatar="p.avatar"
                                   size="sm" :show-name="false"></user-chip>
                    </span>
                    <span v-if="item.participant_count > item.participants.length"
                          class="chub-participant chub-participant--more">
                        +[[ item.participant_count - item.participants.length ]]
                    </span>
                </span>
                <span class="chub-meta ms-auto">
                    <i class="fa-regular fa-clock me-1 opacity-50"></i>[[ fmtDate(item.last_activity) ]]
                </span>
            </div>

            <div class="d-flex align-items-center gap-2 mt-2">
                <button class="chub-action-btn chub-action-btn--expand"
                        :class="{ 'is-expanded': isCardOpen(item) }"
                        @click="toggleCard(item)">
                    <i class="fas fa-chevron-down chub-expand-chevron me-1" style="font-size:.65rem;"></i>
                    [[ isCardOpen(item) ? 'Hide comments' : 'Preview comments' ]]
                </button>
                <a :href="ctaLink(item)" class="chub-action-btn" title="Open full thread">
                    <i class="fas fa-arrow-up-right-from-square me-1"></i>Open thread
                </a>
            </div>

            <div v-if="isCardOpen(item)" class="chub-card-preview mt-2 pt-2">
                <div v-if="item.categories && item.categories.length > 1" class="chub-category-picker mb-3">
                    <button v-for="cat in item.categories" :key="cat.key"
                            class="chub-category-chip"
                            :class="{ 'is-active': activeCategory(item).key === cat.key }"
                            @click="selectCategory(item, cat)">
                        <i :class="categoryIcon(cat)"></i>
                        [[ cat.label ]]
                        <span class="chub-category-chip__count">[[ cat.count ]]</span>
                    </button>
                </div>
                <comment-thread
                    :key="activeCategory(item).key"
                    :object-type="activeCategory(item).object_type"
                    :object-id="activeCategory(item).object_id"
                    :can-create="false"
                    :can-edit-own="true"
                    :can-delete-own="true"
                    :can-moderate="currentUserIsAdmin"
                    :current-user-id="currentUserId"
                    :csrf-token="csrfToken"
                    :per-page="PREVIEW_PER_PAGE"
                    :auto-load="false">
                </comment-thread>
            </div>
        </template>

    </data-table>

</div>
`,
}
