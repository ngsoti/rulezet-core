/**
 * bundleList.js — Reusable bundle list component (card + table views)
 *
 * Mirrors ruleList.js but adapted for bundles:
 *   - Bundle-specific filters: tags, vulnerabilities, access (public/private/mine)
 *   - Sort: newest, oldest, most voted, name A→Z, most viewed
 *   - Card/table expand: lazy-loaded inline rule list for each bundle
 *   - Vote via /bundle/evaluate
 *   - No format/license/search_field filters (not applicable to bundles)
 *
 * Modes:
 *   read    — view only, no selection
 *   select  — checkboxes + confirm button emitting send(ids)
 *   manage  — checkboxes + sticky bulk bar with configurable actions
 *
 * Props:
 *   mode                String   'read'|'select'|'manage'     default:'read'
 *   defaultView         String   'card'|'table'               default:'card'
 *   fetchUrl            String   default:'/bundle/data_table'
 *   userId              Number   filter by creator
 *   currentUserId       Number
 *   currentUserIsAdmin  Boolean
 *   showFilters         Boolean                               default:true
 *   showCreate          Boolean                               default:false
 *   canVote             Boolean                               default:false
 *   bulkActions         Array    [{key,label,icon?,variant?}] default:[]
 *   initialPerPage      Number                                default:12
 *   hiddenFilters       Array                                 default:[]
 *   initialFilters      Object                                default:{}
 *   csrfToken           String                                default:''
 *   currentUserIsAuthenticated Boolean                        default:false
 *   syncUrl             Boolean                               default:true
 *
 * Events:
 *   create
 *   delete(bundle)
 *   vote({ bundleId, type })
 *   bulk-action({ action, ids, count })
 *   send(ids)
 *
 * Expose:
 *   fetchData()
 */

import PaginationComponent      from '/static/js/rule/paginationComponent.js'
import MultiVulnerabilityFilter from '/static/js/vulnerability/multiVulnerabilityFilter.js'
import MultiTagFilter           from '/static/js/tags/multiTagFIlter.js'
import MultiPersonFilter        from '/static/js/rule/multiPersonFilter.js'
import MultiAttackFilter        from '/static/js/attack/multiAttackFilter.js'
import TagsDisplaysList         from '/static/js/tags/tagsDisplaysList.js'
import VulnerabilityDisplaysList from '/static/js/vulnerability/vulnerabilityDisplayList.js'
import AttackDisplayList        from '/static/js/attack/attackDisplayList.js'
import UserChip                 from '/static/js/components/UserChip.js'
import CodeViewer               from '/static/js/components/code-viewer.js'
import { create_message }       from '/static/js/toaster.js'
import ReportModal              from '/static/js/components/ReportModal.js'
import VoterPopover             from '/static/js/components/VoterPopover.js'

const { ref, reactive, computed, watch, onMounted, onUnmounted } = Vue

export default {
    name: 'BundleList',
    components: {
        PaginationComponent,
        MultiVulnerabilityFilter,
        MultiTagFilter,
        MultiPersonFilter,
        MultiAttackFilter,
        TagsDisplaysList,
        VulnerabilityDisplaysList,
        AttackDisplayList,
        UserChip,
        CodeViewer,
        ReportModal,
        VoterPopover,
    },

    props: {
        mode:               { type: String,           default: 'read' },
        defaultView:        { type: String,           default: 'card' },
        fetchUrl:           { type: String,           default: '/bundle/data_table' },
        userId:             { type: [Number, String], default: null },
        currentUserId:      { type: [Number, String], default: null },
        currentUserIsAdmin: { type: Boolean,          default: false },
        showFilters:        { type: Boolean,          default: true },
        showCreate:         { type: Boolean,          default: false },
        canVote:            { type: Boolean,          default: false },
        bulkActions:        { type: Array,            default: () => [] },
        initialPerPage:     { type: Number,           default: 12 },
        hiddenFilters:      { type: Array,            default: () => [] },
        initialFilters:     { type: Object,           default: () => ({}) },
        csrfToken:          { type: String,           default: '' },
        currentUserIsAuthenticated: { type: Boolean,  default: false },
        syncUrl:            { type: Boolean,          default: true },
    },

    emits: ['create', 'delete', 'vote', 'bulk-action', 'send'],

    expose: ['fetchData'],

    template: `
    <div class="bl-wrapper">

        <!-- ── Toolbar ── -->
        <div class="bl-toolbar">
            <div class="bl-toolbar-left">
                <div class="dt-search">
                    <i class="fas fa-search dt-search-icon"></i>
                    <input class="dt-search-input" type="text" placeholder="Search bundles…"
                           v-model="search" @input="onSearchInput" aria-label="Search bundles" />
                    <button v-if="search" class="dt-search-clear" @click="clearSearch">
                        <i class="fas fa-xmark"></i>
                    </button>
                </div>
                <span v-if="!loading" class="text-muted small ms-2 text-nowrap">
                    <strong>{{ total }}</strong> bundle<span v-if="total !== 1">s</span>
                </span>
            </div>

            <div class="bl-toolbar-right">
                <!-- Sort (card mode) -->
                <select v-if="viewMode === 'card'" v-model="cardSort" class="rl-sort-select"
                        @change="onCardSortChange">
                    <option value="newest">Newest</option>
                    <option value="oldest">Oldest</option>
                    <option value="most_voted">Most voted</option>
                    <option value="most_viewed">Most viewed</option>
                    <option value="name_asc">A → Z</option>
                </select>

                <!-- View toggle -->
                <div class="dt-view-toggle">
                    <button class="dt-view-btn" :class="{ 'dt-view-btn--active': viewMode === 'card' }"
                            @click="viewMode = 'card'">
                        <i class="fas fa-rectangle-list"></i>
                    </button>
                    <button class="dt-view-btn" :class="{ 'dt-view-btn--active': viewMode === 'table' }"
                            @click="viewMode = 'table'">
                        <i class="fas fa-table-cells-large"></i>
                    </button>
                </div>

                <!-- Column picker (table mode) -->
                <div v-if="viewMode === 'table'" class="dropdown">
                    <button class="dt-toolbar-btn dropdown-toggle" data-bs-toggle="dropdown">
                        <i class="fas fa-table-columns"></i>
                        <span>Columns</span>
                    </button>
                    <ul class="dropdown-menu dropdown-menu-end shadow border-0 py-2"
                        style="border-radius:12px;min-width:165px;" @click.stop>
                        <li v-for="col in TOGGLEABLE_COLS" :key="col.key">
                            <label class="dropdown-item rounded-2 d-flex align-items-center gap-2"
                                   style="cursor:pointer;font-size:.84rem;user-select:none;">
                                <input type="checkbox" :checked="colVisible[col.key]"
                                       @change="toggleColumn(col.key)" />
                                {{ col.label }}
                            </label>
                        </li>
                    </ul>
                </div>

                <!-- Expand / collapse all -->
                <button class="dt-toolbar-btn"
                        :class="{ 'dt-toolbar-btn--active': allExpanded }"
                        :title="allExpanded ? 'Collapse all' : 'Expand all'"
                        @click="allExpanded ? collapseAll() : expandAll()">
                    <i :class="allExpanded ? 'fas fa-compress-alt' : 'fas fa-expand-alt'"></i>
                    <span>{{ allExpanded ? 'Collapse' : 'Expand' }}</span>
                </button>

                <!-- Filters toggle -->
                <button v-if="showFilters" class="dt-toolbar-btn"
                        :class="{ 'dt-toolbar-btn--active': filtersOpen }"
                        @click="filtersOpen = !filtersOpen">
                    <i class="fas fa-sliders"></i>
                    <span>Filters</span>
                    <span v-if="activeFilterCount > 0" class="rl-filter-badge ms-1">{{ activeFilterCount }}</span>
                </button>

                <!-- New Bundle -->
                <button v-if="showCreate" class="dt-toolbar-btn dt-toolbar-btn--primary"
                        @click="$emit('create')">
                    <i class="fas fa-folder-plus"></i>
                    <span>New Bundle</span>
                </button>

                <!-- Select confirm (mode=select) -->
                <button v-if="mode === 'select'" class="dt-toolbar-btn dt-toolbar-btn--primary"
                        :disabled="selectionCount === 0" @click="emitSend">
                    <i class="fas fa-check"></i>
                    <span>Confirm{{ selectionCount > 0 ? ' (' + selectionCount + ')' : '' }}</span>
                </button>

                <!-- Per-page (table mode) -->
                <div v-if="viewMode === 'table'" class="rl-per-page">
                    <span>Rows</span>
                    <select v-model="perPageModel">
                        <option v-for="n in [10, 25, 50, 100]" :key="n" :value="n">{{ n }}</option>
                    </select>
                </div>
            </div>
        </div>

        <!-- ── Filter panel ── -->
        <template v-if="showFilters">
            <div v-show="filtersOpen" class="rl-filter-panel">

                <div class="rl-fp-row">
                    <!-- Access toggle -->
                    <div v-if="!isFilterHidden('access')" class="bl-access-toggle">
                        <button :class="['bl-acc-btn', accessFilter === '' ? 'bl-acc-btn--active' : '']"
                                @click="accessFilter = ''; onFilterChange()">
                            <i class="fas fa-globe"></i> All
                        </button>
                        <button :class="['bl-acc-btn', accessFilter === 'public' ? 'bl-acc-btn--active' : '']"
                                @click="accessFilter = 'public'; onFilterChange()">
                            <i class="fas fa-lock-open"></i> Public
                        </button>
                        <button v-if="currentUserIsAdmin"
                                :class="['bl-acc-btn', accessFilter === 'private' ? 'bl-acc-btn--active' : '']"
                                @click="accessFilter = 'private'; onFilterChange()">
                            <i class="fas fa-lock"></i> Private
                        </button>
                    </div>

                    <!-- Mine only toggle -->
                    <div v-if="currentUserIsAuthenticated && !numericUserId"
                         class="rl-scope-toggle">
                        <button :class="['rl-scope-btn', !scopeMine ? 'rl-scope-btn--active' : '']"
                                @click="scopeMine = false; onFilterChange()">
                            <i class="fa-solid fa-globe"></i> All
                        </button>
                        <button :class="['rl-scope-btn', scopeMine ? 'rl-scope-btn--active' : '']"
                                @click="scopeMine = true; onFilterChange()">
                            <i class="fa-solid fa-user"></i> Mine
                        </button>
                    </div>

                    <button v-if="activeFilterCount > 0" class="rl-fp-reset" @click="resetFilters">
                        <i class="fas fa-rotate-left"></i> Reset
                    </button>
                </div>

                <div class="rl-fp-row rl-fp-row--multi">
                    <div v-if="!isFilterHidden('tags')" class="rl-fp-multi-item">
                        <span class="rl-fp-multi-label">
                            <i class="fa-solid fa-tags text-primary"></i> Tags
                        </span>
                        <multi-tag-filter v-model="selectedTags"
                            api-endpoint="/bundle/get_all_tags_usage"
                            placeholder="Filter tags…"
                            target-type="bundle"
                            @change="onFilterChange">
                        </multi-tag-filter>
                    </div>

                    <div v-if="!isFilterHidden('vulnerabilities')" class="rl-fp-multi-item">
                        <span class="rl-fp-multi-label">
                            <i class="fa-solid fa-shield-virus text-danger"></i> Vulnerabilities
                        </span>
                        <multi-vulnerability-filter v-model="selectedVulns"
                            api-endpoint="/bundle/get_all_vulnerabilities_usage"
                            placeholder="CVE, GHSA…"
                            @change="onFilterChange">
                        </multi-vulnerability-filter>
                    </div>

                    <div v-if="!isFilterHidden('attacks')" class="rl-fp-multi-item">
                        <span class="rl-fp-multi-label">
                            <i class="fa-solid fa-crosshairs text-warning"></i> ATT&amp;CK
                        </span>
                        <multi-attack-filter v-model="selectedAttacks"
                            api-endpoint="/bundle/attacks_usage"
                            placeholder="Filter by technique…"
                            @change="onFilterChange">
                        </multi-attack-filter>
                    </div>

                    <div v-if="!isFilterHidden('person') && !numericUserId" class="rl-fp-multi-item">
                        <span class="rl-fp-multi-label">
                            <i class="fa-solid fa-person-circle-check text-warning"></i> Creator
                        </span>
                        <multi-person-filter v-model="personFilter"
                            author-endpoint="/bundle/get_bundle_creators_usage"
                            editor-endpoint="/bundle/get_bundle_creators_usage"
                            @change="onPersonFilterChange">
                        </multi-person-filter>
                    </div>
                </div>
            </div>
        </template>

        <!-- ── Select-all-pages banner ── -->
        <div v-if="showSelectBanner" class="rl-select-banner">
            <span v-if="!allPagesSelected">All {{ items.length }} bundles on this page are selected.</span>
            <span v-else>All {{ total }} bundles are selected.</span>
            <button v-if="!allPagesSelected" class="rl-select-banner-btn" @click="selectAllPages">
                Select all {{ total }} bundles
            </button>
            <button class="rl-select-banner-btn" @click="clearSelection">Clear selection</button>
        </div>

        <!-- ── Selected panel ── -->
        <div v-if="!allPagesSelected && selectedBundlesList.length" class="rl-picked-panel">
            <div class="rl-picked-header">
                <span class="rl-picked-title">
                    <i class="fas fa-check-square me-1"></i>
                    {{ selectedBundlesList.length }} bundle{{ selectedBundlesList.length !== 1 ? 's' : '' }} selected
                </span>
                <button class="rl-picked-clear" @click="clearSelection">
                    <i class="fas fa-xmark me-1"></i>Clear all
                </button>
            </div>
            <div class="rl-picked-chips">
                <span v-for="b in showAllPicked ? selectedBundlesList : selectedBundlesList.slice(0, 8)"
                      :key="b.id" class="rl-picked-chip">
                    <span class="rl-picked-chip-fmt">
                        <i class="fas fa-layer-group" style="font-size:.6rem;"></i>
                    </span>
                    <span class="rl-picked-chip-title">{{ b.name }}</span>
                    <button class="rl-picked-chip-rm" @click="removeFromSelection(b.id)">
                        <i class="fas fa-xmark"></i>
                    </button>
                </span>
                <button v-if="selectedBundlesList.length > 8 && !showAllPicked"
                        class="rl-picked-more" @click="showAllPicked = true">
                    +{{ selectedBundlesList.length - 8 }} more
                </button>
                <button v-if="showAllPicked && selectedBundlesList.length > 8"
                        class="rl-picked-more" @click="showAllPicked = false">
                    Show less
                </button>
            </div>
        </div>

        <!-- ── Loading ── -->
        <div v-if="loading" class="rl-loading">
            <div class="spinner-border text-primary" role="status"></div>
        </div>

        <!-- ── Empty ── -->
        <div v-else-if="items.length === 0" class="rl-empty">
            <div class="rl-empty-icon"><i class="fas fa-layer-group"></i></div>
            <p class="mb-0">No bundles found matching your search.</p>
        </div>

        <!-- ═══════════════════════════════════════
             CARD VIEW
             ═══════════════════════════════════════ -->
        <div v-else-if="viewMode === 'card'" class="bl-cards">

            <div v-for="bundle in items" :key="bundle.id"
                 class="card h-100 shadow-sm border-0 mb-4 bl-bundle-card"
                 :class="{ 'bl-bundle-card--selected': isSelected(bundle) }">

                <div class="premium-accent-line"></div>
                <div class="card-watermark-list" v-show="!expandedIds.has(bundle.id)">
                    <i class="fa-solid fa-layer-group"></i>
                </div>

                <!-- Top-right badges -->
                <div class="position-absolute top-0 end-0 mt-3 me-3 d-flex gap-2" style="z-index:2;">
                    <span v-if="bundle.is_verified"
                          class="badge bg-primary shadow-sm pt-1" title="Verified bundle">
                        <i class="fas fa-circle-check me-1"></i>Verified
                    </span>
                    <span class="badge shadow-sm pt-1"
                          :class="bundle.access ? 'bg-success' : 'bg-secondary'"
                          :title="bundle.access ? 'Public bundle' : 'Private bundle'">
                        <i :class="bundle.access ? 'fas fa-lock-open me-1' : 'fas fa-lock me-1'"></i>
                        {{ bundle.access ? 'Public' : 'Private' }}
                    </span>
                </div>

                <div class="card-body d-flex flex-column p-4" style="z-index:1;">

                    <!-- Selection row -->
                    <div v-if="isSelectable"
                         class="rl-card-check-row mb-3"
                         :class="{ 'rl-card-check-row--on': isSelected(bundle) }"
                         @click.stop="toggleItem(bundle)">
                        <input type="checkbox" class="rl-card-check-input"
                               :checked="isSelected(bundle)"
                               @change.stop @click.stop />
                        <span class="rl-card-check-text">
                            {{ isSelected(bundle) ? 'Selected' : 'Select this bundle' }}
                        </span>
                        <i v-if="isSelected(bundle)" class="fas fa-check ms-auto text-primary" style="font-size:.78rem;"></i>
                    </div>

                    <!-- Title + author + date -->
                    <div class="mb-3 pe-5">
                        <h5 class="fw-bold mb-1">
                            <a :href="'/bundle/detail/' + bundle.id"
                               class="fw-bold h5 border-start border-primary border-4 ps-3 custom-rule-link text-decoration-none d-block"
                               v-html="highlight(bundle.name)">
                            </a>
                        </h5>
                        <div class="d-flex align-items-center gap-2 mt-2">
                            <user-chip :user-id="bundle.user_id" :username="bundle.user_name"
                                       :avatar="bundle.author_avatar" size="xs"></user-chip>
                            <span class="text-muted opacity-50">|</span>
                            <small class="text-muted">{{ fromNow(bundle.created_at) }}</small>
                        </div>
                    </div>

                    <!-- Description -->
                    <p class="rl-card-desc mb-3"
                       style="-webkit-line-clamp:3;-webkit-box-orient:vertical;display:-webkit-box;overflow:hidden;">
                        <span v-html="highlight(bundle.description || 'No description.')"></span>
                    </p>

                    <!-- Format badges + rule count -->
                    <div class="d-flex flex-wrap gap-1 mb-2" @click.stop>
                        <span class="badge rounded-pill bg-dark pt-1 shadow-sm"
                              v-for="fmt in (bundle.list_of_format_of_rules || [])" :key="fmt">
                            {{ fmt.toUpperCase() }}
                        </span>
                        <span class="badge rounded-pill bg-primary pt-1 shadow-sm">
                            <i class="fas fa-file-code me-1"></i>{{ bundle.number_of_rules }} rule{{ bundle.number_of_rules !== 1 ? 's' : '' }}
                        </span>
                    </div>

                    <!-- CVEs -->
                    <div class="mb-2" @click.stop>
                        <vulnerability-displays-list object-type="bundle" :object-id="bundle.id"
                            :max-visible="3"
                            :initial-vulnerabilities="bundle.vulnerability_identifiers || []">
                        </vulnerability-displays-list>
                    </div>

                    <!-- Tags -->
                    <div class="mb-2" @click.stop>
                        <tags-displays-list object-type="bundle" :object-id="bundle.id"
                            :max-visible="3"
                            :initial-tags="bundle.tags || []">
                        </tags-displays-list>
                    </div>

                    <!-- ATT&CK -->
                    <div v-if="bundle.attacks && bundle.attacks.length" class="mb-3" @click.stop>
                        <attack-display-list :initial-attacks="bundle.attacks" :max-visible="3">
                        </attack-display-list>
                    </div>

                    <!-- Meta strip -->
                    <div class="rl-card-meta">
                        <span class="rl-meta-item">
                            <i class="fas fa-eye"></i>
                            <span>{{ bundle.view_count }} views</span>
                        </span>
                        <span class="rl-meta-item">
                            <i class="fas fa-download"></i>
                            <span>{{ bundle.download_count }} downloads</span>
                        </span>
                        <span class="rl-meta-item rl-meta-item--uuid" :title="bundle.uuid">
                            <i class="fas fa-fingerprint"></i>
                            <span>{{ bundle.uuid }}</span>
                        </span>
                    </div>

                    <!-- Footer: votes + actions -->
                    <div class="d-flex justify-content-between align-items-center pt-3 border-top mt-auto">

                        <!-- Votes -->
                        <div class="btn-group shadow-sm border rounded-pill overflow-hidden">
                            <voter-popover :fetch-url="'/bundle/voters?bundleId=' + bundle.id + '&voteType=up'" label="Liked by">
                                <button @click="handleVote('up', bundle)"
                                        class="btn btn-sm px-3 border-0 border-end border-light shadow-none btn-animate home-btn"
                                        :class="{ 'rl-vote-disabled': !canVote, 'rl-vote-btn--active-up': bundle.user_vote === 'up' }"
                                        :title="canVote ? 'Upvote' : 'Login to vote'">
                                    <i class="fas fa-thumbs-up me-1"></i>{{ bundle.vote_up }}
                                </button>
                            </voter-popover>
                            <voter-popover :fetch-url="'/bundle/voters?bundleId=' + bundle.id + '&voteType=down'" label="Disliked by">
                                <button @click="handleVote('down', bundle)"
                                        class="btn btn-sm px-3 border-0 shadow-none btn-animate home-btn"
                                        :class="{ 'rl-vote-disabled': !canVote, 'rl-vote-btn--active-down': bundle.user_vote === 'down' }"
                                        :title="canVote ? 'Downvote' : 'Login to vote'">
                                    <i class="fas fa-thumbs-down me-1"></i>{{ bundle.vote_down }}
                                </button>
                            </voter-popover>
                        </div>

                        <div class="d-flex gap-2 align-items-center">

                            <!-- Expand rules -->
                            <button class="btn btn-sm rounded-circle shadow-sm p-0 d-flex align-items-center justify-content-center home-btn"
                                    style="width:32px;height:32px;border:1px solid #eee;"
                                    :title="expandedIds.has(bundle.id) ? 'Hide rules' : 'Show rules'"
                                    @click="toggleExpand(bundle)">
                                <i :class="expandedIds.has(bundle.id) ? 'fas fa-eye-slash' : 'fas fa-list'"
                                   style="font-size:.72rem;"></i>
                            </button>

                            <!-- More dropdown -->
                            <div class="dropup">
                                <button class="btn btn-sm rounded-circle shadow-sm p-0 d-flex align-items-center justify-content-center home-btn"
                                        style="width:32px;height:32px;border:1px solid #eee;"
                                        data-bs-toggle="dropdown">
                                    <i class="fas fa-ellipsis-v text-muted" style="font-size:.75rem;"></i>
                                </button>
                                <ul class="dropdown-menu dropdown-menu-end shadow border-0 mb-2"
                                    style="border-radius:12px;">
                                    <li>
                                        <a class="dropdown-item rounded-2" :href="'/bundle/detail/' + bundle.id">
                                            <i class="fas fa-eye me-2 text-muted"></i>View Detail
                                        </a>
                                    </li>
                                    <template v-if="numericCurrentUserId && (isOwner(bundle) || currentUserIsAdmin)">
                                        <li><hr class="dropdown-divider"></li>
                                        <li>
                                            <a class="dropdown-item rounded-2" :href="'/bundle/edit/' + bundle.id">
                                                <i class="fas fa-pen me-2 text-primary"></i>Edit Bundle
                                            </a>
                                        </li>
                                        <li>
                                            <button class="dropdown-item rounded-2 text-danger"
                                                    @click="$emit('delete', bundle)">
                                                <i class="fa-solid fa-trash me-2"></i>Delete Bundle
                                            </button>
                                        </li>
                                    </template>
                                    <template v-if="currentUserIsAuthenticated">
                                        <li><hr class="dropdown-divider"></li>
                                        <li>
                                            <report-modal
                                                object-type="bundle"
                                                :object-id="bundle.id"
                                                :object-label="bundle.name"
                                                :csrf-token="csrfToken">
                                                <template #trigger="{ open }">
                                                    <button class="dropdown-item rounded-2 text-danger" @click.stop="open">
                                                        <i class="fas fa-flag me-2"></i>Report
                                                    </button>
                                                </template>
                                            </report-modal>
                                        </li>
                                    </template>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- ── Expand: inline rule list ── -->
                <div v-if="expandedIds.has(bundle.id)" class="bl-rules-expand border-top">
                    <div class="bl-rules-expand-header">
                        <i class="fas fa-file-code text-primary me-2"></i>
                        <strong>Rules in this bundle</strong>
                        <span v-if="bundleRulesData.get(bundle.id)" class="text-muted small ms-2">
                            ({{ bundleRulesData.get(bundle.id).total }} total)
                        </span>
                    </div>

                    <div v-if="!bundleRulesData.get(bundle.id) || bundleRulesData.get(bundle.id).loading"
                         class="py-3 text-center">
                        <div class="spinner-border spinner-border-sm text-primary"></div>
                    </div>

                    <template v-else-if="bundleRulesData.get(bundle.id).items.length">
                        <div class="bl-rules-list">
                            <template v-for="rule in bundleRulesData.get(bundle.id).items" :key="rule.id">
                                <div class="bl-rule-row">
                                    <div class="bl-rule-row-main">
                                        <span v-if="rule.format" class="badge rounded-pill bg-dark bl-rule-fmt">
                                            {{ rule.format.toUpperCase() }}
                                        </span>
                                        <a :href="'/rule/detail_rule/' + rule.id"
                                           class="bl-rule-title" target="_blank" rel="noopener">
                                            {{ rule.title }}
                                        </a>
                                        <div class="bl-rule-meta-inline" @click.stop>
                                            <user-chip :user-id="rule.user_id" :username="rule.editor"
                                                       :avatar="rule.editor_avatar" size="xs"></user-chip>
                                        </div>
                                        <div class="bl-rule-tags-inline" @click.stop>
                                            <tags-displays-list object-type="rule" :object-id="rule.id"
                                                :max-visible="2" :initial-tags="rule.tags || []">
                                            </tags-displays-list>
                                        </div>
                                        <button class="bl-rule-expand-btn"
                                                @click.stop="toggleRuleExpand(bundle.id, rule.id)"
                                                :title="isRuleExpanded(bundle.id, rule.id) ? 'Hide content' : 'Show content'">
                                            <i :class="isRuleExpanded(bundle.id, rule.id) ? 'fas fa-chevron-up' : 'fas fa-chevron-down'"
                                               style="font-size:.65rem;"></i>
                                        </button>
                                    </div>
                                    <div v-if="isRuleExpanded(bundle.id, rule.id)" class="bl-rule-code">
                                        <code-viewer v-if="rule.to_string"
                                            :code="rule.to_string"
                                            :language="ruleLanguage(rule.format)"
                                            :title="rule.title"
                                            max-height="240px">
                                        </code-viewer>
                                        <p v-else class="text-muted small py-2 mb-0 px-3 fst-italic">
                                            No content available.
                                        </p>
                                    </div>
                                </div>
                            </template>
                        </div>

                        <!-- Mini pagination -->
                        <div v-if="bundleRulesData.get(bundle.id).totalPages > 1"
                             class="bl-rules-pagination">
                            <button class="bl-rules-page-btn"
                                    :disabled="bundleRulesData.get(bundle.id).page <= 1"
                                    @click="fetchBundleRules(bundle.id, bundleRulesData.get(bundle.id).page - 1)">
                                <i class="fas fa-chevron-left"></i>
                            </button>
                            <span class="bl-rules-page-info">
                                {{ bundleRulesData.get(bundle.id).page }}
                                / {{ bundleRulesData.get(bundle.id).totalPages }}
                            </span>
                            <button class="bl-rules-page-btn"
                                    :disabled="bundleRulesData.get(bundle.id).page >= bundleRulesData.get(bundle.id).totalPages"
                                    @click="fetchBundleRules(bundle.id, bundleRulesData.get(bundle.id).page + 1)">
                                <i class="fas fa-chevron-right"></i>
                            </button>
                        </div>
                    </template>

                    <div v-else class="py-3 text-center text-muted small fst-italic">
                        <i class="fas fa-folder-open opacity-25 me-2"></i>No rules in this bundle.
                    </div>
                </div>
            </div>
        </div>

        <!-- ═══════════════════════════════════════
             TABLE VIEW
             ═══════════════════════════════════════ -->
        <div v-else class="dt-table-wrap bl-table-wrap">
            <table class="dt-table" role="grid">
                <thead class="dt-thead">
                    <tr>
                        <th v-if="isSelectable" class="dt-th dt-th--checkbox">
                            <input type="checkbox" class="dt-checkbox"
                                   :checked="allOnPageSelected"
                                   :indeterminate="someOnPageSelected"
                                   @change="togglePageSelection" />
                        </th>
                        <th class="dt-th dt-th--sortable" style="min-width:180px;"
                            :class="{ 'dt-th--sorted': sortKey === 'name' }"
                            @click="setSort('name')">
                            <div class="dt-th-inner">
                                Name <i class="fas dt-sort-icon" :class="sortIcon('name')"></i>
                            </div>
                        </th>
                        <th v-show="colVisible.description" class="dt-th">Description</th>
                        <th v-show="colVisible.author" class="dt-th" style="width:140px;">Author</th>
                        <th v-show="colVisible.rules" class="dt-th" style="width:120px;">Rules</th>
                        <th v-show="colVisible.tags" class="dt-th" style="width:160px;">Tags</th>
                        <th v-show="colVisible.cves" class="dt-th" style="width:130px;">CVEs</th>
                        <th v-show="colVisible.attacks" class="dt-th" style="width:180px;">ATT&amp;CK</th>
                        <th v-show="colVisible.created"
                            class="dt-th dt-th--sortable" style="width:110px;"
                            :class="{ 'dt-th--sorted': sortKey === 'created_at' }"
                            @click="setSort('created_at')">
                            <div class="dt-th-inner">
                                Created <i class="fas dt-sort-icon" :class="sortIcon('created_at')"></i>
                            </div>
                        </th>
                        <th v-show="colVisible.votes"
                            class="dt-th dt-th--sortable" style="width:120px;"
                            :class="{ 'dt-th--sorted': sortKey === 'vote_up' }"
                            @click="setSort('vote_up')">
                            <div class="dt-th-inner">
                                Votes <i class="fas dt-sort-icon" :class="sortIcon('vote_up')"></i>
                            </div>
                        </th>
                        <th class="dt-th dt-th--actions" style="width:100px;">Actions</th>
                    </tr>
                </thead>

                <tbody>
                    <template v-for="bundle in items" :key="bundle.id">
                        <tr class="dt-row"
                            :class="{
                                'dt-row--selected': isSelected(bundle),
                                'dt-row--expanded': expandedIds.has(bundle.id),
                            }">

                            <td v-if="isSelectable" class="dt-td dt-td--checkbox">
                                <input type="checkbox" class="dt-checkbox"
                                       :checked="isSelected(bundle)"
                                       @change="toggleItem(bundle)" />
                            </td>

                            <td class="dt-td" style="max-width:200px;word-break:break-word;">
                                <div class="d-flex align-items-center gap-1 mb-1 flex-wrap">
                                    <span v-if="bundle.is_verified"
                                          class="badge bg-primary pt-1" style="font-size:.62rem;">
                                        <i class="fas fa-circle-check"></i>
                                    </span>
                                    <span class="badge pt-1"
                                          :class="bundle.access ? 'bg-success' : 'bg-secondary'"
                                          style="font-size:.62rem;">
                                        <i :class="bundle.access ? 'fas fa-lock-open' : 'fas fa-lock'"></i>
                                    </span>
                                </div>
                                <a :href="'/bundle/detail/' + bundle.id" class="dt-rule-title"
                                   v-html="highlight(bundle.name)"></a>
                            </td>

                            <td v-show="colVisible.description" class="dt-td dt-td--truncate">
                                <span class="text-muted"
                                      v-html="highlight(bundle.description || '—')"></span>
                            </td>

                            <td v-show="colVisible.author" class="dt-td" @click.stop>
                                <user-chip :user-id="bundle.user_id" :username="bundle.user_name"
                                           :avatar="bundle.author_avatar" size="xs"></user-chip>
                            </td>

                            <td v-show="colVisible.rules" class="dt-td">
                                <div class="d-flex flex-wrap gap-1">
                                    <span class="badge rounded-pill bg-primary pt-1"
                                          style="font-size:.65rem;">
                                        {{ bundle.number_of_rules }}
                                        <i class="fas fa-file-code ms-1"></i>
                                    </span>
                                    <span v-for="fmt in (bundle.list_of_format_of_rules || [])" :key="fmt"
                                          class="badge rounded-pill bg-dark pt-1" style="font-size:.62rem;">
                                        {{ fmt.toUpperCase() }}
                                    </span>
                                </div>
                            </td>

                            <td v-show="colVisible.tags" class="dt-td" @click.stop>
                                <tags-displays-list v-if="bundle.tags && bundle.tags.length"
                                    object-type="bundle" :object-id="bundle.id" :max-visible="2"
                                    :initial-tags="bundle.tags">
                                </tags-displays-list>
                                <span v-else class="text-muted small">—</span>
                            </td>

                            <td v-show="colVisible.cves" class="dt-td" @click.stop>
                                <vulnerability-displays-list v-if="bundle.vulnerability_identifiers && bundle.vulnerability_identifiers.length"
                                    object-type="bundle" :object-id="bundle.id" :max-visible="2"
                                    :initial-vulnerabilities="bundle.vulnerability_identifiers">
                                </vulnerability-displays-list>
                                <span v-else class="text-muted small">—</span>
                            </td>
                            <td v-show="colVisible.attacks" class="dt-td" @click.stop>
                                <attack-display-list v-if="bundle.attacks && bundle.attacks.length"
                                    :initial-attacks="bundle.attacks" :max-visible="2">
                                </attack-display-list>
                                <span v-else class="text-muted small">—</span>
                            </td>

                            <td v-show="colVisible.created" class="dt-td"
                                style="white-space:nowrap;font-size:.78rem;">
                                {{ formatDate(bundle.created_at) }}
                            </td>

                            <td v-show="colVisible.votes" class="dt-td">
                                <div class="rl-vote-row">
                                    <voter-popover :fetch-url="'/bundle/voters?bundleId=' + bundle.id + '&voteType=up'" label="Liked by">
                                        <button class="rl-vote-btn rl-vote-btn--up"
                                                :class="{ 'rl-vote-disabled': !canVote, 'rl-vote-btn--active-up': bundle.user_vote === 'up' }"
                                                @click.stop="handleVote('up', bundle)">
                                            <i class="fas fa-thumbs-up"></i>
                                            <span>{{ bundle.vote_up }}</span>
                                        </button>
                                    </voter-popover>
                                    <voter-popover :fetch-url="'/bundle/voters?bundleId=' + bundle.id + '&voteType=down'" label="Disliked by">
                                        <button class="rl-vote-btn rl-vote-btn--down"
                                                :class="{ 'rl-vote-disabled': !canVote, 'rl-vote-btn--active-down': bundle.user_vote === 'down' }"
                                                @click.stop="handleVote('down', bundle)">
                                            <i class="fas fa-thumbs-down"></i>
                                            <span>{{ bundle.vote_down }}</span>
                                        </button>
                                    </voter-popover>
                                </div>
                            </td>

                            <td class="dt-td dt-td--actions">
                                <div class="dt-actions">
                                    <div class="rl-action-dropdown" @click.stop>
                                        <button class="dt-action-btn rl-action-dropdown-toggle" title="More actions">
                                            <i class="fas fa-ellipsis-v" style="font-size:.7rem;"></i>
                                        </button>
                                        <div class="rl-action-menu">
                                            <a :href="'/bundle/detail/' + bundle.id" class="rl-action-item">
                                                <i class="fas fa-eye"></i> View
                                            </a>
                                            <template v-if="numericCurrentUserId && (isOwner(bundle) || currentUserIsAdmin)">
                                                <div class="rl-action-divider"></div>
                                                <a :href="'/bundle/edit/' + bundle.id" class="rl-action-item">
                                                    <i class="fas fa-pencil"></i> Edit
                                                </a>
                                                <button class="rl-action-item rl-action-item--danger"
                                                        @click="$emit('delete', bundle)">
                                                    <i class="fas fa-trash"></i> Delete
                                                </button>
                                            </template>
                                            <template v-if="currentUserIsAuthenticated">
                                                <div class="rl-action-divider"></div>
                                                <report-modal
                                                    object-type="bundle"
                                                    :object-id="bundle.id"
                                                    :object-label="bundle.name"
                                                    :csrf-token="csrfToken">
                                                    <template #trigger="{ open }">
                                                        <button class="rl-action-item rl-action-item--danger" @click.stop="open">
                                                            <i class="fas fa-flag"></i> Report
                                                        </button>
                                                    </template>
                                                </report-modal>
                                            </template>
                                        </div>
                                    </div>

                                    <button class="dt-action-btn dt-action-btn--expand"
                                            :class="{ 'is-expanded': expandedIds.has(bundle.id) }"
                                            title="Expand rules" @click="toggleExpand(bundle)">
                                        <i class="fas fa-chevron-down dt-expand-chevron"
                                           style="font-size:.65rem;"></i>
                                    </button>
                                </div>
                            </td>
                        </tr>

                        <!-- Expanded row: inline rule list -->
                        <tr v-if="expandedIds.has(bundle.id)"
                            :key="'expand-' + bundle.id" class="dt-row-expand">
                            <td :colspan="tableColspan" class="dt-expand-cell p-0">
                                <div class="bl-expand-wrap">

                                    <!-- Meta info -->
                                    <div class="rl-expand-meta">
                                        <div class="rl-expand-kv">
                                            <span class="rl-expand-k">Author</span>
                                            <span class="rl-expand-v">{{ bundle.user_name || '—' }}</span>
                                        </div>
                                        <div class="rl-expand-kv">
                                            <span class="rl-expand-k">Created</span>
                                            <span class="rl-expand-v">{{ formatDate(bundle.created_at) }}</span>
                                        </div>
                                        <div class="rl-expand-kv">
                                            <span class="rl-expand-k">Updated</span>
                                            <span class="rl-expand-v">{{ fromNow(bundle.updated_at) }}</span>
                                        </div>
                                        <div class="rl-expand-kv">
                                            <span class="rl-expand-k">Rules</span>
                                            <span class="rl-expand-v">{{ bundle.number_of_rules }}</span>
                                        </div>
                                        <div class="rl-expand-kv">
                                            <span class="rl-expand-k">Views</span>
                                            <span class="rl-expand-v">{{ bundle.view_count }}</span>
                                        </div>
                                        <div class="rl-expand-kv">
                                            <span class="rl-expand-k">Downloads</span>
                                            <span class="rl-expand-v">{{ bundle.download_count }}</span>
                                        </div>
                                        <div class="rl-expand-kv rl-expand-kv--source">
                                            <span class="rl-expand-k">UUID</span>
                                            <span class="rl-expand-v" style="font-family:monospace;font-size:.75rem;">
                                                {{ bundle.uuid }}
                                            </span>
                                        </div>
                                    </div>

                                    <!-- Description -->
                                    <div v-if="bundle.description" class="rl-expand-desc">
                                        <span class="rl-expand-k">
                                            <i class="fas fa-quote-left me-1 opacity-50"></i>Description
                                        </span>
                                        <p class="mb-0 text-muted" style="font-size:.83rem;line-height:1.5;">
                                            {{ bundle.description }}
                                        </p>
                                    </div>

                                    <!-- Tags + CVEs + Rules list -->
                                    <div class="rl-expand-bottom">
                                        <div class="rl-expand-taxonomy" @click.stop>
                                            <div v-if="bundle.tags && bundle.tags.length" class="rl-expand-taxonomy-section">
                                                <span class="rl-expand-k mb-1">
                                                    <i class="fas fa-tags text-primary me-1"></i>Tags
                                                </span>
                                                <tags-displays-list object-type="bundle" :object-id="bundle.id"
                                                    :max-visible="15" :initial-tags="bundle.tags">
                                                </tags-displays-list>
                                            </div>
                                            <div v-if="bundle.vulnerability_identifiers && bundle.vulnerability_identifiers.length"
                                                 class="rl-expand-taxonomy-section mt-2">
                                                <span class="rl-expand-k mb-1">
                                                    <i class="fas fa-shield-virus text-danger me-1"></i>CVEs
                                                </span>
                                                <vulnerability-displays-list object-type="bundle"
                                                    :object-id="bundle.id" :max-visible="8"
                                                    :initial-vulnerabilities="bundle.vulnerability_identifiers">
                                                </vulnerability-displays-list>
                                            </div>
                                            <div v-if="bundle.attacks && bundle.attacks.length"
                                                 class="rl-expand-taxonomy-section mt-2">
                                                <span class="rl-expand-k mb-1">
                                                    <i class="fas fa-crosshairs text-warning me-1"></i>ATT&amp;CK
                                                </span>
                                                <attack-display-list :initial-attacks="bundle.attacks" :max-visible="10">
                                                </attack-display-list>
                                            </div>
                                        </div>

                                        <!-- Inline rule list -->
                                        <div class="rl-expand-code bl-expand-rules">
                                            <div v-if="!bundleRulesData.get(bundle.id) || bundleRulesData.get(bundle.id).loading"
                                                 class="py-3 text-center">
                                                <div class="spinner-border spinner-border-sm text-primary"></div>
                                            </div>
                                            <template v-else-if="bundleRulesData.get(bundle.id).items.length">
                                                <div class="bl-rules-list">
                                                    <template v-for="rule in bundleRulesData.get(bundle.id).items" :key="rule.id">
                                                        <div class="bl-rule-row">
                                                            <div class="bl-rule-row-main">
                                                                <span v-if="rule.format" class="badge rounded-pill bg-dark bl-rule-fmt">
                                                                    {{ rule.format.toUpperCase() }}
                                                                </span>
                                                                <a :href="'/rule/detail_rule/' + rule.id"
                                                                   class="bl-rule-title" target="_blank">
                                                                    {{ rule.title }}
                                                                </a>
                                                                <div class="bl-rule-meta-inline" @click.stop>
                                                                    <user-chip :user-id="rule.user_id" :username="rule.editor"
                                                                               :avatar="rule.editor_avatar" size="xs"></user-chip>
                                                                </div>
                                                                <div class="bl-rule-tags-inline" @click.stop>
                                                                    <tags-displays-list object-type="rule" :object-id="rule.id"
                                                                        :max-visible="2" :initial-tags="rule.tags || []">
                                                                    </tags-displays-list>
                                                                </div>
                                                                <button class="bl-rule-expand-btn"
                                                                        @click.stop="toggleRuleExpand(bundle.id, rule.id)">
                                                                    <i :class="isRuleExpanded(bundle.id, rule.id) ? 'fas fa-chevron-up' : 'fas fa-chevron-down'"
                                                                       style="font-size:.65rem;"></i>
                                                                </button>
                                                            </div>
                                                            <div v-if="isRuleExpanded(bundle.id, rule.id)" class="bl-rule-code">
                                                                <code-viewer v-if="rule.to_string"
                                                                    :code="rule.to_string"
                                                                    :language="ruleLanguage(rule.format)"
                                                                    :title="rule.title"
                                                                    max-height="200px">
                                                                </code-viewer>
                                                            </div>
                                                        </div>
                                                    </template>
                                                </div>
                                                <div v-if="bundleRulesData.get(bundle.id).totalPages > 1"
                                                     class="bl-rules-pagination">
                                                    <button class="bl-rules-page-btn"
                                                            :disabled="bundleRulesData.get(bundle.id).page <= 1"
                                                            @click="fetchBundleRules(bundle.id, bundleRulesData.get(bundle.id).page - 1)">
                                                        <i class="fas fa-chevron-left"></i>
                                                    </button>
                                                    <span class="bl-rules-page-info">
                                                        {{ bundleRulesData.get(bundle.id).page }}
                                                        / {{ bundleRulesData.get(bundle.id).totalPages }}
                                                    </span>
                                                    <button class="bl-rules-page-btn"
                                                            :disabled="bundleRulesData.get(bundle.id).page >= bundleRulesData.get(bundle.id).totalPages"
                                                            @click="fetchBundleRules(bundle.id, bundleRulesData.get(bundle.id).page + 1)">
                                                        <i class="fas fa-chevron-right"></i>
                                                    </button>
                                                </div>
                                            </template>
                                            <div v-else class="text-muted small fst-italic py-2">
                                                No rules in this bundle.
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </td>
                        </tr>
                    </template>
                </tbody>
            </table>
        </div>

        <!-- ── Footer ── -->
        <div v-if="!loading && items.length > 0" class="rl-footer">
            <div v-if="viewMode === 'card'" class="rl-per-page">
                <span>Per page</span>
                <select v-model="perPageModel">
                    <option v-for="n in [6, 12, 24, 48]" :key="n" :value="n">{{ n }}</option>
                </select>
            </div>
            <div v-else style="width:1px;"></div>

            <div style="flex-grow:1;display:flex;justify-content:center;">
                <pagination-component :current-page="page" :total-pages="totalPages"
                                      @change-page="goToPage"></pagination-component>
            </div>

            <div class="rl-footer-info">{{ footerInfo }}</div>
        </div>

        <!-- ── Bulk bar ── -->
        <transition name="rl-bulk-slide">
            <div v-if="showBulkBar" class="rl-bulk-bar">
                <span class="rl-bulk-count">
                    {{ selectionCount }} {{ selectionCount === 1 ? 'bundle' : 'bundles' }} selected
                </span>
                <div class="rl-bulk-actions">
                    <button v-for="action in bulkActions" :key="action.key"
                            class="rl-bulk-btn"
                            :class="{ 'rl-bulk-btn--danger': action.variant === 'danger' }"
                            @click="emitBulkAction(action.key)">
                        <i v-if="action.icon" :class="'fas ' + action.icon"></i>
                        {{ action.label }}
                    </button>
                </div>
                <button class="rl-bulk-clear" @click="clearSelection">
                    <i class="fas fa-xmark"></i> Clear
                </button>
            </div>
        </transition>

    </div>
    `,

    setup(props, { emit }) {
        const init = props.initialFilters

        // ── URL param helpers ─────────────────────────────────────────────
        const _url = new URLSearchParams(window.location.search)
        const _p   = (key, fallback = '') => _url.get(key) ?? fallback
        const _arr = (key, fallback = '') =>
            (_p(key) || fallback).split(',').filter(Boolean)

        // ── Data ─────────────────────────────────────────────────────────
        const items      = ref([])
        const total      = ref(0)
        const totalPages = ref(1)
        const loading    = ref(false)

        // ── Pagination / sort ─────────────────────────────────────────────
        const page     = ref(Number(_p('page', '1')) || 1)
        const sortKey  = ref(_p('sort', ''))
        const sortDir  = ref(_p('dir', 'desc'))
        const viewMode = ref(_p('view', props.defaultView))

        // per_page is view-specific: restore for whichever view was active at reload
        const _urlPP      = Number(_p('per_page', '')) || 0
        const cardPerPage  = ref(viewMode.value !== 'table' && _urlPP ? _urlPP : props.initialPerPage)
        const tablePerPage = ref(viewMode.value === 'table'  && _urlPP ? _urlPP : 25)

        const perPage = computed(() =>
            viewMode.value === 'table' ? tablePerPage.value : cardPerPage.value
        )
        const perPageModel = computed({
            get: () => perPage.value,
            set: val => {
                if (viewMode.value === 'table') tablePerPage.value = Number(val)
                else cardPerPage.value = Number(val)
                page.value = 1
                fetchData()
            },
        })

        // ── Filter state ─────────────────────────────────────────────────
        const search          = ref(_p('search', init.search || ''))
        const selectedTags    = ref(_arr('tags',            init.tags || ''))
        const selectedVulns   = ref(_arr('vulnerabilities', init.vulnerabilities || ''))
        const selectedAttacks = ref(_arr('attacks',         init.attacks || ''))
        const accessFilter    = ref(_p('access', init.access || ''))
        const scopeMine       = ref(_p('scope') === 'mine')
        const personFilter    = ref({
            mode:   _p('person_mode', 'author'),
            values: _arr('creators'),
        })
        const cardSort     = ref('newest')
        const filtersOpen  = ref(['tags','vulnerabilities','attacks','access','creators','scope'].some(k => _url.has(k)))

        // ── Column visibility ─────────────────────────────────────────────
        const TOGGLEABLE_COLS = [
            { key: 'description', label: 'Description' },
            { key: 'author',      label: 'Author'      },
            { key: 'rules',       label: 'Rules'       },
            { key: 'tags',        label: 'Tags'        },
            { key: 'cves',        label: 'CVEs'        },
            { key: 'attacks',     label: 'ATT&CK'      },
            { key: 'created',     label: 'Created'     },
            { key: 'votes',       label: 'Votes'       },
        ]
        const colVisible = Vue.reactive(Object.fromEntries(TOGGLEABLE_COLS.map(c => [c.key, true])))
        function toggleColumn(key) { colVisible[key] = !colVisible[key] }

        // ── Selection ─────────────────────────────────────────────────────
        const selectedIds         = reactive(new Set())
        const selectedBundlesMap  = reactive(new Map())
        const showAllPicked       = ref(false)
        const allPagesSelected    = ref(false)
        let searchTimer = null

        // ── Expand / inline rules ─────────────────────────────────────────
        const expandedIds     = reactive(new Set())
        const bundleRulesData = reactive(new Map())  // bundleId → {items, page, totalPages, loading, expandedRuleIds}
        const expandedRuleMap = reactive(new Map())  // bundleId → Set of expanded ruleIds

        // ── Computed ──────────────────────────────────────────────────────
        const numericUserId = computed(() =>
            props.userId !== null && props.userId !== '' ? Number(props.userId) : null
        )
        const numericCurrentUserId = computed(() =>
            props.currentUserId !== null && props.currentUserId !== ''
                ? Number(props.currentUserId) : null
        )

        function isOwner(bundle) {
            return numericCurrentUserId.value !== null &&
                   numericCurrentUserId.value === bundle.user_id
        }

        function isFilterHidden(key) { return props.hiddenFilters.includes(key) }

        const activeFilterCount = computed(() =>
            (accessFilter.value ? 1 : 0) +
            (scopeMine.value ? 1 : 0) +
            selectedTags.value.length +
            selectedVulns.value.length +
            selectedAttacks.value.length +
            personFilter.value.values.length
        )

        const isSelectable = computed(() =>
            props.mode === 'select' || props.mode === 'manage'
        )

        // ── URL sync ──────────────────────────────────────────────────────
        function syncToUrl() {
            if (!props.syncUrl) return
            const p = new URLSearchParams()
            if (search.value)       p.set('search', search.value)
            if (page.value > 1)     p.set('page', page.value)
            if (sortKey.value)    { p.set('sort', sortKey.value); p.set('dir', sortDir.value) }
            if (viewMode.value !== props.defaultView) p.set('view', viewMode.value)
            // per_page — only write when non-default so URLs stay clean
            const _defaultPP = viewMode.value === 'table' ? 25 : props.initialPerPage
            if (perPage.value !== _defaultPP) p.set('per_page', perPage.value)
            if (selectedTags.value.length)     p.set('tags',            selectedTags.value.join(','))
            if (selectedVulns.value.length)    p.set('vulnerabilities', selectedVulns.value.join(','))
            if (selectedAttacks.value.length)  p.set('attacks',         selectedAttacks.value.join(','))
            if (accessFilter.value)            p.set('access', accessFilter.value)
            if (scopeMine.value)               p.set('scope', 'mine')
            if (personFilter.value.values.length) {
                p.set('creators', personFilter.value.values.join(','))
                if (personFilter.value.mode && personFilter.value.mode !== 'author')
                    p.set('person_mode', personFilter.value.mode)
            }
            const qs = p.toString()
            history.replaceState(null, '', qs ? `?${qs}` : window.location.pathname)
        }

        // ── Fetch bundles ─────────────────────────────────────────────────
        async function fetchData() {
            loading.value = true
            try {
                const params = new URLSearchParams()
                params.set('page', page.value)
                params.set('per_page', perPage.value)
                if (search.value)             params.set('search', search.value)
                if (sortKey.value)          { params.set('sort', sortKey.value); params.set('dir', sortDir.value) }
                if (accessFilter.value)       params.set('access', accessFilter.value)
                if (numericUserId.value)      params.set('user_id', numericUserId.value)
                else if (scopeMine.value && numericCurrentUserId.value)
                    params.set('user_id', numericCurrentUserId.value)
                if (selectedTags.value.length)     params.set('tags',            selectedTags.value.join(','))
                if (selectedVulns.value.length)    params.set('vulnerabilities', selectedVulns.value.join(','))
                if (selectedAttacks.value.length)  params.set('attacks',         selectedAttacks.value.join(','))
                if (personFilter.value.values.length)
                    params.set('creators', personFilter.value.values.join(','))

                const sep = props.fetchUrl.includes('?') ? '&' : '?'
                const res = await fetch(`${props.fetchUrl}${sep}${params}`)
                if (!res.ok) return
                const data = await res.json()
                items.value      = data.items ?? []
                total.value      = data.total ?? 0
                totalPages.value = data.total_pages ?? 1
                if (page.value > totalPages.value && totalPages.value > 0)
                    page.value = totalPages.value
                syncToUrl()
            } finally {
                loading.value = false
            }
        }

        // ── Fetch rules for a bundle (lazy, paginated) ────────────────────
        async function fetchBundleRules(bundleId, pg = 1) {
            if (!bundleRulesData.has(bundleId)) {
                bundleRulesData.set(bundleId, { items: [], page: 1, totalPages: 1, total: 0, loading: true })
            }
            const slot = bundleRulesData.get(bundleId)
            slot.loading = true
            slot.page    = pg
            try {
                const res  = await fetch(`/bundle/get_rules_page_from_bundle?bundle_id=${bundleId}&page=${pg}`)
                const data = await res.json()
                slot.items      = data.rules_list ?? []
                slot.totalPages = data.total_pages ?? 1
                slot.total      = data.total_rules ?? 0
            } catch { slot.items = [] }
            finally { slot.loading = false }
        }

        // ── Expand/collapse bundles ───────────────────────────────────────
        function toggleExpand(bundle) {
            if (expandedIds.has(bundle.id)) {
                expandedIds.delete(bundle.id)
            } else {
                expandedIds.add(bundle.id)
                if (!bundleRulesData.has(bundle.id)) {
                    fetchBundleRules(bundle.id, 1)
                }
            }
        }

        const allExpanded = computed(() =>
            items.value.length > 0 && items.value.every(b => expandedIds.has(b.id))
        )

        function expandAll() {
            items.value.forEach(b => {
                expandedIds.add(b.id)
                if (!bundleRulesData.has(b.id)) fetchBundleRules(b.id, 1)
            })
        }

        function collapseAll() { expandedIds.clear() }

        // ── Expand/collapse individual rules inside a bundle ──────────────
        function toggleRuleExpand(bundleId, ruleId) {
            if (!expandedRuleMap.has(bundleId)) expandedRuleMap.set(bundleId, new Set())
            const s = expandedRuleMap.get(bundleId)
            if (s.has(ruleId)) s.delete(ruleId)
            else                s.add(ruleId)
        }

        function isRuleExpanded(bundleId, ruleId) {
            return expandedRuleMap.has(bundleId) && expandedRuleMap.get(bundleId).has(ruleId)
        }

        // ── Filter change handlers ────────────────────────────────────────
        function onFilterChange() {
            page.value = 1
            allPagesSelected.value = false
            fetchData()
        }

        function onPersonFilterChange(payload) {
            personFilter.value = payload
            onFilterChange()
        }

        function resetFilters() {
            selectedTags.value    = []
            selectedVulns.value   = []
            selectedAttacks.value = []
            accessFilter.value    = ''
            scopeMine.value       = false
            personFilter.value    = { mode: 'author', values: [] }
            onFilterChange()
        }

        function onSearchInput() {
            clearTimeout(searchTimer)
            searchTimer = setTimeout(() => { page.value = 1; fetchData() }, 360)
        }

        function clearSearch() { search.value = ''; page.value = 1; fetchData() }

        // ── Sort ─────────────────────────────────────────────────────────
        function setSort(key) {
            if (sortKey.value === key) {
                sortDir.value = sortDir.value === 'asc' ? 'desc' : 'asc'
            } else {
                sortKey.value = key
                sortDir.value = 'desc'
            }
            page.value = 1
            fetchData()
        }

        function sortIcon(key) {
            if (sortKey.value !== key) return 'fa-sort'
            return sortDir.value === 'asc' ? 'fa-sort-up' : 'fa-sort-down'
        }

        function onCardSortChange() {
            const map = {
                newest:      { key: 'created_at', dir: 'desc' },
                oldest:      { key: 'created_at', dir: 'asc'  },
                most_voted:  { key: 'vote_up',    dir: 'desc' },
                most_viewed: { key: 'view_count',  dir: 'desc' },
                name_asc:    { key: 'name',        dir: 'asc'  },
            }
            const s = map[cardSort.value]
            if (s) { sortKey.value = s.key; sortDir.value = s.dir }
            page.value = 1
            fetchData()
        }

        // ── Pagination ────────────────────────────────────────────────────
        function goToPage(p) { page.value = p; fetchData() }

        // ── Selection ────────────────────────────────────────────────────
        function isSelected(bundle) {
            return allPagesSelected.value || selectedIds.has(bundle.id)
        }

        function _mapAdd(b) {
            selectedBundlesMap.set(b.id, { id: b.id, name: b.name })
        }
        function _mapDel(id) { selectedBundlesMap.delete(id) }

        function toggleItem(bundle) {
            if (allPagesSelected.value) {
                allPagesSelected.value = false
                items.value.forEach(b => {
                    if (b.id !== bundle.id) { selectedIds.add(b.id); _mapAdd(b) }
                })
                return
            }
            if (selectedIds.has(bundle.id)) { selectedIds.delete(bundle.id); _mapDel(bundle.id) }
            else                             { selectedIds.add(bundle.id);    _mapAdd(bundle) }
        }

        function removeFromSelection(id) { selectedIds.delete(id); _mapDel(id) }

        const allOnPageSelected = computed(() =>
            isSelectable.value && items.value.length > 0 && items.value.every(b => selectedIds.has(b.id))
        )
        const someOnPageSelected = computed(() => {
            if (!isSelectable.value) return false
            const n = items.value.filter(b => selectedIds.has(b.id)).length
            return n > 0 && n < items.value.length
        })

        function togglePageSelection() {
            if (allPagesSelected.value) { clearSelection(); return }
            if (allOnPageSelected.value)
                items.value.forEach(b => { selectedIds.delete(b.id); _mapDel(b.id) })
            else
                items.value.forEach(b => { selectedIds.add(b.id); _mapAdd(b) })
        }

        function selectAllPages() { allPagesSelected.value = true }

        function clearSelection() {
            selectedIds.clear()
            selectedBundlesMap.clear()
            allPagesSelected.value = false
            showAllPicked.value = false
        }

        const selectedBundlesList = computed(() => [...selectedBundlesMap.values()])
        const selectionCount = computed(() =>
            allPagesSelected.value ? total.value : selectedIds.size
        )
        const showSelectBanner = computed(() =>
            isSelectable.value && allOnPageSelected.value && total.value > items.value.length
        )
        const showBulkBar = computed(() =>
            props.mode === 'manage' && (selectedIds.size > 0 || allPagesSelected.value)
        )

        // ── Vote ──────────────────────────────────────────────────────────
        function _csrf() { return document.getElementById('csrf_token')?.value ?? '' }

        async function handleVote(type, bundle) {
            if (!props.canVote) return
            try {
                const res  = await fetch(`/bundle/evaluate?bundleId=${bundle.id}&voteType=${type}`)
                const data = await res.json()
                if (res.ok) {
                    bundle.vote_up   = data.vote_up
                    bundle.vote_down = data.vote_down
                    bundle.user_vote = data.user_vote ?? null
                    emit('vote', { bundleId: bundle.id, type })
                }
            } catch {}
        }

        // ── Bulk ──────────────────────────────────────────────────────────
        function emitBulkAction(action) {
            const ids   = allPagesSelected.value ? 'ALL' : Array.from(selectedIds)
            const count = selectionCount.value
            emit('bulk-action', { action, ids, count })
            clearSelection()
        }

        function emitSend() {
            emit('send', allPagesSelected.value ? 'ALL' : Array.from(selectedIds))
        }

        // ── Table colspan ─────────────────────────────────────────────────
        const tableColspan = computed(() => {
            let n = 2 // name + actions always
            if (isSelectable.value) n++
            for (const col of TOGGLEABLE_COLS) if (colVisible[col.key]) n++
            return n
        })

        // ── Footer info ───────────────────────────────────────────────────
        const footerInfo = computed(() => {
            if (total.value === 0) return 'No results'
            const start = (page.value - 1) * perPage.value + 1
            const end   = Math.min(page.value * perPage.value, total.value)
            return `${start}–${end} of ${total.value}`
        })

        // ── Highlight ────────────────────────────────────────────────────
        function highlight(text) {
            if (!text) return ''
            const q = search.value.trim()
            if (!q || q.length < 2) return _esc(text)
            const escaped = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
            return _esc(text).replace(
                new RegExp(escaped, 'gi'),
                m => `<mark class="rl-highlight">${m}</mark>`
            )
        }
        function _esc(s) {
            return String(s)
                .replace(/&/g, '&amp;').replace(/</g, '&lt;')
                .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
        }

        // ── Date helpers ──────────────────────────────────────────────────
        function fromNow(dateStr) {
            if (!dateStr) return ''
            try {
                if (window.dayjs) return window.dayjs.utc(dateStr).fromNow()
                return formatDate(dateStr)
            } catch { return dateStr }
        }

        function formatDate(val) {
            if (!val) return '—'
            try {
                return new Date(val).toLocaleDateString(undefined, {
                    year: 'numeric', month: 'short', day: 'numeric',
                })
            } catch { return val }
        }

        function ruleLanguage(format) {
            if (!format) return 'auto'
            const map = {
                yara: 'yara', sigma: 'yaml', suricata: 'text', zeek: 'zeek',
                elastic: 'json', wazuh: 'xml', nova: 'text', nse: 'lua', crs: 'text',
            }
            return map[format.toLowerCase()] || 'auto'
        }

        // ── Lifecycle ─────────────────────────────────────────────────────
        onMounted(() => fetchData())
        onUnmounted(() => clearTimeout(searchTimer))
        watch(viewMode, () => { page.value = 1; fetchData() })

        return {
            items, total, totalPages, loading, page, perPage, perPageModel,
            sortKey, sortDir, search,
            filtersOpen, selectedTags, selectedVulns, selectedAttacks, accessFilter, scopeMine,
            personFilter, onPersonFilterChange,
            activeFilterCount,
            viewMode, expandedIds, allExpanded,
            TOGGLEABLE_COLS, colVisible, toggleColumn,
            selectedIds, allPagesSelected, isSelectable,
            allOnPageSelected, someOnPageSelected,
            selectionCount, showSelectBanner, showBulkBar,
            selectedBundlesList, showAllPicked, removeFromSelection,
            numericUserId, numericCurrentUserId, tableColspan, footerInfo,
            bundleRulesData, expandedRuleMap,
            cardSort,
            isOwner, isFilterHidden,
            fetchData, onFilterChange, resetFilters, onSearchInput, clearSearch,
            setSort, sortIcon, onCardSortChange,
            goToPage,
            isSelected, toggleItem, togglePageSelection, selectAllPages, clearSelection,
            toggleExpand, expandAll, collapseAll,
            toggleRuleExpand, isRuleExpanded,
            fetchBundleRules,
            handleVote, emitBulkAction, emitSend,
            fromNow, formatDate, ruleLanguage, highlight,
        }
    },
}
