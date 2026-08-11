/**
 * ruleList.js — Reusable rule list component (card + table views)
 *
 * Modes:
 *   read    — view only, no selection
 *   select  — checkboxes + confirm button emitting send(ids)
 *   manage  — checkboxes + sticky bulk bar with configurable actions
 *
 * Both views include integrated filter panel and pagination.
 * Card style matches /rule/rules_list exactly.
 *
 * Props:
 *   mode                String   'read'|'select'|'manage'      default:'read'
 *   defaultView         String   'card'|'table'                default:'card'
 *   fetchUrl            String   paginated API endpoint        default:'/rule/data_table'
 *   source              String   GitHub source URL filter
 *   userId              Number   filter by owner
 *   currentUserId       Number   for OWNER badge
 *   currentUserIsAdmin  Boolean
 *   showFilters         Boolean  show filter panel             default:true
 *   showCreate          Boolean  show "New Rule" button        default:false
 *   canVote             Boolean                                default:false
 *   canFavorite         Boolean                                default:false
 *   canEdit             Boolean                                default:false
 *   canDelete           Boolean                                default:false
 *   bulkActions         Array    [{key,label,icon?,variant?}]  default:[]
 *   initialPerPage      Number                                 default:12
 *   hiddenFilters       Array    field keys to hide            default:[]
 *   initialFilters      Object   pre-filled filter values      default:{}
 *   ids                 String|Array  pin listing to an explicit, fixed set of rule ids  default:null
 *   hasCveOnly          Boolean  pin listing to rules with a CVE (also read from ?has_cve=true)  default:false
 *   initialSort         String   default sort column when no ?sort in URL    default:''
 *   initialDir          String   default sort direction                      default:'asc'
 *
 * Events:
 *   create
 *   edit(rule)
 *   delete(rule)
 *   vote({ ruleId, type })           — voted; local state updated automatically
 *   favorite({ ruleId, isFavorited}) — toggled; local state updated automatically
 *   bulk-action({ action, ids, count })
 *   send(ids)
 *
 * Exposed:
 *   fetchData() — re-fetch current page from the outside
 */

import PaginationComponent      from '/static/js/rule/paginationComponent.js'
import MultiVulnerabilityFilter from '/static/js/vulnerability/multiVulnerabilityFilter.js'
import MultiSourceFilter        from '/static/js/rule/multiSourceFilter.js'
import MultiLicenseFilter       from '/static/js/rule/multiLicenseFilter.js'
import MultiPersonFilter        from '/static/js/rule/multiPersonFilter.js'
import MultiTagFilter           from '/static/js/tags/multiTagFIlter.js'
import TagsDisplaysList         from '/static/js/tags/tagsDisplaysList.js'
import VulnerabilityDisplaysList from '/static/js/vulnerability/vulnerabilityDisplayList.js'
import UserChip                 from '/static/js/components/UserChip.js'
import CodeViewer               from '/static/js/components/code-viewer.js'
import RuleExportAction         from '/static/js/rule/ruleExportAction.js'
import { create_message }       from '/static/js/toaster.js'
import ReportModal              from '/static/js/components/ReportModal.js'
import MultiAttackFilter        from '/static/js/attack/multiAttackFilter.js'
import AttackDisplayList        from '/static/js/attack/attackDisplayList.js'
import YaraMatchDetail           from '/static/js/rule_tester/YaraMatchDetail.js'

const { ref, reactive, computed, watch, onMounted, onUnmounted, nextTick } = Vue

export default {
    name: 'RuleList',
    components: {
        PaginationComponent,
        MultiVulnerabilityFilter,
        MultiSourceFilter,
        MultiLicenseFilter,
        MultiTagFilter,
        MultiPersonFilter,
        TagsDisplaysList,
        VulnerabilityDisplaysList,
        UserChip,
        CodeViewer,
        RuleExportAction,
        ReportModal,
        MultiAttackFilter,
        AttackDisplayList,
        YaraMatchDetail,
    },

    props: {
        mode:               { type: String,           default: 'read' },
        defaultView:        { type: String,           default: 'card' },
        fetchUrl:           { type: String,           default: '/rule/data_table' },
        source:             { type: String,           default: null },
        // Pins the sidebar facet counts (tags/ATT&CK/vulnerabilities/licenses/person)
        // to a fixed author, the same way `source` already pins them to a fixed
        // source. Only used when there's no source to pin by (e.g. a rule with no
        // known source but a known author). No effect on any other page.
        authorContext:      { type: String,           default: '' },
        // Pins the listing to an explicit, fixed set of rule ids (backend
        // `/rule/data_table?ids=` support already existed; this just wires
        // it into the component) — e.g. showing exactly the N rules covered
        // by one bulk ownership grant, rather than a live filter.
        ids:                { type: [String, Array],  default: null },
        userId:             { type: [Number, String], default: null },
        currentUserId:      { type: [Number, String], default: null },
        currentUserIsAdmin: { type: Boolean,          default: false },
        showFilters:        { type: Boolean,          default: true },
        showCreate:         { type: Boolean,          default: false },
        canVote:            { type: Boolean,          default: false },
        canFavorite:        { type: Boolean,          default: false },
        canEdit:            { type: Boolean,          default: false },
        canDelete:          { type: Boolean,          default: false },
        bulkActions:        { type: Array,            default: () => [] },
        initialPerPage:     { type: Number,           default: 12 },
        hiddenFilters:      { type: Array,            default: () => [] },
        initialFilters:     { type: Object,           default: () => ({}) },
        csrfToken:          { type: String,           default: '' },
        currentUserIsAuthenticated: { type: Boolean,  default: false },
        showExport:         { type: Boolean,          default: true },
        syncUrl:            { type: Boolean,          default: true },
        confirmDisabled:    { type: Boolean,          default: false },
        hiddenColumns:      { type: Array,            default: () => [] },
        draggable:          { type: Boolean,          default: false },
        showStatus:         { type: Boolean,          default: false },
        // Opt-in, page-local extension: when true, each `rule` item is expected to
        // carry an embedded `test_result` ({ matched, score, execution_time_ms,
        // quality_hints, details, error }) — used by the Rule Tester's test detail
        // page only. No effect on any other page that doesn't pass this prop.
        showTestResults:    { type: Boolean,          default: false },
        // The payload the tests were run against — { type: 'hex'|'string'|..., value } —
        // enables the per-string "compare with your input" button. Optional.
        testInput:          { type: Object,            default: null },
        // Rule UUID to visually highlight + auto-scroll to once loaded (e.g. when
        // arriving from that rule's own Test History via ?rule_uuid=...). Optional.
        highlightUuid:      { type: String,             default: null },
        // Pins the listing to rules that carry at least one CVE — used by the
        // dashboard's "Last CVEs" widget. Not exposed as a user-facing filter.
        hasCveOnly:         { type: Boolean,             default: false },
        // Default sort column/direction when the URL has none (e.g. embedded
        // widgets that don't want to touch the page's own URL via syncUrl).
        initialSort:        { type: String,              default: '' },
        initialDir:         { type: String,              default: 'asc' },
    },

    emits: ['create', 'edit', 'delete', 'vote', 'favorite', 'bulk-action', 'send', 'rule-drag-start', 'rule-drag-end', 'status-change'],

    // 'ruleType'/'onFilterChange' let a parent page drive the format filter
    // from outside (e.g. clicking a "12 YARA rules" stat elsewhere on the
    // page) via a template ref — same idea as 'fetchData' already being
    // exposed for an external refresh trigger.
    expose: ['fetchData', 'ruleType', 'onFilterChange'],

    template: `
    <div class="rl-wrapper">

        <!-- ── Toolbar: search + sort + view toggle ── -->
        <div class="rl-toolbar">
            <div class="rl-toolbar-left">
                <!-- Search -->
                <div class="dt-search">
                    <i class="fas fa-search dt-search-icon"></i>
                    <input class="dt-search-input" type="text" placeholder="Search rules…"
                           v-model="search" @input="onSearchInput" aria-label="Search rules" />
                    <button v-if="search" class="dt-search-clear" @click="clearSearch"
                            aria-label="Clear search">
                        <i class="fas fa-xmark"></i>
                    </button>
                </div>
                <span v-if="!loading" class="text-muted small ms-2 text-nowrap">
                    <strong>{{ total }}</strong> rule<span v-if="total !== 1">s</span>
                </span>
            </div>

            <div class="rl-toolbar-right">
                <!-- Sort dropdown (card mode) -->
                <select v-if="viewMode === 'card'" v-model="cardSort" class="rl-sort-select"
                        @change="onCardSortChange" aria-label="Sort rules">
                    <option value="newest">Newest</option>
                    <option value="oldest">Oldest</option>
                    <option value="most_likes">Most liked</option>
                    <option value="title_asc">A → Z</option>
                </select>

                <!-- View toggle -->
                <div class="dt-view-toggle" title="Switch view">
                    <button class="dt-view-btn" :class="{ 'dt-view-btn--active': viewMode === 'card' }"
                            @click="viewMode = 'card'" aria-label="Card view">
                        <i class="fas fa-rectangle-list"></i>
                    </button>
                    <button class="dt-view-btn" :class="{ 'dt-view-btn--active': viewMode === 'table' }"
                            @click="viewMode = 'table'" aria-label="Table view">
                        <i class="fas fa-table-cells-large"></i>
                    </button>
                </div>

                <!-- Column picker (table mode) -->
                <div v-if="viewMode === 'table'" class="dropdown">
                    <button class="dt-toolbar-btn dropdown-toggle" data-bs-toggle="dropdown"
                            aria-expanded="false" aria-label="Toggle columns">
                        <i class="fas fa-table-columns"></i>
                        <span>Columns</span>
                    </button>
                    <ul class="dropdown-menu dropdown-menu-end shadow border-0 py-2"
                        style="border-radius:12px;min-width:165px;" @click.stop>
                        <li v-for="col in TOGGLEABLE_COLS" :key="col.key">
                            <label class="dropdown-item rounded-2 d-flex align-items-center gap-2"
                                   style="cursor:pointer;font-size:.84rem;user-select:none;">
                                <input type="checkbox"
                                       :checked="colVisible[col.key]"
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
                <button v-if="showFilters"
                        class="dt-toolbar-btn"
                        :class="{ 'dt-toolbar-btn--active': filtersOpen }"
                        @click="filtersOpen = !filtersOpen"
                        :aria-expanded="filtersOpen">
                    <i class="fa-solid fa-filter"></i>
                    <span>Filters</span>
                    <span v-if="activeFilterCount > 0" class="rl-filter-badge ms-1">{{ activeFilterCount }}</span>
                </button>

                <!-- New Rule -->
                <button v-if="showCreate" class="dt-toolbar-btn dt-toolbar-btn--primary"
                        @click="$emit('create')">
                    <i class="fas fa-file-circle-plus"></i>
                    <span>New Rule</span>
                </button>

                <!-- Select-all / send (mode=select) -->
                <button v-if="mode === 'select'"
                        class="dt-toolbar-btn dt-toolbar-btn--primary"
                        :disabled="selectionCount === 0 || confirmDisabled"
                        @click="emitSend">
                    <i class="fas fa-check"></i>
                    <span>Confirm{{ selectionCount > 0 ? ' (' + selectionCount + ')' : '' }}</span>
                </button>

                <!-- Per-page (table mode) -->
                <div v-if="viewMode === 'table'" class="rl-per-page">
                    <span>Rows</span>
                    <select v-model="perPageModel" aria-label="Rows per page">
                        <option v-for="n in [10, 25, 50, 100]" :key="n" :value="n">{{ n }}</option>
                    </select>
                </div>
            </div>
        </div>

        <!-- ── Filter panel (below toolbar) ── -->
        <template v-if="showFilters">
            <div v-show="filtersOpen" class="rl-filter-panel">

                <!-- Row 1: quick options -->
                <div class="rl-fp-row">
                    <div class="rl-fp-item rl-fp-fmt-wrap" v-if="!isFilterHidden('format')">
                        <div class="rl-fmt-badge" :class="{ 'rl-fmt-badge--set': ruleType }">
                            <span v-if="ruleType" class="rl-fmt-badge__label">{{ ruleType.toUpperCase() }}</span>
                            <span v-else class="rl-fmt-badge__placeholder">
                                <i class="fa-solid fa-file-code me-1" style="font-size:.7rem;opacity:.5;"></i>Format
                            </span>
                            <i class="fa-solid fa-chevron-down" style="font-size:.6rem;opacity:.5;flex-shrink:0;"></i>
                        </div>
                        <select class="rl-fmt-select-overlay" v-model="ruleType" @change="onFilterChange" aria-label="Format">
                            <option value="">All formats</option>
                            <option v-for="f in rulesFormats" :key="f.id" :value="f.name">{{ f.name.toUpperCase() }}</option>
                        </select>
                    </div>

                    <div class="rl-fp-item" v-if="!isFilterHidden('search_field')">
                        <select v-model="searchField" class="rl-fp-select" @change="onFilterChange"
                                aria-label="Search in">
                            <option value="all">All fields</option>
                            <option value="title">Title only</option>
                            <option value="content">Content only</option>
                            <option value="uuid">UUID / ID</option>
                        </select>
                    </div>

                    <label v-if="!isFilterHidden('exact_match')"
                           class="rl-fp-switch" title="Exact match">
                        <input type="checkbox" v-model="exactMatch" @change="onFilterChange" />
                        <span>Exact</span>
                    </label>

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

                    <button v-if="activeFilterCount > 0"
                            class="rl-fp-reset" @click="resetFilters">
                        <i class="fas fa-rotate-left"></i> Reset
                    </button>
                </div>

                <!-- Row 2: multi-selects (sources, vulns, licenses, tags) -->
                <div class="rl-fp-row rl-fp-row--multi">
                    <div class="rl-fp-multi-item" v-if="!isFilterHidden('sources') && !source">
                        <span class="rl-fp-multi-label">
                            <i class="fa-solid fa-code-branch text-primary"></i> Sources
                        </span>
                        <multi-source-filter v-model="selectedSources"
                            api-endpoint="/rule/get_rules_sources_usage"
                            placeholder="Filter sources…"
                            :userId="numericUserId"
                            :filter-context="facetContextParams"
                            @change="onFilterChange">
                        </multi-source-filter>
                    </div>

                    <div class="rl-fp-multi-item" v-if="!isFilterHidden('vulnerabilities')">
                        <span class="rl-fp-multi-label">
                            <i class="fa-solid fa-shield-virus text-danger"></i> Vulnerabilities
                        </span>
                        <multi-vulnerability-filter v-model="selectedVulns"
                            api-endpoint="/rule/get_all_rules_vulnerabilities_usage"
                            placeholder="CVE, GHSA…"
                            :user-id="numericUserId"
                            :source-rules="source || ''"
                            :filter-context="facetContextParams"
                            @change="onFilterChange">
                        </multi-vulnerability-filter>
                    </div>

                    <div class="rl-fp-multi-item" v-if="!isFilterHidden('attacks')">
                        <span class="rl-fp-multi-label">
                            <i class="fa-solid fa-crosshairs text-warning"></i> ATT&amp;CK
                        </span>
                        <multi-attack-filter v-model="selectedAttacks"
                            placeholder="T1059, Command…"
                            :filter-context="facetContextParams"
                            @change="onFilterChange">
                        </multi-attack-filter>
                    </div>

                    <div class="rl-fp-multi-item" v-if="!isFilterHidden('licenses')">
                        <span class="rl-fp-multi-label">
                            <i class="fa-solid fa-scale-balanced text-info"></i> Licenses
                        </span>
                        <multi-license-filter v-model="selectedLicenses"
                            api-endpoint="/rule/get_rules_licenses_usage"
                            placeholder="Filter licenses…"
                            :user-id="numericUserId"
                            :source-rules="source || ''"
                            :filter-context="facetContextParams"
                            @change="onFilterChange">
                        </multi-license-filter>
                    </div>

                    <div class="rl-fp-multi-item" v-if="!isFilterHidden('tags')">
                        <span class="rl-fp-multi-label">
                            <i class="fa-solid fa-tags text-primary"></i> Tags
                        </span>
                        <multi-tag-filter v-model="selectedTags"
                            api-endpoint="/rule/get_all_tags_usage"
                            placeholder="Filter tags…"
                            :user-id="numericUserId"
                            target-type="rule"
                            :filter-context="facetContextParams"
                            @change="onFilterChange">
                        </multi-tag-filter>
                    </div>

                    <div class="rl-fp-multi-item" v-if="!isFilterHidden('person')">
                        <span class="rl-fp-multi-label">
                            <i class="fa-solid fa-person-circle-check text-warning"></i> Author / Editor
                        </span>
                        <multi-person-filter v-model="personFilter"
                            :user-id="numericUserId"
                            :source-rules="source || ''"
                            :filter-context="facetContextParams"
                            @change="onPersonFilterChange">
                        </multi-person-filter>
                    </div>
                </div>

                <!-- ── Export / Bundle — visible only when at least one filter is active ── -->
                <div v-if="showExport && hasActiveFilters" class="rl-fp-export-row">
                    <rule-export-action
                        :search-query="search"
                        :sort-by="sortKey"
                        :rule-type="ruleType"
                        :selected-sources="selectedSources"
                        :selected-vulnerabilities="selectedVulns"
                        :selected-licenses="selectedLicenses"
                        :selected-tags="selectedTags"
                        :total-rules="exportTotalRules"
                        :rule-ids="exportRuleIds"
                        :csrf-token="csrfToken"
                        :current-user-is-authenticated="currentUserIsAuthenticated ? 'True' : 'False'"
                        :start-view="exportActionView"
                        modal-id="rl-export-modal">
                    </rule-export-action>
                </div>

            </div>
        </template>

        <!-- ── Select-all-pages banner ── -->
        <div v-if="showSelectBanner" class="rl-select-banner">
            <span v-if="!allPagesSelected">
                All {{ items.length }} rules on this page are selected.
            </span>
            <span v-else>All {{ total }} rules are selected.</span>
            <button v-if="!allPagesSelected" class="rl-select-banner-btn" @click="selectAllPages">
                Select all {{ total }} rules
            </button>
            <button class="rl-select-banner-btn" @click="clearSelection">Clear selection</button>
        </div>

        <!-- ── Selected rules panel ── -->
        <div v-if="!allPagesSelected && selectedRulesList.length" class="rl-picked-panel">
            <div class="rl-picked-header">
                <span class="rl-picked-title">
                    <i class="fas fa-check-square me-1"></i>
                    {{ selectedRulesList.length }} rule{{ selectedRulesList.length !== 1 ? 's' : '' }} selected
                </span>
                <button class="rl-picked-clear" @click="clearSelection">
                    <i class="fas fa-xmark me-1"></i>Clear all
                </button>
            </div>
            <div class="rl-picked-chips">
                <span v-for="rule in showAllPicked ? selectedRulesList : selectedRulesList.slice(0, 8)"
                      :key="rule.id" class="rl-picked-chip">
                    <span v-if="rule.format" class="rl-picked-chip-fmt">{{ rule.format.toUpperCase() }}</span>
                    <span class="rl-picked-chip-title">{{ rule.title }}</span>
                    <button class="rl-picked-chip-rm" @click="removeFromSelection(rule.id)" title="Remove">
                        <i class="fas fa-xmark"></i>
                    </button>
                </span>
                <button v-if="selectedRulesList.length > 8 && !showAllPicked"
                        class="rl-picked-more" @click="showAllPicked = true">
                    +{{ selectedRulesList.length - 8 }} more
                </button>
                <button v-if="showAllPicked && selectedRulesList.length > 8"
                        class="rl-picked-more" @click="showAllPicked = false">
                    Show less
                </button>
            </div>
        </div>

        <!-- ── Loading ── -->
        <div v-if="loading" class="rl-loading">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading…</span>
            </div>
        </div>

        <!-- ── Empty ── -->
        <div v-else-if="items.length === 0 && !loading" class="rl-empty">
            <div class="rl-empty-icon"><i class="fas fa-search"></i></div>
            <p class="mb-0">No rules found matching your search.</p>
        </div>

        <!-- ══════════════════════════════════════════════
             CARD VIEW
             ══════════════════════════════════════════════ -->
        <div v-else-if="viewMode === 'card'" class="rl-cards">

            <div class="card h-100 shadow-sm border-0 mb-4 rl-rule-card"
                 v-for="rule in items" :key="rule.id"
                 :id="highlightUuid && rule.uuid === highlightUuid ? 'rl-highlight-target' : null"
                 :class="{ 'rl-rule-card--selected': isSelected(rule), 'rl-rule-card--highlighted': highlightUuid && rule.uuid === highlightUuid }">

                <div class="premium-accent-line"></div>
                <div class="card-watermark-list" v-show="!expandedIds.has(rule.id)">
                    <i class="fa-solid fa-shield-halved"></i>
                </div>

                <!-- Badges top-right -->
                <div class="position-absolute top-0 end-0 mt-3 me-3 d-flex gap-2" style="z-index:2;">
                    <span v-if="showTestResults && rule.test_result" class="badge shadow-sm pt-1"
                          :class="rule.test_result.matched ? 'bg-success' : (rule.test_result.error ? 'bg-danger' : 'bg-secondary')">
                        <i class="fa-solid me-1" :class="rule.test_result.matched ? 'fa-check' : (rule.test_result.error ? 'fa-triangle-exclamation' : 'fa-xmark')"></i>
                        <template v-if="rule.test_result.score!=null">{{ Math.round((rule.test_result.score||0)*100) }}%</template>
                        <template v-else>{{ rule.test_result.matched ? 'MATCH' : 'NO MATCH' }}</template>
                    </span>
                    <span v-if="isOwner(rule)" class="badge bg-success shadow-sm pt-1" title="You own this rule">
                        <i class="fa-solid fa-crown me-1"></i>OWNER
                    </span>
                    <span v-if="currentUserIsAdmin" class="badge bg-warning shadow-sm pt-1">
                        <i class="fa-solid fa-crown me-1"></i>ADMIN
                    </span>
                    <span v-if="rule.is_code_format" class="badge bg-danger shadow-sm pt-1"
                          title="Executable code, not a declarative detection rule">
                        <i class="fa-solid fa-code me-1"></i>CODE
                    </span>
                    <span class="badge rounded-pill bg-dark pt-1 shadow-sm">
                        {{ rule.format ? rule.format.toUpperCase() : '?' }}
                    </span>
                </div>

                <div class="card-body d-flex flex-column p-4" style="z-index:1;">

                    <!-- Selection row -->
                    <div v-if="isSelectable"
                         class="rl-card-check-row mb-3"
                         :class="{ 'rl-card-check-row--on': isSelected(rule) }"
                         @click.stop="toggleItem(rule)">
                        <input type="checkbox" class="rl-card-check-input"
                               :checked="isSelected(rule)"
                               @click.stop="toggleItem(rule)"
                               :aria-label="'Select ' + rule.title" />
                        <span class="rl-card-check-text">
                            {{ isSelected(rule) ? 'Selected' : 'Select this rule' }}
                        </span>
                        <i v-if="isSelected(rule)"
                           class="fas fa-check ms-auto text-primary"
                           style="font-size:.78rem;"></i>
                    </div>

                    <!-- Title + editor + date -->
                    <div class="mb-3 pe-5">
                        <h5 class="fw-bold mb-1">
                            <a :href="'/rule/detail_rule/' + rule.id"
                               class="fw-bold h5 border-start border-primary border-4 ps-3 custom-rule-link text-decoration-none d-block"
                               v-html="highlight(rule.title)">
                            </a>
                        </h5>
                        <div class="d-flex align-items-center gap-2 mt-2">
                            <user-chip
                                :user-id="rule.user_id"
                                :username="rule.editor"
                                :avatar="rule.editor_avatar"
                                size="xs">
                            </user-chip>
                            <span class="text-muted opacity-50">|</span>
                            <small class="text-muted">{{ fromNow(rule.last_modif) }}</small>
                        </div>
                    </div>

                    <!-- Description -->
                    <p class="rl-card-desc mb-2"
                       style="-webkit-line-clamp:3;-webkit-box-orient:vertical;display:-webkit-box;overflow:hidden;">
                        <span v-html="highlight(rule.description || 'No description.')"></span>
                    </p>
                    <div v-if="showTestResults && rule.test_result && matchedStringCount(rule) !== null" class="mb-3">
                        <div style="font-size:.65rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--subtle-text-color);margin-bottom:.25rem;">
                            <i class="fa-solid fa-magnifying-glass me-1"></i>Matched Strings
                        </div>
                        <span class="badge" style="background:rgba(13,110,253,.12);color:#0d6efd;font-size:.72rem;">
                            {{ matchedStringCount(rule) }} string{{ matchedStringCount(rule) === 1 ? '' : 's' }} matched
                        </span>
                    </div>

                    <!-- CVEs -->
                    <div class="mb-2" @click.stop>
                        <vulnerability-displays-list object-type="rule" :object-id="rule.id" :max-visible="3"
                            :initial-vulnerabilities="rule.cves || []">
                        </vulnerability-displays-list>
                    </div>

                    <!-- ATT&CK techniques -->
                    <div v-if="rule.attacks && rule.attacks.length" class="mb-2" @click.stop>
                        <attack-display-list :initial-attacks="rule.attacks" :max-visible="3"></attack-display-list>
                    </div>

                    <!-- Tags -->
                    <div class="mb-3" @click.stop>
                        <tags-displays-list object-type="rule" :object-id="rule.id" :max-visible="3"
                            :initial-tags="rule.tags || []">
                        </tags-displays-list>
                    </div>

                    <!-- Metadata strip -->
                    <div class="rl-card-meta">
                        <span class="rl-meta-item rl-meta-item--source" :title="rule.source">
                            <i class="fas fa-link"></i>
                            <span>{{ rule.source || '—' }}</span>
                        </span>
                        <span class="rl-meta-item">
                            <i class="fas fa-scale-balanced"></i>
                            <span>{{ rule.license && rule.license !== 'Unknown' ? rule.license : 'No license' }}</span>
                        </span>
                        <span class="rl-meta-item">
                            <i class="fas fa-code-branch"></i>
                            <span>v{{ rule.version && rule.version !== 'Unknown' ? rule.version : '1.0' }}</span>
                        </span>
                        <span v-if="rule.author && rule.author !== 'Unknown'" class="rl-meta-item">
                            <i class="fas fa-user"></i>
                            <span>{{ rule.author }}</span>
                        </span>
                        <span class="rl-meta-item" :title="'Rule id: ' + rule.id">
                            <i class="fas fa-hashtag"></i>
                            <span v-html="highlight('' + rule.id)"></span>
                        </span>
                        <span class="rl-meta-item rl-meta-item--uuid" :title="rule.uuid">
                            <i class="fas fa-fingerprint"></i>
                            <span v-html="highlight(rule.uuid)"></span>
                        </span>
                        <span v-if="rule.original_uuid && rule.original_uuid !== 'Unknown' && rule.original_uuid !== rule.uuid"
                              class="rl-meta-item rl-meta-item--uuid" :title="'Original UUID: ' + rule.original_uuid">
                            <i class="fas fa-fingerprint" style="opacity:.6;"></i>
                            <span v-html="highlight(rule.original_uuid)"></span>
                        </span>
                    </div>

                    <!-- Footer: votes + actions -->
                    <div class="d-flex justify-content-between align-items-center pt-3 border-top mt-auto">

                        <!-- Votes -->
                        <div class="btn-group shadow-sm border rounded-pill overflow-hidden">
                            <button @click="handleVote('up', rule)"
                                    class="btn btn-sm px-3 border-0 border-end border-light shadow-none btn-animate home-btn"
                                    :class="{ 'rl-vote-disabled': !canVote, 'rl-vote-btn--active-up': rule.user_vote === 'up' }"
                                    :title="canVote ? 'Upvote' : 'Login to vote'">
                                <i class="fas fa-thumbs-up me-1"></i>{{ rule.vote_up }}
                            </button>
                            <button @click="handleVote('down', rule)"
                                    class="btn btn-sm px-3 border-0 shadow-none btn-animate home-btn"
                                    :class="{ 'rl-vote-disabled': !canVote, 'rl-vote-btn--active-down': rule.user_vote === 'down' }"
                                    :title="canVote ? 'Downvote' : 'Login to vote'">
                                <i class="fas fa-thumbs-down me-1"></i>{{ rule.vote_down }}
                            </button>
                        </div>

                        <div class="d-flex gap-2 align-items-center">

                            <!-- Collapse toggle -->
                            <button class="btn btn-sm rounded-circle shadow-sm p-0 d-flex align-items-center justify-content-center home-btn"
                                    style="width:32px;height:32px;border:1px solid #eee;"
                                    :title="expandedIds.has(rule.id) ? 'Hide content' : 'Show content'"
                                    @click="toggleExpand(rule)">
                                <i :class="expandedIds.has(rule.id) ? 'fas fa-eye-slash' : 'fas fa-code'"
                                   style="font-size:.72rem;"></i>
                            </button>

                            <!-- Favorite -->
                            <button v-if="canFavorite"
                                    @click="handleFavorite(rule)"
                                    class="btn btn-sm rounded-circle shadow-sm p-0 d-flex align-items-center justify-content-center home-btn"
                                    style="width:32px;height:32px;border:1px solid #eee;"
                                    title="Add to favorites">
                                <i class="fa-star" :class="rule.is_favorited ? 'fas text-warning' : 'far'"></i>
                            </button>

                            <!-- More dropdown -->
                            <div class="dropup">
                                <button class="btn btn-sm rounded-circle shadow-sm p-0 d-flex align-items-center justify-content-center home-btn"
                                        style="width:32px;height:32px;border:1px solid #eee;"
                                        data-bs-toggle="dropdown" aria-expanded="false">
                                    <i class="fas fa-ellipsis-v text-muted" style="font-size:.75rem;"></i>
                                </button>
                                <ul class="dropdown-menu dropdown-menu-end shadow border-0 mb-2"
                                    style="border-radius:12px;">
                                    <li>
                                        <a class="dropdown-item rounded-2" :href="'/rule/detail_rule/' + rule.id">
                                            <i class="fas fa-eye me-2 text-muted"></i>View Detail
                                        </a>
                                    </li>
                                    <template v-if="currentUserIsAuthenticated">
                                        <li>
                                            <report-modal
                                                object-type="rule"
                                                :object-id="rule.id"
                                                :object-label="rule.title"
                                                :csrf-token="csrfToken">
                                                <template #trigger="{ open }">
                                                    <button class="dropdown-item rounded-2" @click.stop="open">
                                                        <i class="fas fa-flag me-2 text-muted"></i>Report Issue
                                                    </button>
                                                </template>
                                            </report-modal>
                                        </li>
                                    </template>
                                    <template v-if="numericCurrentUserId && (isOwner(rule) || currentUserIsAdmin)">
                                        <li><hr class="dropdown-divider"></li>
                                        <li>
                                            <a class="dropdown-item rounded-2"
                                               :href="'/rule/edit_rule/' + rule.id">
                                                <i class="fas fa-pen me-2 text-primary"></i>Edit Rule
                                            </a>
                                        </li>
                                    </template>
                                    <template v-if="numericCurrentUserId && (isOwner(rule) || currentUserIsAdmin)">
                                        <li>
                                            <button class="dropdown-item rounded-2 text-danger"
                                                    @click="$emit('delete', rule)">
                                                <i class="fa-solid fa-trash me-2"></i>Delete Rule
                                            </button>
                                        </li>
                                    </template>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Collapse: rule content -->
                <div v-if="expandedIds.has(rule.id)" class="rl-rule-collapse border-top">
                    <div v-if="showTestResults && rule.test_result" class="rl-expand-test-report">
                        <div class="rl-expand-test-report__title">
                            <i class="fa-solid fa-flask-vial"></i>
                            <span>Test report</span>
                            <span class="ms-auto badge" :class="rule.test_result.matched ? 'bg-success' : (rule.test_result.error ? 'bg-danger' : 'bg-secondary')">
                                {{ rule.test_result.matched ? 'MATCHED' : (rule.test_result.error ? 'ERROR' : 'NO MATCH') }}
                            </span>
                            <span v-if="rule.test_result.score!=null" class="badge bg-dark">
                                {{ Math.round((rule.test_result.score||0)*100) }}%
                            </span>
                            <span v-if="rule.test_result.execution_time_ms!=null" class="badge bg-dark">
                                {{ rule.test_result.execution_time_ms }}ms
                            </span>
                        </div>
                        <div v-if="rule.test_result.error" class="rtr-hints px-0">
                            <div class="rtr-hint-item">
                                <i class="fa-solid fa-circle-exclamation rtr-hint-icon" style="color:#dc3545;"></i>
                                {{ rule.test_result.error }}
                            </div>
                        </div>
                        <yara-match-detail v-if="rule.format==='yara'"
                            :details="rule.test_result.details || {}"
                            :quality-hints="rule.test_result.quality_hints || []"
                            :test-input="testInput">
                        </yara-match-detail>
                        <div v-else-if="rule.test_result.quality_hints && rule.test_result.quality_hints.length" class="rtr-hints px-0">
                            <div v-for="hint in rule.test_result.quality_hints" :key="hint" class="rtr-hint-item">
                                <i class="fa-solid fa-lightbulb rtr-hint-icon"></i>{{ hint }}
                            </div>
                        </div>
                        <p v-if="matchedHighlightTerms(rule).length" class="mb-0" style="font-size:.72rem;color:var(--subtle-text-color);">
                            <i class="fa-solid fa-arrow-down me-1"></i>The matched bytes are highlighted in blue in the rule content below.
                        </p>
                    </div>
                    <code-viewer v-if="rule.to_string"
                        :code="rule.to_string"
                        :language="ruleLanguage(rule.format)"
                        :title="rule.title"
                        :initial-search="searchField === 'content' ? search : ''"
                        :extra-highlights="showTestResults ? matchedHighlightTerms(rule) : []"
                        :word-wrap="true"
                        max-height="380px">
                    </code-viewer>
                    <p v-else class="text-muted text-center py-3 mb-0 small">No content available.</p>
                </div>
            </div>
        </div>

        <!-- ══════════════════════════════════════════════
             TABLE VIEW
             ══════════════════════════════════════════════ -->
        <div v-else class="dt-table-wrap rl-table-wrap">
            <table class="dt-table" role="grid">
                <thead class="dt-thead">
                    <tr>
                        <th v-if="draggable" class="dt-th dt-th--drag"></th>
                        <th v-if="isSelectable" class="dt-th dt-th--checkbox">
                            <input type="checkbox" class="dt-checkbox"
                                   :checked="allOnPageSelected"
                                   :indeterminate="someOnPageSelected"
                                   @change="togglePageSelection"
                                   aria-label="Select all on page" />
                        </th>
                        <th v-if="showStatus" class="dt-th" style="width:110px;">Status</th>
                        <th class="dt-th dt-th--sortable" style="width:180px;"
                            :class="{ 'dt-th--sorted': sortKey === 'title' }"
                            @click="setSort('title')">
                            <div class="dt-th-inner">
                                Title <i class="fas dt-sort-icon" :class="sortIcon('title')"></i>
                            </div>
                        </th>
                        <th v-if="showTestResults" class="dt-th" style="width:150px;">Result</th>
                        <th v-show="colVisible.id" class="dt-th" style="width:90px;">ID</th>
                        <th v-show="colVisible.format"
                            class="dt-th dt-th--sortable" style="width:80px;"
                            :class="{ 'dt-th--sorted': sortKey === 'format' }"
                            @click="setSort('format')">
                            <div class="dt-th-inner">
                                Format <i class="fas dt-sort-icon" :class="sortIcon('format')"></i>
                            </div>
                        </th>
                        <th v-show="colVisible.editor" class="dt-th" style="width:140px;">
                            Editor
                        </th>
                        <th v-show="colVisible.description" class="dt-th">Description</th>
                        <th v-show="colVisible.tags" class="dt-th" style="width:160px;">Tags</th>
                        <th v-show="colVisible.cves" class="dt-th" style="width:130px;">CVEs</th>
                        <th v-show="colVisible.attacks" class="dt-th" style="width:160px;">ATT&amp;CK</th>
                        <th v-show="colVisible.created"
                            class="dt-th dt-th--sortable" style="width:110px;"
                            :class="{ 'dt-th--sorted': sortKey === 'creation_date' }"
                            @click="setSort('creation_date')">
                            <div class="dt-th-inner">
                                Created <i class="fas dt-sort-icon" :class="sortIcon('creation_date')"></i>
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
                    <template v-for="rule in items" :key="rule.id">
                        <tr class="dt-row"
                            :id="highlightUuid && rule.uuid === highlightUuid ? 'rl-highlight-target' : null"
                            :class="{
                                'dt-row--selected':  isSelected(rule),
                                'dt-row--expanded':  expandedIds.has(rule.id),
                                'dt-row--favorited': rule.is_favorited,
                                'dt-row--highlighted': highlightUuid && rule.uuid === highlightUuid,
                            }"
                            :draggable="draggable"
                            @dragstart="draggable && $emit('rule-drag-start', rule)"
                            @dragend="draggable && $emit('rule-drag-end', rule)">

                            <td v-if="draggable" class="dt-td dt-td--drag">
                                <span class="drag-handle" title="Drag to workspace">
                                    <i class="fas fa-grip-vertical"></i>
                                </span>
                            </td>
                            <td v-if="isSelectable" class="dt-td dt-td--checkbox">
                                <input type="checkbox" class="dt-checkbox"
                                       :checked="isSelected(rule)"
                                       @change="toggleItem(rule)"
                                       :aria-label="'Select ' + rule.title" />
                            </td>

                            <td v-if="showStatus" class="dt-td" @click.stop>
                                <button class="rl-status-badge"
                                        :class="'rl-status--' + (rule.status || 'draft')"
                                        :title="canChangeStatus(rule) ? 'Click to cycle status' : statusLabel(rule.status || \'draft\')"
                                        @click="canChangeStatus(rule) && cycleStatus(rule)">
                                    <i :class="statusIcon(rule.status || 'draft')"></i>
                                    {{ statusLabel(rule.status || 'draft') }}
                                </button>
                            </td>

                            <td class="dt-td" style="max-width:200px;word-break:break-word;">
                                <a :href="'/rule/detail_rule/' + rule.id" class="dt-rule-title"
                                   v-html="highlight(rule.title)">
                                </a>
                            </td>

                            <td v-show="colVisible.id" class="dt-td" :title="'Rule id: ' + rule.id">
                                <span v-html="highlight('' + rule.id)"></span>
                            </td>

                            <td v-if="showTestResults" class="dt-td">
                                <div v-if="rule.test_result" class="d-flex align-items-center gap-1">
                                    <i v-if="rule.test_result.matched"    class="fa-solid fa-check text-success" title="Matched"></i>
                                    <i v-else-if="rule.test_result.error" class="fa-solid fa-triangle-exclamation text-danger" :title="rule.test_result.error"></i>
                                    <i v-else                             class="fa-solid fa-xmark text-muted" title="No match"></i>
                                    <div v-if="rule.test_result.score!=null" style="flex:1;min-width:36px;">
                                        <div style="height:5px;border-radius:3px;background:var(--border-color);overflow:hidden;">
                                            <div :style="'width:'+Math.round((rule.test_result.score||0)*100)+'%;height:100%;border-radius:3px;background:'+(rule.test_result.score>=.7?'#198754':rule.test_result.score>=.3?'#ffc107':'#dc3545')+';'"></div>
                                        </div>
                                    </div>
                                    <span style="font-size:.68rem;white-space:nowrap;color:var(--subtle-text-color);">
                                        <template v-if="rule.test_result.score!=null">{{ Math.round((rule.test_result.score||0)*100) }}%</template>
                                        <template v-if="rule.test_result.execution_time_ms!=null"> · {{ rule.test_result.execution_time_ms }}ms</template>
                                    </span>
                                </div>
                            </td>

                            <td v-show="colVisible.format" class="dt-td">
                                <span v-if="rule.is_code_format" class="badge bg-danger pt-1 shadow-sm me-1"
                                      title="Executable code, not a declarative detection rule">
                                    <i class="fa-solid fa-code me-1"></i>CODE
                                </span>
                                <span v-if="rule.format"
                                      class="badge rounded-pill bg-dark pt-1 shadow-sm">
                                    {{ rule.format.toUpperCase() }}
                                </span>
                            </td>

                            <td v-show="colVisible.editor" class="dt-td" style="max-width:140px;"
                                @click.stop>
                                <user-chip
                                    :user-id="rule.user_id"
                                    :username="rule.editor"
                                    :avatar="rule.editor_avatar"
                                    size="xs">
                                </user-chip>
                            </td>

                            <td v-show="colVisible.description" class="dt-td dt-td--truncate">
                                <span class="text-muted"
                                      v-html="highlight(rule.description || '—')"></span>
                                <div v-if="showTestResults && rule.test_result && matchedStringCount(rule) !== null" class="mt-1">
                                    <div style="font-size:.6rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--subtle-text-color);">
                                        <i class="fa-solid fa-magnifying-glass me-1"></i>Matched Strings
                                    </div>
                                    <span class="badge" style="background:rgba(13,110,253,.12);color:#0d6efd;font-size:.68rem;">
                                        {{ matchedStringCount(rule) }} string{{ matchedStringCount(rule) === 1 ? '' : 's' }} matched
                                    </span>
                                </div>
                            </td>

                            <td v-show="colVisible.tags" class="dt-td" @click.stop>
                                <tags-displays-list v-if="rule.tags && rule.tags.length"
                                    object-type="rule" :object-id="rule.id" :max-visible="2"
                                    :initial-tags="rule.tags">
                                </tags-displays-list>
                                <span v-else class="text-muted small">—</span>
                            </td>

                            <td v-show="colVisible.cves" class="dt-td" @click.stop>
                                <vulnerability-displays-list v-if="rule.cves && rule.cves.length"
                                    object-type="rule" :object-id="rule.id" :max-visible="2"
                                    :initial-vulnerabilities="rule.cves">
                                </vulnerability-displays-list>
                                <span v-else class="text-muted small">—</span>
                            </td>

                            <td v-show="colVisible.attacks" class="dt-td" @click.stop>
                                <attack-display-list
                                    :initial-attacks="rule.attacks || []"
                                    :max-visible="2">
                                </attack-display-list>
                            </td>

                            <td v-show="colVisible.created" class="dt-td"
                                style="white-space:nowrap;font-size:.78rem;">
                                {{ formatDate(rule.creation_date) }}
                            </td>

                            <td v-show="colVisible.votes" class="dt-td">
                                <div class="rl-vote-row">
                                    <button class="rl-vote-btn rl-vote-btn--up"
                                            :class="{ 'rl-vote-disabled': !canVote, 'rl-vote-btn--active-up': rule.user_vote === 'up' }"
                                            :title="canVote ? 'Upvote' : 'Login to vote'"
                                            @click.stop="handleVote('up', rule)">
                                        <i class="fas fa-thumbs-up"></i>
                                        <span>{{ rule.vote_up }}</span>
                                    </button>
                                    <button class="rl-vote-btn rl-vote-btn--down"
                                            :class="{ 'rl-vote-disabled': !canVote, 'rl-vote-btn--active-down': rule.user_vote === 'down' }"
                                            :title="canVote ? 'Downvote' : 'Login to vote'"
                                            @click.stop="handleVote('down', rule)">
                                        <i class="fas fa-thumbs-down"></i>
                                        <span>{{ rule.vote_down }}</span>
                                    </button>
                                </div>
                            </td>

                            <td class="dt-td dt-td--actions">
                                <div class="dt-actions">
                                    <!-- Favori : toujours visible -->
                                    <button v-if="canFavorite"
                                            class="dt-action-btn"
                                            :class="{ 'rl-fav-active': rule.is_favorited }"
                                            :title="rule.is_favorited ? 'Remove from favorites' : 'Add to favorites'"
                                            @click.stop="handleFavorite(rule)">
                                        <i class="fa-star" :class="rule.is_favorited ? 'fas' : 'far'"></i>
                                    </button>

                                    <!-- Dropdown secondaire -->
                                    <div class="rl-action-dropdown" @click.stop>
                                        <button class="dt-action-btn rl-action-dropdown-toggle" title="More actions">
                                            <i class="fas fa-ellipsis-v" style="font-size:.7rem;"></i>
                                        </button>
                                        <div class="rl-action-menu">
                                            <a :href="'/rule/detail_rule/' + rule.id"
                                               class="rl-action-item">
                                                <i class="fas fa-eye"></i> View
                                            </a>
                                            <template v-if="currentUserIsAuthenticated">
                                                <report-modal
                                                    object-type="rule"
                                                    :object-id="rule.id"
                                                    :object-label="rule.title"
                                                    :csrf-token="csrfToken">
                                                    <template #trigger="{ open }">
                                                        <button class="rl-action-item rl-action-item--muted" @click.stop="open">
                                                            <i class="fas fa-flag"></i> Report
                                                        </button>
                                                    </template>
                                                </report-modal>
                                            </template>
                                            <template v-if="numericCurrentUserId && (isOwner(rule) || currentUserIsAdmin)">
                                                <div class="rl-action-divider"></div>
                                                <a :href="'/rule/edit_rule/' + rule.id"
                                                   class="rl-action-item">
                                                    <i class="fas fa-pencil"></i> Edit
                                                </a>
                                            </template>
                                            <template v-if="numericCurrentUserId && (isOwner(rule) || currentUserIsAdmin)">
                                                <button class="rl-action-item rl-action-item--danger"
                                                        @click="$emit('delete', rule)">
                                                    <i class="fas fa-trash"></i> Delete
                                                </button>
                                            </template>
                                        </div>
                                    </div>

                                    <!-- Expand : toujours en dernier -->
                                    <button class="dt-action-btn dt-action-btn--expand"
                                            :class="{ 'is-expanded': expandedIds.has(rule.id) }"
                                            title="Expand" @click="toggleExpand(rule)">
                                        <i class="fas fa-chevron-down dt-expand-chevron"
                                           style="font-size:.65rem;"></i>
                                    </button>
                                </div>
                            </td>
                        </tr>

                        <!-- Expanded row -->
                        <tr v-if="expandedIds.has(rule.id)"
                            :key="'expand-' + rule.id" class="dt-row-expand">
                            <td :colspan="tableColspan" class="dt-expand-cell p-0">
                                <div class="rl-expand-wrap">

                                    <!-- ⓪ Test report (only when showTestResults) -->
                                    <div v-if="showTestResults && rule.test_result" class="rl-expand-test-report">
                                        <div class="rl-expand-test-report__title">
                                            <i class="fa-solid fa-flask-vial"></i>
                                            <span>Test report</span>
                                            <span class="ms-auto badge" :class="rule.test_result.matched ? 'bg-success' : (rule.test_result.error ? 'bg-danger' : 'bg-secondary')">
                                                {{ rule.test_result.matched ? 'MATCHED' : (rule.test_result.error ? 'ERROR' : 'NO MATCH') }}
                                            </span>
                                            <span v-if="rule.test_result.score!=null" class="badge bg-dark">
                                                {{ Math.round((rule.test_result.score||0)*100) }}%
                                            </span>
                                            <span v-if="rule.test_result.execution_time_ms!=null" class="badge bg-dark">
                                                {{ rule.test_result.execution_time_ms }}ms
                                            </span>
                                        </div>
                                        <div v-if="rule.test_result.error" class="rtr-hints px-0">
                                            <div class="rtr-hint-item">
                                                <i class="fa-solid fa-circle-exclamation rtr-hint-icon" style="color:#dc3545;"></i>
                                                {{ rule.test_result.error }}
                                            </div>
                                        </div>
                                        <yara-match-detail v-if="rule.format==='yara'"
                                            :details="rule.test_result.details || {}"
                                            :quality-hints="rule.test_result.quality_hints || []"
                                            :test-input="testInput">
                                        </yara-match-detail>
                                        <div v-else-if="rule.test_result.quality_hints && rule.test_result.quality_hints.length" class="rtr-hints px-0">
                                            <div v-for="hint in rule.test_result.quality_hints" :key="hint" class="rtr-hint-item">
                                                <i class="fa-solid fa-lightbulb rtr-hint-icon"></i>{{ hint }}
                                            </div>
                                        </div>
                                        <p v-if="matchedHighlightTerms(rule).length" class="mb-0" style="font-size:.72rem;color:var(--subtle-text-color);">
                                            <i class="fa-solid fa-arrow-right me-1"></i>The matched bytes are highlighted in blue in the rule content, on the right.
                                        </p>
                                    </div>

                                    <!-- ① Meta strip -->
                                    <div class="rl-expand-meta">
                                        <div class="rl-expand-kv">
                                            <span class="rl-expand-k">Author</span>
                                            <span class="rl-expand-v">{{ rule.author && rule.author !== 'Unknown' ? rule.author : '—' }}</span>
                                        </div>
                                        <div class="rl-expand-kv" @click.stop>
                                            <span class="rl-expand-k">Editor</span>
                                            <span class="rl-expand-v">
                                                <user-chip
                                                    :user-id="rule.user_id"
                                                    :username="rule.editor"
                                                    :avatar="rule.editor_avatar"
                                                    size="xs">
                                                </user-chip>
                                            </span>
                                        </div>
                                        <div class="rl-expand-kv">
                                            <span class="rl-expand-k">Format</span>
                                            <span class="rl-expand-v">
                                                <span v-if="rule.is_code_format" class="badge bg-danger me-1"
                                                      title="Executable code, not a declarative detection rule">
                                                    <i class="fa-solid fa-code me-1"></i>CODE
                                                </span>
                                                <span v-if="rule.format" class="badge rounded-pill bg-dark">
                                                    {{ rule.format.toUpperCase() }}
                                                </span>
                                                <span v-else>—</span>
                                            </span>
                                        </div>
                                        <div class="rl-expand-kv">
                                            <span class="rl-expand-k">License</span>
                                            <span class="rl-expand-v">
                                                {{ rule.license && rule.license !== 'Unknown' ? rule.license : 'No license' }}
                                            </span>
                                        </div>
                                        <div class="rl-expand-kv">
                                            <span class="rl-expand-k">Version</span>
                                            <span class="rl-expand-v">
                                                <span class="badge text-bg-light border px-1">
                                                    {{ rule.version && rule.version !== 'Unknown' ? rule.version : '1.0' }}
                                                </span>
                                            </span>
                                        </div>
                                        <div class="rl-expand-kv">
                                            <span class="rl-expand-k">Created</span>
                                            <span class="rl-expand-v">{{ formatDate(rule.creation_date) }}</span>
                                        </div>
                                        <div class="rl-expand-kv">
                                            <span class="rl-expand-k">Modified</span>
                                            <span class="rl-expand-v">{{ fromNow(rule.last_modif) }}</span>
                                        </div>
                                        <div class="rl-expand-kv" :title="'Rule id: ' + rule.id">
                                            <span class="rl-expand-k">ID</span>
                                            <span class="rl-expand-v" v-html="highlight('' + rule.id)"></span>
                                        </div>
                                        <div class="rl-expand-kv" :title="rule.uuid">
                                            <span class="rl-expand-k">UUID</span>
                                            <span class="rl-expand-v" v-html="highlight(rule.uuid)"></span>
                                        </div>
                                        <div v-if="rule.original_uuid && rule.original_uuid !== 'Unknown' && rule.original_uuid !== rule.uuid"
                                             class="rl-expand-kv" :title="rule.original_uuid">
                                            <span class="rl-expand-k">Original UUID</span>
                                            <span class="rl-expand-v" v-html="highlight(rule.original_uuid)"></span>
                                        </div>
                                        <div v-if="rule.source" class="rl-expand-kv rl-expand-kv--source">
                                            <span class="rl-expand-k">
                                                <i class="fas fa-link me-1"></i>Source
                                            </span>
                                            <a :href="rule.source" target="_blank" rel="noreferrer"
                                               class="rl-expand-v text-primary rl-expand-source-link">
                                                {{ rule.source }}
                                            </a>
                                        </div>
                                    </div>

                                    <!-- ② Description -->
                                    <div v-if="rule.description" class="rl-expand-desc">
                                        <span class="rl-expand-k">
                                            <i class="fas fa-quote-left me-1 opacity-50"></i>Description
                                        </span>
                                        <p class="mb-0 text-muted" style="font-size:.83rem;line-height:1.5;">
                                            {{ rule.description }}
                                        </p>
                                    </div>

                                    <!-- ③ Tags + CVEs (left) / Code (right) -->
                                    <div class="rl-expand-bottom">
                                        <div class="rl-expand-taxonomy" @click.stop>
                                            <div class="rl-expand-taxonomy-section">
                                                <span class="rl-expand-k mb-1">
                                                    <i class="fas fa-tags text-primary me-1"></i>Tags
                                                </span>
                                                <tags-displays-list object-type="rule" :object-id="rule.id"
                                                    :max-visible="15"
                                                    :initial-tags="rule.tags || []">
                                                </tags-displays-list>
                                            </div>
                                            <div v-if="rule.cves && rule.cves.length"
                                                 class="rl-expand-taxonomy-section mt-2">
                                                <span class="rl-expand-k mb-1">
                                                    <i class="fas fa-shield-virus text-danger me-1"></i>CVEs
                                                </span>
                                                <vulnerability-displays-list object-type="rule"
                                                    :object-id="rule.id" :max-visible="8"
                                                    :initial-vulnerabilities="rule.cves">
                                                </vulnerability-displays-list>
                                            </div>
                                            <div v-if="rule.attacks && rule.attacks.length"
                                                 class="rl-expand-taxonomy-section mt-2">
                                                <span class="rl-expand-k mb-1">
                                                    <i class="fa-solid fa-crosshairs text-warning me-1"></i>ATT&amp;CK
                                                </span>
                                                <attack-display-list
                                                    :initial-attacks="rule.attacks"
                                                    :max-visible="20">
                                                </attack-display-list>
                                            </div>
                                        </div>

                                        <div class="rl-expand-code">
                                            <code-viewer v-if="rule.to_string"
                                                :code="rule.to_string"
                                                :language="ruleLanguage(rule.format)"
                                                :title="rule.title"
                                                :initial-search="searchField === 'content' ? search : ''"
                                                :extra-highlights="showTestResults ? matchedHighlightTerms(rule) : []"
                                                :word-wrap="true"
                                                max-height="300px">
                                            </code-viewer>
                                            <div v-else
                                                 class="rl-expand-no-content text-muted small fst-italic">
                                                No content available.
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

        <!-- ── Footer: pagination + per-page (card) + count ── -->
        <div v-if="!loading && items.length > 0" class="rl-footer">
            <div v-if="viewMode === 'card'" class="rl-per-page">
                <span>Per page</span>
                <select v-model="perPageModel" aria-label="Items per page">
                    <option v-for="n in [6, 12, 24, 48]" :key="n" :value="n">{{ n }}</option>
                </select>
            </div>
            <div v-else style="width:1px;"></div>

            <div style="flex-grow:1;display:flex;justify-content:center;">
                <pagination-component
                    :current-page="page"
                    :total-pages="totalPages"
                    @change-page="goToPage">
                </pagination-component>
            </div>

            <div class="rl-footer-info">{{ footerInfo }}</div>
        </div>

        <!-- ── Bulk bar (sticky bottom) ── -->
        <transition name="rl-bulk-slide">
            <div v-if="showBulkBar" class="rl-bulk-bar">
                <span class="rl-bulk-count">
                    {{ selectionCount }} {{ selectionCount === 1 ? 'rule' : 'rules' }} selected
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
        const page         = ref(Number(_p('page', '1')) || 1)
        const _cardDefault = props.initialPerPage === 12
            ? (Number(localStorage.getItem('rz-per-page-card')) || 12)
            : props.initialPerPage
        const cardPerPage   = ref(Number(_p('per_page', String(_cardDefault))) || _cardDefault)
        const _tableDefault = props.initialPerPage === 12
            ? (Number(localStorage.getItem('rz-per-page-table')) || 25)
            : props.initialPerPage
        const tablePerPage  = ref(_tableDefault)
        const sortKey      = ref(_p('sort', props.initialSort))
        const sortDir      = ref(_p('dir', props.initialDir))

        // Active per-page depends on the current view (set after viewMode is declared)
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
        const search           = ref(_p('search', init.search || ''))
        const searchField      = ref(_p('search_field', init.search_field || 'all'))
        const exactMatch       = ref(_p('exact_match') === 'true' || init.exact_match === 'true' || false)
        const ruleType         = ref(_p('rule_type', init.format || ''))
        const selectedTags     = ref(_arr('tags',            init.tags || ''))
        const selectedSources  = ref(_arr('sources',         init.sources || ''))
        const selectedLicenses = ref(_arr('licenses',        init.licenses || ''))
        const selectedVulns    = ref(_arr('vulnerabilities', init.vulnerabilities || ''))
        const selectedAttacks  = ref(_arr('attacks',         init.attacks         || ''))
        const personFilter     = ref({
            mode:   _p('person_mode', 'author'),
            values: _arr(_url.has('editors') ? 'editors' : 'authors'),
        })
        const scopeMine        = ref(_p('scope') === 'mine')
        const cveOnly           = ref(props.hasCveOnly || _p('has_cve') === 'true')
        const rulesFormats    = ref([])

        // Card sort shorthand (maps to sortKey/sortDir)
        const cardSort = ref('newest')

        // ── UI state ──────────────────────────────────────────────────────
        const _defaultView = props.defaultView !== 'card'
            ? props.defaultView
            : (localStorage.getItem('rz-list-view') || 'card')
        const viewMode    = ref(_p('view', _defaultView))
        const _hasUrlFilters = ['tags','sources','licenses','vulnerabilities','attacks','authors','editors',
                                'rule_type','search_field','exact_match','person_mode','scope']
                               .some(k => _url.has(k))
        const filtersOpen = ref(_hasUrlFilters)
        const expandedIds = reactive(new Set())

        // ── Column visibility (table mode) ────────────────────────────────
        const TOGGLEABLE_COLS = [
            { key: 'id',          label: 'ID' },
            { key: 'format',      label: 'Format' },
            { key: 'editor',      label: 'Editor' },
            { key: 'description', label: 'Description' },
            { key: 'tags',        label: 'Tags' },
            { key: 'cves',        label: 'CVEs' },
            { key: 'attacks',     label: 'ATT&CK' },
            { key: 'created',     label: 'Created' },
            { key: 'votes',       label: 'Votes' },
        ]
        const colVisible = Vue.reactive(Object.fromEntries(TOGGLEABLE_COLS.map(c => [c.key, !props.hiddenColumns.includes(c.key)])))
        function toggleColumn(key) { colVisible[key] = !colVisible[key] }

        // ── Selection ─────────────────────────────────────────────────────
        const selectedIds       = reactive(new Set())
        const selectedRulesMap  = reactive(new Map()) // id → {id, title, format}
        const showAllPicked     = ref(false)
        const allPagesSelected = ref(false)

        let searchTimer = null

        // ── Helpers ───────────────────────────────────────────────────────
        const numericUserId = computed(() =>
            props.userId !== null && props.userId !== '' ? Number(props.userId) : null
        )

        const numericCurrentUserId = computed(() =>
            props.currentUserId !== null && props.currentUserId !== ''
                ? Number(props.currentUserId) : null
        )

        function isOwner(rule) {
            return numericCurrentUserId.value !== null &&
                   numericCurrentUserId.value === rule.user_id
        }

        function isFilterHidden(key) {
            return props.hiddenFilters.includes(key)
        }

        function onPersonFilterChange(payload) {
            personFilter.value = payload
            onFilterChange()
        }

        const activeFilterCount = computed(() =>
            (!isFilterHidden('format') && ruleType.value ? 1 : 0) +
            (!isFilterHidden('exact_match') && exactMatch.value ? 1 : 0) +
            (!isFilterHidden('search_field') && searchField.value !== 'all' ? 1 : 0) +
            (scopeMine.value ? 1 : 0) +
            (isFilterHidden('tags') ? 0 : selectedTags.value.length) +
            (isFilterHidden('sources') ? 0 : selectedSources.value.length) +
            (isFilterHidden('licenses') ? 0 : selectedLicenses.value.length) +
            (isFilterHidden('vulnerabilities') ? 0 : selectedVulns.value.length) +
            (isFilterHidden('attacks') ? 0 : selectedAttacks.value.length) +
            (isFilterHidden('person') ? 0 : personFilter.value.values.length)
        )

        // ── URL sync ──────────────────────────────────────────────────────
        // Start from the current params so external ones (e.g. ?url=...) are preserved.
        function syncToUrl() {
            if (!props.syncUrl) return
            const p = new URLSearchParams(window.location.search)

            const _upd = (key, val) => val ? p.set(key, val) : p.delete(key)

            _upd('search',       search.value || null)
            _upd('page',         page.value > 1 ? page.value : null)
            _upd('search_field', searchField.value !== 'all' ? searchField.value : null)
            _upd('exact_match',  exactMatch.value ? 'true' : null)
            _upd('rule_type',    ruleType.value || null)
            if (sortKey.value) { p.set('sort', sortKey.value); p.set('dir', sortDir.value) }
            else               { p.delete('sort'); p.delete('dir') }
            _upd('view',    viewMode.value !== props.defaultView ? viewMode.value : null)
            _upd('tags',            selectedTags.value.join(',')    || null)
            _upd('sources',         selectedSources.value.join(',') || null)
            _upd('licenses',        selectedLicenses.value.join(',')|| null)
            _upd('vulnerabilities', selectedVulns.value.join(',')   || null)
            _upd('attacks',         selectedAttacks.value.join(',') || null)
            if (personFilter.value.values.length) {
                const pKey = personFilter.value.mode === 'editor' ? 'editors' : 'authors'
                p.set(pKey, personFilter.value.values.join(','))
                _upd('person_mode', personFilter.value.mode !== 'author' ? personFilter.value.mode : null)
            } else {
                p.delete('authors'); p.delete('editors'); p.delete('person_mode')
            }
            _upd('scope', scopeMine.value ? 'mine' : null)

            const qs = p.toString()
            history.replaceState(null, '', qs ? `?${qs}` : window.location.pathname)
        }

        // ── Fetch ─────────────────────────────────────────────────────────
        async function fetchData() {
            loading.value = true
            try {
                const params = new URLSearchParams()
                params.set('page', page.value)
                params.set('per_page', perPage.value)
                if (search.value)                    params.set('search', search.value)
                if (searchField.value !== 'all')     params.set('search_field', searchField.value)
                if (exactMatch.value)                params.set('exact_match', 'true')
                if (ruleType.value)                  params.set('rule_type', ruleType.value)
                if (sortKey.value)                   params.set('sort', sortKey.value)
                if (sortKey.value)                   params.set('dir', sortDir.value)
                if (props.source)                    params.set('source', props.source)
                if (props.ids)                        params.set('ids', Array.isArray(props.ids) ? props.ids.join(',') : props.ids)
                if (numericUserId.value)             params.set('user_id', numericUserId.value)
                else if (scopeMine.value && numericCurrentUserId.value) params.set('user_id', numericCurrentUserId.value)
                if (selectedTags.value.length)       params.set('tags', selectedTags.value.join(','))
                if (selectedSources.value.length)    params.set('sources', selectedSources.value.join(','))
                if (selectedLicenses.value.length)   params.set('licenses', selectedLicenses.value.join(','))
                if (selectedVulns.value.length)      params.set('vulnerabilities', selectedVulns.value.join(','))
                if (selectedAttacks.value.length)    params.set('attacks', selectedAttacks.value.join(','))
                if (cveOnly.value)                    params.set('has_cve', 'true')
                if (personFilter.value.values.length) {
                    const pKey = personFilter.value.mode === 'editor' ? 'editors' : 'authors'
                    params.set(pKey, personFilter.value.values.join(','))
                }

                const sep = props.fetchUrl.includes('?') ? '&' : '?'
                const res = await fetch(`${props.fetchUrl}${sep}${params}`)
                if (!res.ok) return
                const data = await res.json()
                items.value      = data.items ?? []
                total.value      = data.total ?? 0
                totalPages.value = data.total_pages ?? 1
                if (page.value > totalPages.value && totalPages.value > 0) {
                    page.value = totalPages.value
                }
                syncToUrl()
                if (props.highlightUuid) {
                    const target = items.value.find(r => r.uuid === props.highlightUuid)
                    if (target) expandedIds.add(target.id)
                    nextTick(() => {
                        const el = document.getElementById('rl-highlight-target')
                        if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' })
                    })
                }
            } finally {
                loading.value = false
            }
        }

        async function fetchFormats() {
            try {
                const res = await fetch('/rule/get_rules_formats')
                const data = await res.json()
                rulesFormats.value = data.formats || []
            } catch { /* silently skip */ }
        }

        // ── Filter change handlers ────────────────────────────────────────
        function onFilterChange() {
            page.value = 1
            // only reset "select all pages" — individual picks survive the filter change
            allPagesSelected.value = false
            fetchData()
        }

        function resetFilters() {
            // Hidden filters are locked by the parent (e.g. a fixed format) — never clear those.
            if (!isFilterHidden('format'))          ruleType.value       = ''
            if (!isFilterHidden('search_field'))    searchField.value    = 'all'
            if (!isFilterHidden('exact_match'))     exactMatch.value     = false
            scopeMine.value      = false
            if (!isFilterHidden('tags'))            selectedTags.value   = []
            if (!isFilterHidden('sources'))         selectedSources.value = []
            if (!isFilterHidden('licenses'))        selectedLicenses.value = []
            if (!isFilterHidden('vulnerabilities')) selectedVulns.value   = []
            if (!isFilterHidden('attacks'))         selectedAttacks.value = []
            if (!isFilterHidden('person'))          personFilter.value    = { mode: 'author', values: [] }
            onFilterChange()
        }

        // ── Search ────────────────────────────────────────────────────────
        function onSearchInput() {
            clearTimeout(searchTimer)
            searchTimer = setTimeout(() => { page.value = 1; fetchData() }, 360)
        }

        function clearSearch() {
            search.value = ''
            page.value = 1
            fetchData()
        }

        // ── Sort ─────────────────────────────────────────────────────────
        function setSort(key) {
            if (sortKey.value === key) {
                sortDir.value = sortDir.value === 'asc' ? 'desc' : 'asc'
            } else {
                sortKey.value = key
                sortDir.value = 'asc'
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
                newest:     { key: 'creation_date', dir: 'desc' },
                oldest:     { key: 'creation_date', dir: 'asc'  },
                most_likes: { key: 'vote_up',        dir: 'desc' },
                title_asc:  { key: 'title',           dir: 'asc'  },
            }
            const s = map[cardSort.value]
            if (s) { sortKey.value = s.key; sortDir.value = s.dir }
            else   { sortKey.value = ''; sortDir.value = 'asc' }
            page.value = 1
            fetchData()
        }

        // ── Pagination ────────────────────────────────────────────────────
        function goToPage(p) {
            page.value = p
            fetchData()
        }

        // ── Selection ────────────────────────────────────────────────────
        const isSelectable = computed(() =>
            props.mode === 'select' || props.mode === 'manage'
        )

        function isSelected(rule) {
            return allPagesSelected.value || selectedIds.has(rule.id)
        }

        function _mapAdd(rule) {
            selectedRulesMap.set(rule.id, { id: rule.id, title: rule.title, format: rule.format })
        }
        function _mapDel(id) { selectedRulesMap.delete(id) }

        function toggleItem(rule) {
            if (allPagesSelected.value) {
                allPagesSelected.value = false
                items.value.forEach(r => {
                    if (r.id !== rule.id) { selectedIds.add(r.id); _mapAdd(r) }
                })
                return
            }
            if (selectedIds.has(rule.id)) { selectedIds.delete(rule.id); _mapDel(rule.id) }
            else                           { selectedIds.add(rule.id);    _mapAdd(rule) }
        }

        function removeFromSelection(id) {
            selectedIds.delete(id)
            _mapDel(id)
        }

        const allOnPageSelected = computed(() => {
            if (!isSelectable.value || !items.value.length) return false
            return items.value.every(r => selectedIds.has(r.id))
        })

        const someOnPageSelected = computed(() => {
            if (!isSelectable.value) return false
            const n = items.value.filter(r => selectedIds.has(r.id)).length
            return n > 0 && n < items.value.length
        })

        function togglePageSelection() {
            if (allPagesSelected.value) { clearSelection(); return }
            if (allOnPageSelected.value) {
                items.value.forEach(r => { selectedIds.delete(r.id); _mapDel(r.id) })
            } else {
                items.value.forEach(r => { selectedIds.add(r.id); _mapAdd(r) })
            }
        }

        function selectAllPages() {
            allPagesSelected.value = true
            // don't populate map — "all" mode doesn't track individually
        }

        function clearSelection() {
            selectedIds.clear()
            selectedRulesMap.clear()
            allPagesSelected.value = false
            showAllPicked.value = false
        }

        const selectedRulesList = computed(() => [...selectedRulesMap.values()])

        const selectionCount = computed(() =>
            allPagesSelected.value ? total.value : selectedIds.size
        )

        const showSelectBanner = computed(() =>
            isSelectable.value && allOnPageSelected.value && total.value > items.value.length
        )

        const showBulkBar = computed(() =>
            props.mode === 'manage' && (selectedIds.size > 0 || allPagesSelected.value)
        )

        // ── Expand / collapse ─────────────────────────────────────────────

        function toggleExpand(rule) {
            if (expandedIds.has(rule.id)) {
                expandedIds.delete(rule.id)
            } else {
                expandedIds.add(rule.id)
            }
        }

        const allExpanded = computed(() => items.value.length > 0 && items.value.every(r => expandedIds.has(r.id)))

        function expandAll() {
            items.value.forEach(r => expandedIds.add(r.id))
        }

        function collapseAll() {
            expandedIds.clear()
        }

        // ── Vote / favorite ───────────────────────────────────────────────
        function _csrf() { return document.getElementById('csrf_token')?.value ?? '' }

        async function handleVote(type, rule) {
            if (!props.canVote) return
            try {
                const res = await fetch('/rule/vote_rule', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': _csrf() },
                    body: JSON.stringify({ id: rule.id, vote_type: type }),
                })
                const data = await res.json()
                rule.vote_up   = data.vote_up
                rule.vote_down = data.vote_down
                rule.user_vote = data.user_vote ?? null
                emit('vote', { ruleId: rule.id, type })
            } catch { /* ignore */ }
        }

        async function handleFavorite(rule) {
            if (!props.canFavorite) return
            try {
                const res = await fetch(`/rule/favorite/${rule.id}`, {
                    method: 'POST',
                    headers: { 'X-CSRFToken': _csrf() },
                })
                const data = await res.json()
                if (res.ok) {
                    rule.is_favorited = data.is_favorited
                    emit('favorite', { ruleId: rule.id, isFavorited: data.is_favorited })
                }
            } catch { /* ignore */ }
        }

        // ── Bulk ──────────────────────────────────────────────────────────
        // ── Export modal view ──────────────────────────────────────────────
        const exportActionView = ref('main')

        async function _openExportModal(view) {
            exportActionView.value = view
            await nextTick()
            const el = document.getElementById('rl-export-modal')
            if (el) bootstrap.Modal.getOrCreateInstance(el).show()
        }

        async function _bulkDelete(ids) {
            if (ids === 'ALL') {
                create_message('Select specific rules to delete (ALL not supported here).', 'warning')
                return
            }
            try {
                const res  = await fetch('/rule/delete_rule_list', {
                    method:  'POST',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': props.csrfToken },
                    body:    JSON.stringify({ ids }),
                })
                const data = await res.json()
                create_message(data.message, data.toast_class)
                if (res.ok) { clearSelection(); fetchData() }
            } catch (e) {
                create_message('Delete failed.', 'danger')
            }
        }

        function emitBulkAction(action) {
            const ids   = allPagesSelected.value ? 'ALL' : Array.from(selectedIds)
            const count = selectionCount.value

            if (action === 'delete') {
                _bulkDelete(ids)
            } else if (action === 'download') {
                _openExportModal('download')
            } else if (action === 'bundle' || action === 'export') {
                _openExportModal(action === 'bundle' ? 'bundle' : 'main')
            } else {
                emit('bulk-action', { action, ids, count })
                clearSelection()
            }
        }

        function emitSend() {
            const ids = allPagesSelected.value ? 'ALL' : Array.from(selectedIds)
            // Full active filter set — not just format — so "select all matching"
            // actually scopes to what's on screen (search/tags/sources/etc.),
            // not every rule in the database. `format` is kept (not renamed to
            // rule_type) for consumers already reading filters.format.
            // Mirrors _build_rule_query's accepted field names.
            const filters = {
                format:          ruleType.value || null,
                search:          search.value.trim() || null,
                search_field:    searchField.value !== 'all' ? searchField.value : null,
                exact_match:     exactMatch.value || null,
                sources:         selectedSources.value.length  ? selectedSources.value.join(',')  : null,
                licenses:        selectedLicenses.value.length ? selectedLicenses.value.join(',') : null,
                vulnerabilities: selectedVulns.value.length    ? selectedVulns.value.join(',')    : null,
                tags:            selectedTags.value.length     ? selectedTags.value.join(',')     : null,
                editors:         personFilter.value.mode === 'editor' && personFilter.value.values.length
                                     ? personFilter.value.values.join(',') : null,
                authors:         personFilter.value.mode === 'author' && personFilter.value.values.length
                                     ? personFilter.value.values.join(',') : null,
            }
            emit('send', ids, filters)
        }

        // ── Table colspan ─────────────────────────────────────────────────
        const tableColspan = computed(() => {
            let n = 2 // title + actions always visible
            if (isSelectable.value) n++
            if (props.draggable) n++
            if (props.showStatus) n++
            if (props.showTestResults) n++
            for (const col of TOGGLEABLE_COLS) if (colVisible[col.key]) n++
            return n
        })

        // ── Status helpers ────────────────────────────────────────────────
        const STATUS_ORDER  = ['draft', 'testing', 'production', 'deprecated']
        const STATUS_ICONS  = { draft: 'fa-solid fa-pencil', testing: 'fa-solid fa-flask', production: 'fa-solid fa-circle-check', deprecated: 'fa-solid fa-ban' }
        const STATUS_LABELS = { draft: 'Draft', testing: 'Testing', production: 'Production', deprecated: 'Deprecated' }

        function statusIcon(s)  { return STATUS_ICONS[s]  || STATUS_ICONS.draft }
        function statusLabel(s) { return STATUS_LABELS[s] || 'Draft' }

        function canChangeStatus(rule) {
            return numericCurrentUserId.value !== null &&
                   (numericCurrentUserId.value === rule.user_id || props.currentUserIsAdmin)
        }

        async function cycleStatus(rule) {
            const cur  = rule.status || 'draft'
            const next = STATUS_ORDER[(STATUS_ORDER.indexOf(cur) + 1) % STATUS_ORDER.length]
            try {
                const res  = await fetch(`/rule/${rule.id}/status`, {
                    method:  'PATCH',
                    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': _csrf() },
                    body:    JSON.stringify({ status: next }),
                })
                const data = await res.json()
                if (data.success) { rule.status = next; emit('status-change', { ruleId: rule.id, status: next }) }
            } catch { /* ignore */ }
        }

        // ── Footer info ───────────────────────────────────────────────────
        const footerInfo = computed(() => {
            if (total.value === 0) return 'No results'
            const start = (page.value - 1) * perPage.value + 1
            const end   = Math.min(page.value * perPage.value, total.value)
            return `${start}–${end} of ${total.value}`
        })

        // ── Search highlight ──────────────────────────────────────────────
        function highlight(text) {
            if (!text) return ''
            const q = search.value.trim()
            if (!q || q.length < 2) return _esc(text)
            const escaped = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
            return _esc(text).replace(
                new RegExp(escaped.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'),
                m => `<mark class="rl-highlight">${m}</mark>`
            )
        }
        function _esc(s) {
            return String(s)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
        }

        // ── Date formatting ───────────────────────────────────────────────
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

        // ── Rule format → hljs language ───────────────────────────────────
        function ruleLanguage(format) {
            if (!format) return 'auto'
            const map = {
                yara:     'yara',
                sigma:    'yaml',
                suricata: 'text',
                zeek:     'zeek',
                elastic:  'json',
                wazuh:    'xml',
                nova:     'text',
                nse:      'lua',
                crs:      'text',
            }
            return map[format.toLowerCase()] || 'auto'
        }

        // ── Test result: matched bytes → highlight terms for CodeViewer ────
        // Reconstructs "31 F7 40 88 ..." the same way the rule source spells a
        // hex string, so CodeViewer can find and blue-highlight it verbatim.
        function matchedHighlightTerms(rule) {
            const tr = rule.test_result
            const strings = tr && tr.details && tr.details.strings_matched
            if (!strings || !strings.length) return []
            return strings
                .map(s => (s.value_hex ? s.value_hex.match(/.{1,2}/g).join(' ').toUpperCase() : ''))
                .filter(Boolean)
        }

        // Number of strings matched, for the compact badge shown next to Description
        // (card view) and in the Description column (table view) — null when the
        // test result predates per-string tracking (nothing to count).
        function matchedStringCount(rule) {
            const tr = rule.test_result
            const strings = tr && tr.details && tr.details.strings_matched
            return Array.isArray(strings) ? strings.length : null
        }

        // ── Faceted filter context ──────────────────────────────────────────
        // Every sidebar count widget (tags, sources, licenses, CVEs, ATT&CK,
        // author/editor) needs to know about every OTHER currently active
        // filter, so its own counts stay scoped to what's actually visible —
        // otherwise picking format=suricata wouldn't narrow the ATT&CK counts.
        // The backend excludes each widget's own dimension from this context
        // server-side (see parse_facet_filters), so we can safely send the
        // exact same string to all of them.
        const facetContextParams = computed(() => {
            const p = new URLSearchParams()
            if (ruleType.value)               p.set('rule_type', ruleType.value)
            if (search.value.trim())          p.set('search', search.value.trim())
            if (searchField.value !== 'all')  p.set('search_field', searchField.value)
            if (exactMatch.value)             p.set('exact_match', 'true')
            if (selectedTags.value.length)     p.set('tags', selectedTags.value.join(','))
            if (selectedSources.value.length)  p.set('sources', selectedSources.value.join(','))
            else if (props.source)             p.set('sources', props.source)
            if (selectedLicenses.value.length) p.set('licenses', selectedLicenses.value.join(','))
            if (selectedVulns.value.length)    p.set('vulnerabilities', selectedVulns.value.join(','))
            if (selectedAttacks.value.length)  p.set('attacks', selectedAttacks.value.join(','))
            if (personFilter.value.values.length) {
                const pKey = personFilter.value.mode === 'editor' ? 'editors' : 'authors'
                p.set(pKey, personFilter.value.values.join(','))
            } else if (props.authorContext) {
                p.set('authors', props.authorContext)
            }
            return p.toString()
        })

        // ── Export bar ────────────────────────────────────────────────────
        const hasActiveFilters = computed(() =>
            search.value.trim() !== '' ||
            ruleType.value !== '' ||
            selectedTags.value.length > 0 ||
            selectedSources.value.length > 0 ||
            selectedLicenses.value.length > 0 ||
            selectedVulns.value.length > 0 ||
            selectedAttacks.value.length > 0 ||
            personFilter.value.values.length > 0
        )

        // IDs to pass to RuleExportAction:
        //   - null → filter-based export (all pages selected, or filters active but no manual pick)
        //   - array → export exactly those IDs
        const exportRuleIds = computed(() => {
            if (allPagesSelected.value) return null
            if (selectedIds.size > 0) return [...selectedIds]
            return null
        })

        const showExportBar = computed(() =>
            hasActiveFilters.value || selectedIds.size > 0
        )

        const exportTotalRules = computed(() =>
            allPagesSelected.value ? total.value : selectedIds.size || total.value
        )

        // ── Lifecycle ─────────────────────────────────────────────────────
        onMounted(() => {
            fetchData()
            fetchFormats()
        })

        onUnmounted(() => clearTimeout(searchTimer))

        // Re-fetch when switching views (per-page may have changed)
        watch(viewMode, () => { page.value = 1; fetchData() })

        // Auto-expand all items when search field is "content"
        watch(items, (newItems) => {
            if (searchField.value === 'content') {
                newItems.forEach(r => expandedIds.add(r.id))
            }
        })

        watch(searchField, (val) => {
            if (val !== 'content') collapseAll()
        })

        return {
            // Data
            items, total, totalPages, loading, page, perPage, perPageModel,
            sortKey, sortDir, search,
            // Filters
            filtersOpen, ruleType, searchField, exactMatch, cardSort,
            selectedTags, selectedSources, selectedLicenses, selectedVulns, selectedAttacks,
            personFilter, onPersonFilterChange,
            scopeMine,
            rulesFormats, activeFilterCount,
            // UI
            viewMode, expandedIds,
            allExpanded, expandAll, collapseAll,
            // Columns
            TOGGLEABLE_COLS, colVisible, toggleColumn,
            // Selection
            selectedIds, allPagesSelected, isSelectable,
            allOnPageSelected, someOnPageSelected,
            selectionCount, showSelectBanner, showBulkBar,
            selectedRulesList, showAllPicked, removeFromSelection,
            // Computed
            numericUserId, numericCurrentUserId, tableColspan, footerInfo,
            // Methods
            isOwner, isFilterHidden,
            fetchData, onFilterChange, resetFilters,
            onSearchInput, clearSearch,
            setSort, sortIcon, onCardSortChange,
            goToPage,
            isSelected, toggleItem, togglePageSelection, selectAllPages, clearSelection,
            toggleExpand,
            handleVote, handleFavorite,
            emitBulkAction, emitSend,
            fromNow, formatDate, ruleLanguage, highlight, matchedHighlightTerms, matchedStringCount,
            // Status
            statusIcon, statusLabel, canChangeStatus, cycleStatus,
            // Export
            hasActiveFilters, exportRuleIds, showExportBar, exportTotalRules, facetContextParams,
            exportActionView,
        }
    },
}
