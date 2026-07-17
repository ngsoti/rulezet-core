/**
 * widgetRegistry.js — maps a widget "type" (stored in the saved layout) to
 * its Vue component and its "add to dashboard" catalog entry (label, icon,
 * description, default size, default params). Add a new widget type here
 * and it shows up in the picker automatically — nothing else needs to
 * change. `category` places it in the right "Add widget" submenu; see
 * CATEGORIES below for the top-level grouping.
 */
import KpiWidget              from './components/kpiWidget.js'
import ChartWidget            from './components/chartWidget.js'
import StatsRowWidget         from './components/statsRowWidget.js'
import TrendingVulnsWidget    from './components/trendingVulnsWidget.js'
import AttackHeatmapWidget    from './components/attackHeatmapWidget.js'
import RuleListWidget         from './components/ruleListWidget.js'
import ActivityFeedWidget     from './components/activityFeedWidget.js'
import FormatRaceWidget       from './components/formatRaceWidget.js'
import ActivityCalendarWidget from './components/activityCalendarWidget.js'

// Top-level "Add widget" categories, in display order. `key` matches each
// registry entry's `category` field.
export const CATEGORIES = [
    { key: 'overview', label: 'Overview',   icon: 'fa-gauge-high',         description: 'Platform-wide counters at a glance.' },
    { key: 'charts',   label: 'Charts',     icon: 'fa-chart-line',         description: 'Pick a dataset + chart type — added ready to go.' },
    { key: 'attack',   label: 'ATT&CK',     icon: 'fa-crosshairs',         description: 'MITRE ATT&CK technique coverage.' },
    { key: 'security', label: 'Security',   icon: 'fa-bug',                description: 'Vulnerabilities tracked across your rules.' },
    { key: 'rules',    label: 'Rules',      icon: 'fa-shield-halved',      description: 'Curated rule lists — newest, riskiest, best-rated.' },
    { key: 'activity', label: 'Activity',   icon: 'fa-clock-rotate-left',  description: 'Community activity over time.' },
]

// rule_list is one widget type with 3 variants — each gets its own catalog
// card (like a separate widget) so it can be added/hidden independently.
export const RULE_LIST_VARIANTS = {
    last_rules: { label: 'Last Rules', icon: 'fa-shield-halved', description: 'Most recently added rules, newest first.' },
    last_cves:  { label: 'Last CVEs',  icon: 'fa-bug',           description: 'Recently added rules that reference at least one CVE.' },
    top_rated:  { label: 'Top Rated',  icon: 'fa-star',          description: 'Rules ranked by community upvotes.' },
}

const WIDGET_REGISTRY = {
    stats_row: {
        component: StatsRowWidget,
        label: 'Stats Row',
        icon: 'fa-chart-simple',
        description: 'One full-width strip with every key platform counter — rules, CVEs, tags, bundles, users, comments.',
        category: 'overview',
        defaultSize: { w: 12, h: 2 },
        defaultParams: {},
        singleton: true, // one is enough — it's a full-width strip of every counter
    },
    attack_heatmap: {
        component: AttackHeatmapWidget,
        label: 'ATT&CK Coverage',
        icon: 'fa-crosshairs',
        description: 'Same rendering as the full ATT&CK heatmap page — tactic columns, technique chips, click for a rule breakdown.',
        category: 'attack',
        // Same rich rendering as the full /attack/heatmap page (stats bar,
        // legend, matrix, detail panel) — needs real room, not a small tile.
        defaultSize: { w: 12, h: 9 },
        defaultParams: {},
        singleton: true,
    },
    trending_vulns: {
        component: TrendingVulnsWidget,
        label: 'Trending Vulnerabilities',
        icon: 'fa-bug',
        description: 'Most-referenced CVEs across your rules, as a proportional bar list — click one to filter the rules list.',
        category: 'security',
        defaultSize: { w: 6, h: 4 },
        defaultParams: { limit: 10 },
        singleton: true,
    },
    chart: {
        component: ChartWidget,
        label: 'Chart',
        icon: 'fa-chart-line',
        description: 'Pick any dataset and chart type yourself — for anything not covered by the curated presets.',
        category: 'charts',
        defaultSize: { w: 6, h: 4 },
        defaultParams: {
            endpoint: '/platform/insights_data', path: 'charts.rules_over_time', view: 'area',
        },
        // Not a singleton — the whole point is being able to drop several
        // charts side by side, each pointed at a different dataset.
    },
    rule_list: {
        component: RuleListWidget,
        label: 'Rule List',
        icon: 'fa-shield-halved',
        category: 'rules',
        defaultSize: { w: 6, h: 5 },
        defaultParams: { variant: 'last_rules', limit: 5, view: 'card' },
        // Each variant may only be placed once; the catalog hides each one
        // individually once it's on the board — see RULE_LIST_VARIANTS above.
        variants: ['last_rules', 'last_cves', 'top_rated'],
        variantParam: 'variant',
    },
    activity_feed: {
        component: ActivityFeedWidget,
        label: 'Recent Activity',
        icon: 'fa-clock-rotate-left',
        description: 'The same public activity feed as the homepage — who did what, with a link to it.',
        category: 'activity',
        defaultSize: { w: 6, h: 5 },
        defaultParams: { limit: 8 },
        singleton: true,
    },
    format_race: {
        component: FormatRaceWidget,
        label: 'Format Popularity Race',
        icon: 'fa-flag-checkered',
        description: 'Animated bar race of cumulative rules per format, month by month — play/pause included.',
        category: 'activity',
        defaultSize: { w: 12, h: 6 },
        defaultParams: { speed: 'normal' },
        singleton: true,
    },
    activity_calendar: {
        component: ActivityCalendarWidget,
        label: 'Activity Calendar',
        icon: 'fa-calendar-days',
        description: 'GitHub-style contribution calendar of platform activity — switch between month, 3 months, and year.',
        category: 'activity',
        defaultSize: { w: 12, h: 5 },
        defaultParams: { period: 'year' },
        singleton: true,
    },
    // Kept resolvable (so any already-saved layout still renders) but hidden
    // from the "Add widget" catalog — superseded by the Stats Row widget.
    kpi: {
        component: KpiWidget,
        label: 'KPI number',
        icon: 'fa-hashtag',
        defaultSize: { w: 3, h: 2 },
        defaultParams: {
            endpoint: '/platform/insights_data', path: 'kpi.total_rules',
            label: 'Total Rules', icon: 'fa-shield-halved', color: 'blue',
        },
        hidden: true,
    },
}

export default WIDGET_REGISTRY
