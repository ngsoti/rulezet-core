/**
 * widgetRegistry.js — maps a widget "type" (stored in the saved layout) to
 * its Vue component and its "add to dashboard" catalog entry (label, icon,
 * default size, default params). Add a new widget type here and it shows
 * up in the picker automatically — nothing else needs to change.
 */
import KpiWidget           from './components/kpiWidget.js'
import ChartWidget         from './components/chartWidget.js'
import StatsRowWidget      from './components/statsRowWidget.js'
import TrendingVulnsWidget from './components/trendingVulnsWidget.js'
import AttackHeatmapWidget from './components/attackHeatmapWidget.js'
import RuleListWidget      from './components/ruleListWidget.js'
import ActivityFeedWidget  from './components/activityFeedWidget.js'
import FormatRaceWidget    from './components/formatRaceWidget.js'
import ActivityCalendarWidget from './components/activityCalendarWidget.js'

const WIDGET_REGISTRY = {
    stats_row: {
        component: StatsRowWidget,
        label: 'Stats Row',
        icon: 'fa-chart-simple',
        defaultSize: { w: 12, h: 2 },
        defaultParams: {},
        singleton: true, // one is enough — it's a full-width strip of every counter
    },
    attack_heatmap: {
        component: AttackHeatmapWidget,
        label: 'ATT&CK Coverage',
        icon: 'fa-crosshairs',
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
        defaultSize: { w: 6, h: 4 },
        defaultParams: { limit: 10 },
        singleton: true,
    },
    chart: {
        component: ChartWidget,
        label: 'Chart',
        icon: 'fa-chart-line',
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
        defaultSize: { w: 6, h: 5 },
        defaultParams: { variant: 'last_rules', limit: 5, view: 'card' },
        // Each variant may only be placed once; the catalog hides this entry
        // entirely once all three are on the board (see dashboard.html).
        variants: ['last_rules', 'last_cves', 'top_rated'],
        variantParam: 'variant',
    },
    activity_feed: {
        component: ActivityFeedWidget,
        label: 'Recent Activity',
        icon: 'fa-clock-rotate-left',
        defaultSize: { w: 6, h: 5 },
        defaultParams: { limit: 8 },
        singleton: true,
    },
    format_race: {
        component: FormatRaceWidget,
        label: 'Format Popularity Race',
        icon: 'fa-flag-checkered',
        defaultSize: { w: 12, h: 6 },
        defaultParams: { speed: 'normal' },
        singleton: true,
    },
    activity_calendar: {
        component: ActivityCalendarWidget,
        label: 'Activity Calendar',
        icon: 'fa-calendar-days',
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
