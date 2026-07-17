/**
 * chartPresets.js — curated dataset+view combinations shown as individual,
 * live-mini-previewed cards in the "Add widget" → Charts submenu. Each one
 * maps straight to a `chart` widget with these exact defaultParams — no
 * "blank chart, configure it yourself" step needed at add-time (you can
 * still fine-tune path/view afterwards via the widget's own settings).
 *
 * Deliberately NOT the full dataset × view cross product (most combinations
 * make no visual sense — a monthly time series as a donut, say) — just the
 * pairings that are actually a good fit for that dataset's shape. A couple
 * of datasets get two sensible alternate views (e.g. formats as bar or
 * rose) since both genuinely work.
 */
export const CHART_PRESETS = [
    { path: 'charts.rules_over_time',       view: 'area',    label: 'Rules Added',                icon: 'fa-chart-area' },
    { path: 'charts.users_over_time',        view: 'line',    label: 'New Users',                  icon: 'fa-chart-line' },
    { path: 'charts.bundles_over_time',      view: 'line',    label: 'Bundles Created',            icon: 'fa-chart-line' },
    { path: 'charts.activity_over_time',     view: 'bar',     label: 'Platform Events',             icon: 'fa-chart-column' },
    { path: 'charts.formats',                view: 'bar-h',   label: 'Rules by Format',            icon: 'fa-chart-bar' },
    { path: 'charts.formats',                view: 'rose',    label: 'Rules by Format (Rose)',     icon: 'fa-sun' },
    { path: 'charts.top_tags',               view: 'bar-h',   label: 'Top Tags',                   icon: 'fa-chart-bar' },
    { path: 'charts.top_tags',               view: 'donut',   label: 'Top Tags (Donut)',           icon: 'fa-circle-dot' },
    { path: 'charts.top_contribs',           view: 'bar-h',   label: 'Top Contributors',            icon: 'fa-chart-bar' },
    { path: 'charts.proposals',              view: 'donut',   label: 'Edit Proposals',              icon: 'fa-circle-dot' },
    { path: 'charts.rule_health',            view: 'donut',   label: 'Rule Health',                 icon: 'fa-circle-dot' },
    { path: 'charts.user_roles',             view: 'pie',     label: 'User Roles',                  icon: 'fa-chart-pie' },
    { path: 'charts.heatmap',                view: 'heatmap', label: 'Activity Heatmap',            icon: 'fa-border-all' },
    { path: 'charts.attack_top_techniques',  view: 'bar-h',   label: 'ATT&CK Top Techniques',       icon: 'fa-crosshairs' },
    { path: 'charts.attack_tactic_coverage', view: 'bar-h',   label: 'ATT&CK Tactic Coverage %',    icon: 'fa-crosshairs' },
    { path: 'charts.attack_tactic_rules',    view: 'bar-h',   label: 'ATT&CK Rules per Tactic',     icon: 'fa-crosshairs' },
    { path: 'charts.attack_covered_donut',   view: 'donut',   label: 'ATT&CK Covered vs Uncovered', icon: 'fa-circle-dot' },
]

export function getPath(obj, path) {
    return path.split('.').reduce((acc, key) => (acc == null ? undefined : acc[key]), obj)
}
