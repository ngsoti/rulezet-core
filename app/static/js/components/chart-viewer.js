/*
  chart-viewer.js — Universal ECharts viewer component (Vue 3).

  Props:
    data    Object   Universal JSON: { title, subtitle, categories, series, meta }
    views   Array|String  One or more chart types, e.g. ['line','bar','pie'] or 'line'
    detail  Boolean  If true, enables click-to-detail and adds 'table' tab
    height  String   CSS height (default '420px')

  Requires window.echarts (loaded globally via CDN in base.html).
*/

import { get_theme } from './charts/chart-utils.js';

const VIEW_META = {
    line:    { label: 'Line',    icon: 'fa-chart-line'    },
    area:    { label: 'Area',    icon: 'fa-chart-area'    },
    bar:     { label: 'Bar',     icon: 'fa-chart-column'  },
    'bar-h': { label: 'Horiz.', icon: 'fa-chart-bar'     },
    pie:     { label: 'Pie',     icon: 'fa-chart-pie'     },
    donut:   { label: 'Donut',   icon: 'fa-circle-dot'    },
    scatter: { label: 'Scatter', icon: 'fa-braille'       },
    radar:   { label: 'Radar',   icon: 'fa-spider'        },
    funnel:  { label: 'Funnel',  icon: 'fa-filter'        },
    gauge:   { label: 'Gauge',   icon: 'fa-gauge-high'    },
    treemap: { label: 'Treemap', icon: 'fa-table-cells'   },
    heatmap: { label: 'Heatmap', icon: 'fa-border-all'    },
    table:   { label: 'Table',   icon: 'fa-table'         },
};

/* Lazy-load individual renderers to avoid one large bundle */
const RENDERERS = {};
async function get_renderer(type) {
    if (RENDERERS[type]) return RENDERERS[type];
    const map = {
        line:    () => import('./charts/chart-line.js'),
        area:    () => import('./charts/chart-area.js'),
        bar:     () => import('./charts/chart-bar.js'),
        'bar-h': () => import('./charts/chart-bar-h.js'),
        pie:     () => import('./charts/chart-pie.js'),
        donut:   () => import('./charts/chart-donut.js'),
        scatter: () => import('./charts/chart-scatter.js'),
        radar:   () => import('./charts/chart-radar.js'),
        funnel:  () => import('./charts/chart-funnel.js'),
        gauge:   () => import('./charts/chart-gauge.js'),
        treemap: () => import('./charts/chart-treemap.js'),
        heatmap: () => import('./charts/chart-heatmap.js'),
    };
    if (!map[type]) return null;
    const mod = await map[type]();
    RENDERERS[type] = mod.build_option;
    return mod.build_option;
}

const { defineComponent, ref, computed, watch, onMounted, onBeforeUnmount, nextTick } = Vue;

export default defineComponent({
    name: 'ChartViewer',

    props: {
        data:   { type: Object,           default: () => ({}) },
        views:  { type: [Array, String],  default: 'line'     },
        detail: { type: Boolean,          default: false       },
        height: { type: String,           default: '420px'     },
    },

    emits: ['chart-click'],

    template: `
<div class="cv-root" :style="{ height }">

  <!-- Tabs bar (only when multiple views) -->
  <div v-if="view_list.length > 1" class="cv-tabs">
    <button
      v-for="v in view_list" :key="v"
      class="cv-tab"
      :class="{ 'is-active': active_view === v }"
      @click="switch_view(v)"
      :title="VIEW_META[v] ? VIEW_META[v].label : v"
    >
      <i v-if="VIEW_META[v]" :class="'fas ' + VIEW_META[v].icon"></i>
      <span>{{ VIEW_META[v] ? VIEW_META[v].label : v }}</span>
    </button>
    <div class="cv-tab-spacer"></div>
    <button v-if="active_view !== 'table'" class="cv-action" @click="do_export" title="Export PNG">
      <i class="fas fa-download"></i>
    </button>
  </div>

  <!-- Single-view action bar -->
  <div v-if="view_list.length === 1" class="cv-tabs cv-tabs--single">
    <span v-if="data.title" class="cv-chart-title">{{ data.title }}</span>
    <div class="cv-tab-spacer"></div>
    <button v-if="active_view !== 'table'" class="cv-action" @click="do_export" title="Export PNG">
      <i class="fas fa-download"></i>
    </button>
  </div>

  <!-- Chart canvas -->
  <div class="cv-canvas" ref="canvas_ref">

    <!-- ECharts container -->
    <div ref="chart_el" class="cv-echarts" v-show="active_view !== 'table'"></div>

    <!-- Table view -->
    <div v-if="active_view === 'table'" class="cv-table-wrap">
      <table class="cv-table">
        <thead>
          <tr>
            <th></th>
            <th v-for="cat in (data.categories || [])" :key="cat">{{ cat }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="s in (data.series || [])" :key="s.name">
            <td class="cv-table-label">{{ s.name }}</td>
            <td v-for="(v, i) in (s.values || [])" :key="i">{{ v }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Detail panel -->
    <transition name="cv-slide">
      <div v-if="detail_item" class="cv-detail">
        <button class="cv-detail-close" @click="detail_item = null" title="Close">
          <i class="fas fa-times"></i>
        </button>
        <div class="cv-detail-content">
          <div class="cv-detail-name">{{ detail_item.name }}</div>
          <div class="cv-detail-value">{{ detail_item.value }}<span v-if="data.meta && data.meta.unit" class="cv-detail-unit"> {{ data.meta.unit }}</span></div>
          <div v-if="detail_item.series_name" class="cv-detail-series">{{ detail_item.series_name }}</div>
        </div>
      </div>
    </transition>

  </div>
</div>
    `,

    setup(props, { emit }) {
        const canvas_ref  = ref(null);
        const chart_el    = ref(null);
        const active_view = ref('');
        const detail_item = ref(null);

        let _chart        = null;
        let _ro           = null;   /* ResizeObserver */
        let _mo           = null;   /* MutationObserver (theme) */
        let _ew           = null;   /* ECharts-wait interval */

        /* Build the ordered view list */
        const view_list = computed(() => {
            const raw = Array.isArray(props.views) ? props.views : [props.views];
            const list = [...new Set(raw.filter(v => v && VIEW_META[v]))];
            if (props.detail && !list.includes('table')) list.push('table');
            return list;
        });

        /* ── Init active view ── */
        function init_view() {
            if (!active_view.value && view_list.value.length) {
                active_view.value = view_list.value[0];
            }
        }

        /* ── Render chart ── */
        async function render() {
            if (active_view.value === 'table') {
                if (_chart) { _chart.dispose(); _chart = null; }
                return;
            }
            const el = chart_el.value;
            if (!el) return;

            // ECharts CDN may still be downloading (async tag) — poll until ready
            if (!window.echarts) {
                if (!_ew) {
                    _ew = setInterval(() => {
                        if (window.echarts) {
                            clearInterval(_ew); _ew = null;
                            render();
                        }
                    }, 60);
                }
                return;
            }
            if (_ew) { clearInterval(_ew); _ew = null; }

            const build_option = await get_renderer(active_view.value);
            if (!build_option) return;

            const theme = get_theme();
            // Single-view: title shown in the bar above — strip it from ECharts options
            const chart_data = view_list.value.length === 1
                ? { ...props.data, title: undefined, subtitle: undefined }
                : props.data;
            const option = build_option(chart_data, theme);
            option.backgroundColor = 'transparent';

            if (_chart) {
                _chart.setOption(option, { notMerge: true });
            } else {
                _chart = window.echarts.init(el, null, { renderer: 'canvas' });
                _chart.setOption(option, { notMerge: true });
                _chart.on('click', params => {
                    const item = {
                        name:        params.name  || params.dataIndex,
                        value:       params.value,
                        series_name: params.seriesName,
                    };
                    emit('chart-click', item);
                    if (props.detail) detail_item.value = item;
                });
            }
        }

        async function switch_view(v) {
            active_view.value = v;
            if (v !== 'table') {
                await nextTick();
                render();
            }
        }

        /* ── Export PNG ── */
        function do_export() {
            if (!_chart) return;
            const url = _chart.getDataURL({ type: 'png', pixelRatio: 2, backgroundColor: get_theme().bg_surface });
            const a   = document.createElement('a');
            a.href     = url;
            a.download = (props.data.title || 'chart') + '.png';
            a.click();
        }

        /* ── Observers ── */
        function setup_observers() {
            /* Resize */
            if (window.ResizeObserver && canvas_ref.value) {
                _ro = new ResizeObserver(() => { if (_chart) _chart.resize(); });
                _ro.observe(canvas_ref.value);
            }
            /* Theme change */
            _mo = new MutationObserver(() => render());
            _mo.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });
        }

        /* ── Watchers ── */
        watch(() => props.data, () => render(), { deep: true });

        // `views` can change after mount (e.g. a settings panel switching a
        // single chart's type) without the tab bar being there to drive it
        // via switch_view() — re-sync active_view whenever it falls out of
        // the current view list, so a prop-only view change still renders.
        watch(view_list, (list) => {
            if (!list.includes(active_view.value)) {
                active_view.value = list[0] || '';
                nextTick(() => render());
            }
        });

        /* ── Lifecycle ── */
        onMounted(async () => {
            init_view();
            await nextTick();
            setup_observers();
            render();
        });

        onBeforeUnmount(() => {
            if (_ew)     { clearInterval(_ew); _ew = null; }
            if (_chart)  { _chart.dispose(); _chart = null; }
            if (_ro)     _ro.disconnect();
            if (_mo)     _mo.disconnect();
        });

        return {
            canvas_ref,
            chart_el,
            active_view,
            detail_item,
            view_list,
            VIEW_META,
            switch_view,
            do_export,
        };
    },
});
