/*
  chart-calendar.js — GitHub-style contribution calendar renderer.
  data.calendar_data = [[dateStr, count], ...], data.range = [startDateStr, endDateStr].
  Global daily activity volume only — no per-entry detail (that's what the
  ActivityFeed/LogTable widgets are for).
*/

import { mk_title } from './chart-utils.js';

export function build_option(data, theme) {
    const cal_data = data.calendar_data || [];
    const range    = data.range || [];

    const values = cal_data.map(p => p[1]);
    const max_v  = Math.max(1, ...values);

    return {
        ...mk_title(data, theme),
        tooltip: {
            backgroundColor: theme.bg_surface,
            borderColor:     theme.border,
            borderWidth:     1,
            textStyle:       { color: theme.text_main, fontSize: 12 },
            formatter: p => `${p.data[0]}<br/>${p.data[1] || 0} event${p.data[1] === 1 ? '' : 's'}`,
        },
        visualMap: {
            min: 0,
            max: max_v,
            calculable: true,
            orient: 'horizontal',
            left: 'center',
            bottom: 0,
            itemWidth: 12,
            itemHeight: 80,
            textStyle: { color: theme.text_muted, fontSize: 10 },
            inRange: { color: [theme.bg_body, theme.brand] },
        },
        calendar: {
            top:    data.title ? 56 : 24,
            left:   40,
            right:  20,
            bottom: 48,
            cellSize: ['auto', 15],
            range,
            itemStyle: {
                borderWidth: 3,
                borderColor: theme.bg_surface,
                color: theme.bg_body,
            },
            splitLine: { show: false },
            yearLabel: { show: false },
            dayLabel:  { color: theme.text_muted, fontSize: 10, nameMap: 'en' },
            monthLabel:{ color: theme.text_muted, fontSize: 10, nameMap: 'en' },
        },
        series: [{
            type: 'heatmap',
            coordinateSystem: 'calendar',
            data: cal_data,
        }],
    };
}
