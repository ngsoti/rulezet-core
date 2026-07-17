/*
  chart-rose.js — Nightingale rose (polar area) chart renderer.
  Same data contract as pie/donut: data.categories + data.series[0].values.
  A visually punchier alternative to donut for ranked breakdowns (top tags,
  formats, contributors) where the radius encodes magnitude, not just angle.
*/

import { mk_title, mk_tooltip_item } from './chart-utils.js';

export function build_option(data, theme) {
    const s     = (data.series && data.series[0]) || {};
    const cats  = data.categories || [];
    const vals  = s.values || [];
    const items = cats.map((c, i) => ({
        name:      c,
        value:     vals[i] || 0,
        itemStyle: { color: theme.palette[i % theme.palette.length] },
    }));

    return {
        ...mk_title(data, theme),
        ...mk_tooltip_item(theme),
        legend: {
            data:      cats,
            textStyle: { color: theme.text_muted, fontSize: 11 },
            top:       data.title ? 36 : 8,
            left:      'center',
            icon:      'circle',
            itemWidth:  8,
            itemHeight: 8,
            itemGap:   14,
        },
        series: [{
            name:     s.name || 'Value',
            type:     'pie',
            radius:   ['12%', '70%'],
            center:   ['50%', '58%'],
            roseType: 'area',
            data:     items,
            label: {
                color:     theme.text_muted,
                fontSize:  11,
                formatter: '{b}\n{d}%',
            },
            labelLine: { lineStyle: { color: theme.border } },
            itemStyle: {
                borderRadius: 6,
                borderColor:  theme.bg_surface,
                borderWidth:  2,
            },
            emphasis: {
                itemStyle: { shadowBlur: 12, shadowColor: 'rgba(0,0,0,.3)' },
            },
        }],
    };
}
