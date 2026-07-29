import "d3-force";
import { N as F, S as A, E as C, T as k, a as N } from "./index-Bzoqf7dC.js";
const _ = 1e4, h = 2e4, b = 0.15 * h;
self.onmessage = (g) => {
  var D, S, t, n;
  if (g.data.source !== "simulation-worker-wrapper") return;
  const { nodes: T, edges: i, options: a, canvasBCR: f } = g.data, u = T.map((e) => {
    const c = new F(e.id, e.data, e.style);
    return c.setCircleRadius(e._circleRadius ?? 10), typeof e.x == "number" && (c.x = e.x), typeof e.y == "number" && (c.y = e.y), typeof e.fx == "number" && (c.fx = e.fx), typeof e.fy == "number" && (c.fy = e.fy), c;
  }), o = new Map(u.map((e) => [e.id, e]));
  (D = a.layout) == null || D.type;
  const { simulation: r, simulationForces: y } = A.initSimulationForces(a, f), d = [];
  for (const e of i) {
    const c = o.get(e.from.id), M = o.get(e.to.id);
    if (c && M) {
      const I = e.style ?? {};
      d.push(new C(e.id, c, M, e.data, I, e.directed));
    }
  }
  r.nodes(u);
  const p = r.force("link");
  p && p.id((e) => e.id).links(d), ((S = a.layout) == null ? void 0 : S.type) === "tree" ? k.registerForcesOnSimulation(
    u,
    d,
    r,
    y,
    a.layout,
    f,
    k
  ) : ((t = a.layout) == null ? void 0 : t.type) === "egoTree" && k.registerForcesOnSimulation(
    u,
    d,
    r,
    y,
    a.layout,
    f,
    N
  );
  let s = a.warmupTicks || h;
  s = s === "auto" ? h : s, s = s - b;
  let m = 0.3;
  r.alphaTarget(m);
  const l = (/* @__PURE__ */ new Date()).getTime();
  let w;
  for (let e = 0; e < s && !((/* @__PURE__ */ new Date()).getTime() - l > _ || (/* @__PURE__ */ new Date()).getTime() - l > a.cooldownTime || x(a, r, m) && (/* @__PURE__ */ new Date()).getTime() - l > a.cooldownTime * 0.15); ++e)
    e % 5 === 0 && (w = E(e, (/* @__PURE__ */ new Date()).getTime() - l, a), postMessage({ type: "tick", progress: w, elapsedTime: (/* @__PURE__ */ new Date()).getTime() - l })), r.tick();
  m = 0, r.alphaTarget(m), r.alpha(1);
  for (let e = 0; e < b && !(x(a, r, m) && (/* @__PURE__ */ new Date()).getTime() - l > a.cooldownTime * 0.15); ++e)
    r.tick(), e % 5 === 0 && (w = E(s + e, (/* @__PURE__ */ new Date()).getTime() - l, a), postMessage({ type: "tick", progress: w, elapsedTime: (/* @__PURE__ */ new Date()).getTime() - l }));
  postMessage({ type: "tick", progress: 1, elapsedTime: (/* @__PURE__ */ new Date()).getTime() - l }), ((n = a.layout) == null ? void 0 : n.type) === "tree" && k.simulationDone(
    u,
    d,
    r,
    a.layout
  ), postMessage({
    type: "done",
    nodes: u.map((e) => e.toDict()),
    edges: d.map((e) => e.toDict())
  });
};
function X(g, T, i, a) {
  var l, w, D, S;
  const f = g.map((t) => {
    const n = new F(t.id, t.getData(), t.getStyle());
    return n.weight = t.weight || 1, n.setCircleRadius(t.getCircleRadius()), typeof t.x == "number" && (n.x = t.x), typeof t.y == "number" && (n.y = t.y), typeof t.fx == "number" && (n.fx = t.fx), typeof t.fy == "number" && (n.fy = t.fy), n;
  }), u = new Map(f.map((t) => [t.id, t]));
  (l = i.layout) == null || l.type;
  const { simulation: o, simulationForces: r } = A.initSimulationForces(i, a), y = [];
  for (const t of T) {
    const n = u.get(t.from.id), e = u.get(t.to.id);
    if (n && e) {
      const c = t.getStyle() ?? {};
      y.push(new C(t.id, n, e, t.getData(), c, t.directed));
    }
  }
  o.nodes(f);
  const d = o.force("link");
  d && d.id((t) => t.id).links(y), (((w = i.layout) == null ? void 0 : w.type) === "tree" || ((D = i.layout) == null ? void 0 : D.type) === "egoTree") && k.registerForcesOnSimulation(
    f,
    y,
    o,
    r,
    i.layout,
    a,
    k
  );
  let p;
  i.warmupTicks === "auto" || i.warmupTicks == null ? p = h : p = i.warmupTicks, p = p - b;
  let s = 0.3;
  o.alphaTarget(s);
  const m = (/* @__PURE__ */ new Date()).getTime();
  for (let t = 0; t < p && !((/* @__PURE__ */ new Date()).getTime() - m > _ || (/* @__PURE__ */ new Date()).getTime() - m > i.cooldownTime || x(i, o, s) && (/* @__PURE__ */ new Date()).getTime() - m > i.cooldownTime * 0.15); ++t)
    o.tick();
  s = 0, o.alphaTarget(s), o.alpha(1);
  for (let t = 0; t < b && !(x(i, o, s) && (/* @__PURE__ */ new Date()).getTime() - m > i.cooldownTime * 0.15); ++t)
    o.tick();
  return ((S = i.layout) == null ? void 0 : S.type) === "tree" && k.simulationDone(
    f,
    y,
    o,
    i.layout
  ), {
    nodes: f,
    edges: y
  };
}
function E(g, T, i) {
  return T / i.cooldownTime;
}
function x(g, T, i) {
  return g.d3AlphaMin > 0 && T.alpha() - i < g.d3AlphaMin;
}
export {
  X as runSimulation
};
