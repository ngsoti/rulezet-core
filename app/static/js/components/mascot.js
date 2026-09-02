// Site-wide "show Rulezy" flag, set server-side in base.html from
// InstanceConfig.mascot_enabled. Cosmetic only — never gates whether an AI
// feature itself runs, only whether the character renders.
export const MASCOT_ENABLED = window.__MASCOT_ENABLED__ !== false
