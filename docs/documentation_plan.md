# Rulezet — Master Documentation Plan

> **Meta note — read this first, then delete before publishing.**
> This file is the **outline/skeleton** for a full Rulezet documentation site, not the final text.
> It exists so that each chapter can be written independently later while staying consistent.
>
> - **Target output:** a documentation template with a left-hand navigation menu, one page (or
>   collapsible section) per `H1` chapter below. `H2` becomes the in-page sub-navigation / anchor
>   links. `H3` is used inside a section for a checklist or a code/technical breakdown — it does not
>   need its own menu entry.
> - **Translation:** every chapter is written in English first. The heading structure (H1/H2 order
>   and count) must stay identical across languages so the French version can be generated
>   section-for-section without breaking the menu or cross-links.
> - **Export:** the final template must support "export as report" (PDF/print view) — keep each
>   chapter self-contained (no "as explained above" without a link) so it still reads correctly when
>   exported as a single linear document.
> - **Screenshots:** every feature chapter ends with a `#### Screenshots to capture` checklist. Shoot
>   those first, then write the prose around them — this keeps the writing grounded in what the UI
>   actually shows instead of what we remember it showing.
> - **Tone:** written for someone who understands *general* IT/security concepts but has never used
>   Rulezet — never assume the reader already knows what a "rule format" or "TLP" is; define it once
>   in the Glossary (Appendix A) and link to it the first time a chapter uses it.
> - **Style rule for every future section:** start with *why this exists / what problem it solves*
>   before *what it does*. Never open a chapter with a feature list — open it with the pain point.

---

## How this plan is organized

- **Part I** — Introduction & context (why Rulezet exists, who it's for).
- **Part II** — Feature guide, one chapter per user-facing feature (this is the bulk of the report).
- **Part III** — Technical architecture & developer guide (how the platform is built, how to extend it).
- **Part IV** — Appendices (glossary, roadmap, screenshot master checklist).

Each **Part II** chapter follows the same eight subsections, in the same order, every time:

1. Purpose & Motivation
2. Key Concepts
3. How It Works
4. Use Cases
5. Detailed Capabilities
6. Roles & Permissions
7. Limitations & Things to Watch
8. Screenshots to Capture

Each **Part III** chapter follows a different, developer-oriented five-subsection pattern (see the
Part III preamble). Keep both patterns rigid — that consistency is what will make the final template
navigable and translatable.

---
---

# PART I — Introduction & Context

## 1. Foreword — About CIRCL and the NGSOTI Project

**Purpose of this chapter:** ground the platform in *who built it and why*, before describing what
it does. A reader landing on page one should understand this isn't a hobby project.

- Who CIRCL is: Luxembourg's Computer Incident Response Center — a national/governmental CERT,
  operating trusted tools for the security community (MISP, the MISP taxonomies/galaxy
  knowledge bases, Vulnerability Lookup, and others).
- Rulezet's place in that ecosystem: developed at CIRCL as part of the **NGSOTI** project, aimed at
  giving SOC analysts and detection engineers a shared, trustworthy place to work with detection
  content — the same spirit as MISP, but for detection *rules* instead of threat *indicators*.
- One or two sentences on NGSOTI's broader goal (training the next generation of SOC analysts /
  tooling) — keep this short, it's context, not the subject of the report.
- Link out: CIRCL's site, `rulezet.org`, the GitHub repository, and (roadmap item) the planned
  integration with `vulnerability.circl.lu`.
- Note the project's TLP:CLEAR posture — everything documented here is meant to be shared openly.

#### Screenshots to capture
- CIRCL logo + Rulezet logo side by side (branding slide already exists in `docs/`, reuse it).
- Homepage hero (`/`) as the very first "here's the product" image of the whole report.

---

## 2. The Problem — Why Detection Rule Sharing Is Broken

**Purpose of this chapter:** make the reader feel the pain before showing the solution. This is the
"origin story" — reuse the framing already validated in the CIRCL slide deck (`docs/*.pdf`).

- Detection rules (YARA, Sigma, Suricata, Zeek, …) are the actual, operational output of threat
  detection work — but they live scattered across GitHub repos, blog posts, gists, private Slack
  channels.
- Consequences of that scattering:
  - No single place to search "has someone already written a rule for X".
  - No consistent way to judge whether a rule is *good* — syntactically valid, still relevant,
    actually effective — before trusting it in production.
  - Every team re-solves the same "which format do I even want" and "how do I validate this"
    problems independently.
  - Duplicated effort: the same detection idea gets rewritten in five repos instead of improved
    once, collaboratively, in one place.
- The specific, concrete failure modes to illustrate with an example each:
  - A rule copy-pasted from a blog post that has a silent syntax error.
  - Two near-identical YARA rules maintained separately because nobody knew the other existed
    (this is literally why Rulezet's *similarity detection* feature exists — forward-reference it).
  - A rule that was valid a year ago but nobody owns it anymore, so nobody notices it's stale.
- Land the transition: Rulezet's answer is a *single collaborative repository with validation and
  community review built in*, not just another paste bin for rules.

#### Screenshots to capture
- None strictly required — this chapter is narrative. Optionally: a montage/screenshot of "rules
  scattered across GitHub search results" to visualize the problem (careful with copyright/attribution
  if using real external screenshots).

---

## 3. What Is Rulezet — Vision, Mission, Goals

**Purpose of this chapter:** the elevator pitch, expanded into a real mission statement.

- One-paragraph definition: Rulezet is an open-source, community-driven platform to create, import,
  validate, discuss, and curate cybersecurity detection rules across multiple formats.
- The four goals (reuse and expand the CIRCL deck's "Goal of the platform" slide):
  1. Simplify rule management and collaborative evaluation.
  2. Enable collaborative contribution across organizations, not just within one team.
  3. Reduce the chaos of scattered open-source detection content.
  4. Validate both the *syntax* and (as far as automatable) the *effectiveness* of every rule.
- What Rulezet is **not**: not a SIEM, not a detection engine itself, not a replacement for MISP
  (indicators) — it's the missing layer for the *rules* themselves. Make this distinction explicit,
  readers with a security background will ask.
- High-level capability summary (one line each, each becomes a Part II chapter):
  rule management · validation & similarity · collaborative edit proposals · ownership · bundles ·
  tags/taxonomies · ATT&CK mapping · community discussion & moderation · blog · workspaces ·
  gamification · notifications · rule tester · dashboard · connectors/federation · background jobs ·
  activity log · administration · public API.
- Supported rule formats today: YARA, Sigma, Suricata, Zeek, Wazuh, NSE, CRS, Nova, Elastic,
  "no format" (free text) — framed as *extensible*, forward-reference the Part III chapter on adding
  a new format.

#### Screenshots to capture
- Homepage (`/`) full view.
- The "Recent Rules" / rule list card grid (same shot used in the CIRCL deck's "Tool Demonstration"
  slide is a good reference point).

---

## 4. Audience & How to Use This Documentation

**Purpose of this chapter:** tell different readers where to skip to — this is what makes a long
report actually usable.

- **SOC analyst / detection engineer (end user):** read Part II end to end, skip Part III.
- **Team lead / instance admin:** read Part II, then the Administration chapter closely, then skim
  Part III's architecture overview to understand what they're responsible for operating.
- **Contributor / developer:** skim Part II for context, then read Part III in full — especially the
  "how to add a rule format" and "how to add a job type" chapters, and the coding-conventions chapter
  before opening a pull request.
- **Instance-to-instance integrator (federation):** Part II chapter 21 (Connectors) + Part III's
  architecture overview.
- How the report is meant to be consumed: as a website with a nav menu day-to-day, exportable as a
  single PDF/report when someone needs an offline or formal copy (e.g. onboarding a new analyst,
  handing to a partner organization evaluating Rulezet).
- Note on language: written in English, French translation planned — same structure, so cross-links
  keep working in both.

#### Screenshots to capture
- None — this chapter is pure navigation text.

---

## 5. Core Terminology & Concepts

**Purpose of this chapter:** define the vocabulary once so every later chapter can use it without
re-explaining. Cross-reference the full Glossary (Appendix A) for anything not covered here.

- **Detection rule** — a piece of logic written in a specific *format* that flags something as
  suspicious/malicious when matched against data (a file, a log line, network traffic…).
- **Rule format** — the syntax/engine a rule is written for (YARA for files, Sigma for logs,
  Suricata/Zeek for network traffic, etc.). One paragraph explaining *why* Rulezet supports many
  formats instead of just one (different detection surfaces need different tools).
- **Rule lifecycle vocabulary:** author/owner, version, source, TLP/PAP classification, soft-delete
  vs. permanent delete, trash.
- **Edit proposal** — the PR-style review mechanism: someone proposes a change, the owner/admin
  approves or rejects it.
- **Bundle** — a curated collection of rules (like a "playlist" of detection content).
- **Tag / taxonomy / galaxy** — MISP-standard vocabularies reused for classification (briefly explain
  MISP taxonomies vs. galaxies as concepts, not implementation).
- **ATT&CK technique** — MITRE's framework for describing adversary behavior; how a rule maps to one.
- **Ownership** — every rule has an owning user; explain why that matters (accountability, contact
  point, permission boundary) before the dedicated chapter.
- **Instance / connector / federation** — a "Rulezet instance" is one deployment (e.g. the official
  `rulezet.org`); a *connector* lets one instance pull content from another.
- **Background job** — any operation heavy/slow enough to run asynchronously with progress tracking
  instead of blocking a page load.

#### Screenshots to capture
- None required — optionally a single annotated screenshot of a rule detail page with callouts
  pointing at "format", "owner", "version", "TLP tag" etc., reused as a running reference image.

---
---

# PART II — Feature Guide

> Every chapter below follows the fixed 8-subsection pattern described in the plan header. Where a
> feature has near-zero content for a subsection (e.g. "Limitations" for something simple), keep the
> heading and write one honest sentence rather than deleting it — the structure must stay identical
> across chapters for the template/menu to work and for translation to stay 1:1.

---

## 6. Accounts, Roles & Permissions

#### Purpose & Motivation
- Any collaborative platform needs to know *who* is doing *what* — accountability is what makes
  community-contributed detection content trustworthy at all.
- Explain the three-tier model up front since every later chapter refers back to it: anonymous
  (read-only), authenticated user, admin.

#### Key Concepts
- Anonymous vs. authenticated vs. admin.
- "Owner" of a resource (rule/bundle/proposal/comment) vs. admin — the two roles that can act on it.
- Email verification, API key (used by the public API, chapter 25).

#### How It Works
- Registration → email verification → login flow.
- Profile page: editable identity, API key management, notification preferences link.
- How admin status is granted (out of scope for a normal user — mention it's an operational/admin
  action, cross-reference chapter 24).

#### Use Cases
- A new analyst signs up to start proposing rule improvements.
- A team lead needs an API key to automate rule pulls into their own tooling.
- An admin promotes a trusted long-time contributor.

#### Detailed Capabilities
- Registration, login, password reset, email verification.
- Profile editing (name, avatar, etc.).
- API key generation/rotation.
- Notification preferences (link to chapter 18).
- Public contributor profile / leaderboard entry (link to chapter 17).

#### Roles & Permissions
- Anonymous: browse public rules/bundles/blog, read-only.
- Authenticated: create/vote/comment/favorite/propose edits, manage only their own resources.
- Admin: everything, plus moderation and platform administration (chapter 24).

#### Limitations & Things to Watch
- Account recovery depends on email deliverability — note as an operational dependency.
- No granular roles between "user" and "admin" today (binary) — worth flagging as a known constraint.

#### Screenshots to capture
- Registration form, login form.
- Profile / detail_user page (already the reference layout per project conventions).
- API key section of the profile.

---

## 7. Rule Management — Create, Import, Version

#### Purpose & Motivation
- This is the core object of the entire platform; every other feature exists to make rules better,
  easier to find, or safer to trust.

#### Key Concepts
- Manual creation vs. GitHub import.
- Format-specific validation (see Part III chapter 29 for the technical mechanism).
- Versioning: a rule can be updated, and history is preserved (chapter 12 covers the audit/history
  view in detail — this chapter covers the authoring side).
- Source/original URL field: crediting where a rule came from when imported.

#### How It Works
- Manual path: fill in the create-rule form (title, format, license, source, description, content) →
  validated against the chosen format → saved, default tags (`tlp:clear`, `pap:clear`) auto-attached.
- Import path: point at a GitHub repository → Rulezet walks it, extracts rules per format, validates
  each one → valid rules are created, invalid ones land in the "bad rules" queue (chapter 8) instead
  of silently failing.
- Editing an existing rule you own (or as admin).
- Deleting a rule: soft-delete first (Trash), only an admin can permanently purge (ties into chapter
  15's trust/safety framing).

#### Use Cases
- An analyst writes a new Suricata rule directly from a live incident.
- A team imports their entire existing GitHub rule repository in one operation to bootstrap their
  Rulezet presence.
- An owner updates a rule after a false-positive report from a comment (chapter 14).

#### Detailed Capabilities
- Supported formats list (YARA, Sigma, Suricata, Zeek, Wazuh, NSE, CRS, Nova, Elastic, no-format).
- Bulk GitHub import with per-file/per-rule validation.
- CVE / vulnerability identifier association.
- Favoriting rules, voting up/down.
- Rule detail page: full metadata, code viewer, history, similarity, scope, comments — this chapter
  should link forward to each of those instead of duplicating them.

#### Roles & Permissions
- Anyone authenticated can create a rule.
- Only the owner or an admin can edit/delete it (standard owner/admin guard used everywhere).

#### Limitations & Things to Watch
- Import quality depends entirely on the source repository's structure and the format parser's
  ability to recognize rule boundaries — note this honestly, it's a real constraint, not a bug.
- A rule with no owner (imported before an association existed, or after account deletion) needs a
  documented fallback behavior — check current code behavior before writing this paragraph.

#### Screenshots to capture
- Create-rule form (manual mode) — reuse/update the shot already in `docs/rulezet_create_rule.png`.
- GitHub import flow (`docs/rulezet_import_rules_from_github.png` as a starting reference, screenshot
  the current UI since it may have evolved).
- Rule detail page, full scroll.
- Favorite button in context (`docs/rulezet_favorite_rule.png` as reference).

---

## 8. Rule Validation, Quality & Similarity Detection

#### Purpose & Motivation
- Directly answers the origin-story pain point: "rules may contain syntax errors, and even valid
  ones offer no guarantee of real effectiveness." This chapter is about the safety net.

#### Key Concepts
- "Bad rule" — a rule that failed format validation on import/creation and was quarantined instead of
  silently discarded or silently accepted broken.
- Similarity detection — automatically flags rules that are likely duplicates or near-duplicates of
  each other.

#### How It Works
- Validation happens synchronously at creation/import time (format-specific — see Part III ch. 29).
- A failed rule is stored in the invalid-rule queue with its errors, visible to the submitter/admin
  instead of vanishing.
- Similarity detection runs as a background job (TF-IDF + FAISS + rapidfuzz per the project's tech
  stack) and produces ranked candidate pairs for human review.

#### Use Cases
- A bulk GitHub import brings in 40 rules; 3 fail validation and show up for the importer to fix
  instead of being silently dropped.
- An admin runs a similarity scan across the whole rule base and merges/flags duplicate submissions.

#### Detailed Capabilities
- Bad-rule queue: view, edit-and-resubmit, or discard.
- Similarity scan: trigger, review results, mark pairs as duplicate/not-duplicate.
- Per-rule "similar rules" panel on the detail page.

#### Roles & Permissions
- Any user sees validation errors on their own submissions.
- Similarity administration (triggering platform-wide scans) is admin-only.

#### Limitations & Things to Watch
- Validation checks syntax/structure, not real-world detection efficacy — be explicit that Rulezet
  cannot (yet) tell you a rule *works* against real traffic/malware, only that it's well-formed. This
  honesty matters for credibility.
- Similarity detection is a heuristic — false positives/negatives are expected, it's a review aid, not
  an authority.

#### Screenshots to capture
- Bad-rules queue/summary page.
- A rule's "similar rules" panel.
- Admin similarity-scan trigger/results page.

---

## 9. Collaborative Edit Proposals

#### Purpose & Motivation
- Lets anyone improve a rule they don't own, without giving away direct write access — the
  pull-request model applied to detection content.

#### Key Concepts
- Proposal states: pending, approved, rejected.
- `edit_type` / `change_score` — how a proposal is categorized and how "big" a change it represents.
- Diff view between the current rule content and the proposed content.

#### How It Works
- A non-owner opens "propose edit", writes a change + message, submits.
- The owner (or an admin) reviews a side-by-side diff, discusses via the proposal's own comment
  thread, then approves (applies the change to the live rule) or rejects (with a reason).
- Notifications fire in both directions (submission → owner, decision → submitter) — cross-reference
  chapter 18.

#### Use Cases
- A user spots a false-positive-prone condition and proposes a fix instead of just commenting.
- A rule owner rejects a proposal with a reason, keeping a transparent audit trail of *why*.

#### Detailed Capabilities
- Diff viewer (old vs. new content, using the shared `DiffViewer` component).
- Comment thread scoped to the proposal itself.
- Approval applies the change and stamps history (chapter 12).

#### Roles & Permissions
- Any authenticated user can propose.
- Only the rule's owner or an admin can approve/reject.

#### Limitations & Things to Watch
- Only one proposal's worth of change per review cycle — no merge-conflict handling if two proposals
  land on the same rule at once; document current behavior precisely once verified in code.

#### Screenshots to capture
- Propose-edit form.
- Diff view on a proposal.
- Proposal comment thread.
- Reuse/update `docs/rulezet_propose_edit_rule.png` as a starting reference.

---

## 10. Ownership & Transfer Requests

#### Purpose & Motivation
- Rules need a responsible owner at all times; this feature is the formal, auditable way that
  responsibility changes hands.

#### Key Concepts
- Ownership request (a user asks the current owner/admin for rights).
- Manual/admin-granted transfer (bulk, admin-initiated, bypasses the request flow but is still
  recorded as an approved history entry for audit purposes).
- The `/requests` page: shared between regular users (their own requests) and admins (a
  processing queue) — same URL, different visible sections, deliberately not `/admin/...` so a
  regular user never sees "admin" in a page they routinely use.

#### How It Works
- Request flow: user requests ownership of a specific rule → current owner/admin approves or
  rejects → history entry recorded.
- Manual/bulk flow: an admin selects many rules (optionally filtered) and transfers them to a new
  owner in one background job → an "approved" history entry is auto-created, framed as if the new
  owner had requested it and the admin had approved it, so the audit trail reads consistently
  regardless of which path was used.

#### Use Cases
- A contributor asks to take over a rule whose original author left the project.
- An admin reassigns 150 rules from a departing contributor to a team account in one bulk operation.

#### Detailed Capabilities
- Pending / History / My Requests tabs, each paginated and sortable.
- Manual Ownership (admin-only tab) with filter-aware "select all matching" and rule-count preview.
- Request detail page shows the concerned rule(s) — a single rule directly, or the full list for a
  bulk manual grant.

#### Roles & Permissions
- Any authenticated user: submit and track their own requests.
- Admin only: process others' requests, use Manual Ownership, see the admin processing queue.

#### Limitations & Things to Watch
- Manual bulk transfers are irreversible from the UI (no "undo transfer" button) — note this and
  whatever confirmation safeguard exists.

#### Screenshots to capture
- `/requests` page, regular-user view (no admin panel visible).
- `/requests` page, admin view (Manual Ownership tab visible).
- A request detail page for a single-rule request and for a bulk manual grant.

---

## 11. Bundles — Curated Rule Collections

#### Purpose & Motivation
- Individual rules are the atoms; a bundle is how a coherent, shareable "detection pack" gets
  assembled and distributed (e.g. "all rules for threat actor X", "our team's baseline ruleset").

#### Key Concepts
- Bundle access control (public vs. private/owner-only).
- Bundle structure — a folder-like tree of rules (not just a flat list) for organizing large bundles.
- Verified bundles (an "official" badge, presumably admin-granted).

#### How It Works
- Create a bundle, add rules to it (individually or via the rule selector), optionally arrange them
  into folders with the structure editor.
- View/download counts, voting, comments — bundles get the same community treatment as rules.

#### Use Cases
- A team publishes a "starter kit" bundle for a specific log source.
- A private bundle used internally before being made public once mature.

#### Detailed Capabilities
- Create/edit/delete bundle.
- `BundleRuleSelector` to add rules.
- `BundleStructureEditor` drag-and-drop folder tree.
- Bundle detail page: rule list, structure view, comments, stats.

#### Roles & Permissions
- Owner/admin can edit or delete a bundle.
- Private bundles are visible only to their owner (and admins).

#### Limitations & Things to Watch
- Removing a rule from Rulezet entirely (hard delete) must not leave a dangling reference inside a
  bundle's structure tree — verify and document current cleanup behavior.

#### Screenshots to capture
- Bundle list page.
- Create/edit bundle form.
- Bundle detail page (rule list + structure tree view).

---

## 12. Rule History & Audit Trail (per-rule)

#### Purpose & Motivation
- Complements chapter 9/10 — this is where a reader goes to answer "what happened to this rule over
  time and who did it", independent of which mechanism (edit proposal, manual admin change, ownership
  transfer) caused the change.

#### Key Concepts
- Update history entries vs. the platform-wide activity log (chapter 22 — that one is
  cross-feature/admin-facing, this one is scoped to a single rule's detail page).

#### How It Works
- Every accepted change to a rule's content or ownership appends a history entry, visible on the
  rule's "History" tab.

#### Use Cases
- Understanding why a rule's content differs from what a user remembers importing.
- Verifying an ownership transfer actually happened before escalating a support request.

#### Detailed Capabilities
- Chronological list of content/ownership changes with actor and timestamp.
- Links back to the originating edit proposal or ownership request where applicable.

#### Roles & Permissions
- Visible to anyone who can view the rule (read-only).

#### Limitations & Things to Watch
- History is additive only — there is no way to annotate/correct a past entry after the fact; note
  this as intentional (immutable audit trail) rather than a gap.

#### Screenshots to capture
- Rule detail page, History tab.

---

## 13. Tags, MISP Taxonomies & Galaxies

#### Purpose & Motivation
- Free-text search only goes so far; a shared, standardized vocabulary (the same one MISP uses) lets
  rules be classified consistently across the whole community instead of every team inventing its own
  labels.

#### Key Concepts
- Tag vs. taxonomy vs. galaxy (define precisely — this trips people up): a *taxonomy* is a structured
  vocabulary (e.g. TLP, PAP); a *galaxy* is a knowledge base of clusters (e.g. threat actors, malware
  families); a *tag* is the concrete label attached to a rule/bundle, which may originate from either.
- Default tags: every new rule automatically gets `tlp:clear` and `pap:clear`.

#### How It Works
- Taxonomies/galaxies are imported from the bundled MISP submodules into Rulezet's own tag tables.
- Tag families group related tags visually (e.g. all `tlp:*` tags).
- Tags attach to rules and bundles, with an autocomplete input (`TagInput` component).

#### Use Cases
- Filtering the whole rule base down to `tlp:amber` content only.
- Tagging a rule with a galaxy cluster to associate it with a known threat actor.

#### Detailed Capabilities
- Browse/search all tags, "my tags" view.
- Import a taxonomy or galaxy (and its clusters) from the bundled MISP data.
- Tag visibility/status toggles, bulk removal, family-level removal.

#### Roles & Permissions
- Any user can tag their own resources.
- Importing/removing taxonomies or galaxies platform-wide is admin-only.

#### Limitations & Things to Watch
- Taxonomy/galaxy freshness depends on the bundled submodule's last update — document the update
  mechanism (manual `git submodule update` vs. an in-app refresh) once confirmed.

#### Screenshots to capture
- Tag browser/list page.
- Tag autocomplete input in the rule-create form.
- Admin taxonomy/galaxy import screen.

---

## 14. MITRE ATT&CK Mapping

#### Purpose & Motivation
- Ties detection content to the industry-standard adversary-behavior framework, so coverage can be
  reasoned about ("which techniques do we actually detect for?") instead of rule-by-rule.

#### Key Concepts
- Technique / sub-technique IDs (e.g. `T1068`), tactics.
- Auto-parsing: Rulezet can attempt to extract technique references directly from a rule's own
  content/metadata instead of requiring fully manual tagging.
- Coverage gaps: techniques with no (or very few) associated rules.

#### How It Works
- ATT&CK technique data is fetched/updated from MITRE's STIX feed (background job).
- A rule can have techniques attached manually or via auto-parsing of its content.
- Coverage/gap analytics aggregate this across the whole rule base.

#### Use Cases
- A detection engineer checks which ATT&CK techniques still have zero rules before writing new ones.
- A bulk operation auto-parses ATT&CK references across an entire imported rule set.

#### Detailed Capabilities
- Technique detail page, technique search/autocomplete (`AttackInput`).
- Heatmap / matrix view of coverage (`AttackMatrix`).
- Per-rule technique badges (`AttackDisplay`).
- Coverage & gap analytics.

#### Roles & Permissions
- Any user can tag their own rule's techniques.
- Platform-wide ATT&CK data refresh and bulk auto-parse are admin-only (background jobs).

#### Limitations & Things to Watch
- Auto-parsing accuracy depends on how explicitly a rule's format/content references technique IDs —
  set expectations that manual review is still recommended.

#### Screenshots to capture
- ATT&CK heatmap/matrix page.
- A rule detail page showing attached technique badges.
- Coverage gap analytics view.

---

## 15. Community Discussion — Comments, Reactions & Moderation

#### Purpose & Motivation
- Detection rules improve through scrutiny; this is the mechanism for that scrutiny to happen in the
  open, attached directly to the content it's about.

#### Key Concepts
- Unified comment thread — the same commenting system (with replies and emoji-style reactions) is
  used across rules, bundles, edit proposals, and blog posts, so the experience is identical
  everywhere.
- Reports/flags — a separate, moderation-facing mechanism for surfacing problematic content/comments.
- The Comment Hub — a cross-cutting view for finding "everything being discussed right now" instead
  of hunting per-object.

#### How It Works
- Any authenticated user can comment/reply/react on a rule, bundle, proposal, or blog post.
- A report on any of those raises it into the admin moderation queue.
- Deleting the underlying object (rule/bundle/proposal/blog post) also removes its comment thread —
  note this as a data-hygiene guarantee, not an incidental detail.

#### Use Cases
- A false-positive is reported in a comment thread, prompting an edit proposal (chapter 9).
- An admin resolves a flagged comment for abusive content via the moderation queue.
- A user browses the Comment Hub to catch up on discussion across everything they follow.

#### Detailed Capabilities
- Threaded replies, like/dislike-style reactions.
- "Turn a comment into a GitHub issue" admin action (for tracking real bugs surfaced in discussion).
- Comment Hub: filter by scope, search, date range.
- Report/flag a comment or the underlying object; admin resolve/dismiss/bulk actions.

#### Roles & Permissions
- Any authenticated user: create/edit/delete own comments, react, report.
- Admin: moderate (resolve/dismiss reports), delete any comment.

#### Limitations & Things to Watch
- Comments on a deleted rule/bundle/proposal/blog post are purged, not archived — if an audit need
  ever requires keeping deleted-object comments, that's a deliberate future decision, not today's
  default.

#### Screenshots to capture
- A comment thread on a rule detail page (with a reply and a reaction visible).
- The Comment Hub page.
- Admin moderation/reports queue.

---

## 16. Blog & Knowledge Sharing

#### Purpose & Motivation
- Rules alone don't carry the *why* — a blog post lets the platform host the narrative context
  (a CVE writeup, a campaign analysis) that a set of rules is responding to.

#### Key Concepts
- Draft vs. published (public) posts.
- Associations: a post can link to specific rules, bundles, ATT&CK techniques, and CVE IDs, tying the
  narrative directly to the actionable content.

#### How It Works
- Author drafts a post, attaches relevant rules/bundles/techniques/CVEs, publishes when ready.
- Readers discuss via the same unified comment system as everywhere else (chapter 15).
- A post can be generated as a starting draft from a CVE reference (background job) — an accelerator,
  not a replacement for human writing.

#### Use Cases
- Publishing a "here's what we learned building detection for CVE-2025-XXXXX" writeup with the
  actual rules attached.
- Drafting internally, iterating, then publishing once reviewed.

#### Detailed Capabilities
- Rich content editor, cover image, external links.
- Rule/bundle/technique/CVE association pickers.
- Print-friendly view, admin post list/management.

#### Roles & Permissions
- Any authenticated user can draft; publishing rules mirror the owner/admin pattern.
- Admin has a dedicated management list for all posts.

#### Limitations & Things to Watch
- CVE-based draft generation is a convenience starting point — flag clearly that it needs human
  review before publishing, not an autonomous authoring feature.

#### Screenshots to capture
- Blog list page.
- Create/edit post editor.
- A published post detail page with attached rules/techniques visible.

---

## 17. Personal Workspaces

#### Purpose & Motivation
- An investigation rarely fits neatly into "one rule" or "one bundle" — a workspace is a private,
  flexible scratch space to collect rules, notes, and links while working a case, before anything is
  formalized into a public bundle.

#### Key Concepts
- Workspace documents (freeform notes) and links, alongside a working rule set.
- Workspace KPIs — quick stats about what's inside a given workspace.

#### How It Works
- Create a workspace, add rules to it, attach documents and links, track progress via its KPI panel.
- Distinct from a bundle: a workspace is a personal/team working area, not (necessarily) a published
  artifact.

#### Use Cases
- Collecting every rule relevant to an ongoing incident in one place while triaging it.
- Keeping investigation notes and reference links alongside the rules they relate to.

#### Detailed Capabilities
- Create/update/delete workspace.
- Add/remove rules.
- Documents: create/update/delete freeform notes.
- Links: attach/list external references.
- KPI summary view.

#### Roles & Permissions
- Personal to the creator (and whatever sharing model currently exists — confirm before writing:
  private-by-default vs. team-shared).

#### Limitations & Things to Watch
- Clarify whether a workspace can be converted directly into a bundle, or whether that's a manual
  re-creation today — a natural feature request to anticipate.

#### Screenshots to capture
- Workspace list.
- Workspace detail view (rules + documents + links + KPIs).

---

## 18. Gamification & Leaderboard

#### Purpose & Motivation
- Community platforms live or die on sustained contribution; recognizing effort (points, levels,
  rankings) is the incentive layer that keeps people coming back to review, propose, and own rules.

#### Key Concepts
- Points sources: accepted suggestions, rules owned, likes received, etc., each weighted differently.
- Levels (1–100) computed from accumulated points.
- Global vs. category leaderboards.

#### How It Works
- Actions across the platform (an edit proposal being accepted, a rule being liked, taking ownership)
  award points automatically.
- The leaderboard is paginated, sortable, and searchable by name; a "contributor" profile page shows
  an individual's full breakdown.

#### Use Cases
- A contributor checks their own level/progress on their profile.
- Recognizing the top contributors platform-wide over a period.

#### Detailed Capabilities
- Point categories and their weights (document current values from the model, they may be re-tuned
  over time — flag as "current as of writing").
- Global and category leaderboards with search/sort/pagination.
- Individual contributor page with detailed stats/charts.

#### Roles & Permissions
- Read-only and public by design — anyone can see the leaderboard; points cannot be self-awarded.

#### Limitations & Things to Watch
- Gamification can incentivize quantity over quality (e.g. proposing many trivial edits) — worth a
  short honest note on this trade-off and any safeguard in place (e.g. weighting *accepted*
  suggestions rather than submitted ones).

#### Screenshots to capture
- Global leaderboard page.
- Contributor detail/profile page with charts.

---

## 19. Notifications

#### Purpose & Motivation
- With this many collaborative workflows (proposals, ownership, comments, jobs), users need a single
  place that tells them "something happened that needs your attention" instead of having to poll
  every page.

#### Key Concepts
- Notification types (one per triggering event — proposal submitted/decided, comment/reply, report
  created, ownership requested/granted, job/import completed, similarity scan done, etc.).
- Per-user notification preferences (which types are on/off, and by which channel if more than
  in-app exists — confirm before writing).

#### How It Works
- Any of the triggering actions elsewhere in the platform creates a notification for the relevant
  user(s) (owner, admin, follower).
- The notification bell shows a live unread count and a short recent list; a full page lists/paginates
  everything with read/unread state.

#### Use Cases
- Getting notified the moment someone proposes an edit to a rule you own.
- An admin getting notified when a report is filed, without having to check the queue proactively.

#### Detailed Capabilities
- Bell dropdown (recent items + unread count).
- Full notifications page, mark read, delete.
- Preferences page to control which event types notify.

#### Roles & Permissions
- Personal to each user; admins additionally receive platform-level notifications (reports, failed
  integrations, etc.).

#### Limitations & Things to Watch
- In-app only today (confirm whether email/webhook delivery exists) — note the actual channel(s)
  precisely, this is a common follow-up question from evaluators.

#### Screenshots to capture
- Notification bell dropdown.
- Full notifications page.
- Notification preferences page.

---

## 20. Rule Tester

#### Purpose & Motivation
- A rule that's syntactically valid isn't necessarily a rule that matches anything real — the Rule
  Tester lets a user validate a rule against actual sample data before trusting it.

#### Key Concepts
- Test run vs. test result (a test can be run once and produce many matches).
- Visibility toggle — a user's test can be private or shared.

#### How It Works
- Attach sample data to a rule, run it, review matches, keep notes on the outcome.
- Bulk testing across many rules at once for larger validation efforts.

#### Use Cases
- Confirming a new Suricata rule actually fires against a captured pcap-derived sample before
  publishing it as trusted.
- Bulk-validating an entire imported rule set against a reference dataset.

#### Detailed Capabilities
- Create/run a test, view results and match counts.
- My Tests view (personal history), per-rule test history tab.
- Bulk test workflow.
- Visibility toggle, delete, notes.

#### Roles & Permissions
- Any authenticated user can test rules they can read; deleting/editing visibility is limited to the
  test's creator (or admin).

#### Limitations & Things to Watch
- **This feature is currently suspended in navigation/test history pending re-enablement** (per
  recent project changes) — the documentation must say so plainly rather than describing it as fully
  live, and should be revisited once it's switched back on.

#### Screenshots to capture
- Test creation/run screen.
- Test result/detail view.
- Bulk test screen.
- *(Capture once re-enabled — flag this to whoever schedules the screenshot session.)*

---

## 21. Customizable Dashboard

#### Purpose & Motivation
- Different users care about different signals (a manager wants trend charts, an analyst wants a
  rule list); a fixed homepage can't serve both — a widget dashboard lets each user build their own.

#### Key Concepts
- Widgets (KPI, chart, rule list, ATT&CK heatmap, trending vulnerabilities, activity feed, activity
  calendar, format race, stats row) arranged on a grid layout.
- Layout persistence per user, with a reset-to-default option.

#### How It Works
- Add/remove/resize/rearrange widgets on a grid (drag-and-drop); the layout is saved per user and
  reloaded on next visit.

#### Use Cases
- Building a personal "morning check" dashboard: recent activity, trending CVEs, a KPI row.
- Resetting back to the default layout after experimenting.

#### Detailed Capabilities
- Full widget catalogue (list each of the nine widget types with one line on what it shows).
- Save/reset layout.

#### Roles & Permissions
- Personal to each user; no platform-wide/shared dashboards today (note if that's on the roadmap).

#### Limitations & Things to Watch
- Widget data freshness/refresh cadence varies by widget — document per-widget behavior once
  confirmed, so expectations are set correctly (e.g. "activity feed is live", "trending vulns update
  every N hours").

#### Screenshots to capture
- Full dashboard with a representative widget mix.
- Widget picker/add-widget UI.
- One close-up per widget type (nine small screenshots), or at minimum the more visual ones
  (ATT&CK heatmap widget, activity calendar widget).

---

## 22. Connectors & Federation

#### Purpose & Motivation
- No single Rulezet instance should be an island — connectors let instances (or MISP) share content
  with each other, so a smaller/private deployment can still benefit from a larger community's work.

#### Key Concepts
- Connector — a configured link to another Rulezet instance (or MISP source).
- Pull modes: **soft** (skip anything that already exists locally) vs. **hard** (update existing
  content in place) — matching is done by UUID only, never by name/title.
- Instance telemetry — the official instance phones home every 24h; explicitly *not* enabled on
  self-hosted instances unless configured as official.

#### How It Works
- Admin creates a connector pointing at a remote instance/source, tests connectivity, previews what
  would be pulled, then runs a pull (as a background job, trackable like any other).
- Connector history logs each pull's outcome for auditing.

#### Use Cases
- A private internal Rulezet instance periodically pulling curated content from the public
  `rulezet.org`.
- Importing MISP taxonomy/galaxy tag families through the same connector mechanism (chapter 13).

#### Detailed Capabilities
- Create/update/delete/test a connector.
- Preview before pull.
- Soft/hard pull execution, connector history.
- Tag family import via connector.

#### Roles & Permissions
- Connector management is admin-only, full stop — this is a platform-to-platform trust boundary.

#### Limitations & Things to Watch
- Matching strictly by UUID means content without a stable UUID (e.g. hand-entered content lacking
  one) cannot be synced this way — note this constraint plainly.
- A hard pull can overwrite local edits to synced content — the documentation must warn about this
  explicitly, it's a real risk of data loss if misunderstood.

#### Screenshots to capture
- Connector list page.
- Create-connector form.
- Pull preview screen.
- Connector history/log view.

---

## 23. Background Jobs & Async Operations

#### Purpose & Motivation
- Several operations in this platform are slow by nature (bulk transfers, GitHub imports, similarity
  scans, connector pulls) — running them synchronously would freeze the UI; this feature makes them
  visible, trackable, and safely resumable instead.

#### Key Concepts
- A `BackgroundJob` row with a status (pending/running/paused/completed/failed/cancelled).
- Pause/resume — a job can be paused and later resumed from where it left off, not restarted from
  zero.
- Job logs — a structured, timestamped log attached to each job for troubleshooting.

#### How It Works
- Triggering any heavy operation (import, bulk transfer, connector pull, similarity scan, etc.)
  enqueues a job instead of blocking; a worker thread polls for pending jobs continuously.
- The `JobTracker` UI component shows live progress; the job detail page shows the full log.
- If the server restarts mid-job, the job is automatically recovered back to pending on next startup
  rather than being lost silently.

#### Use Cases
- Watching a 500-rule GitHub import progress live instead of waiting on a blank screen.
- Pausing a large bulk ownership transfer, then resuming it later without redoing already-processed
  rules.

#### Detailed Capabilities
- Job list/detail pages, live progress via `JobTracker`.
- Pause/resume/cancel controls.
- Full current catalogue of job types (bulk tag add/remove, GitHub rule deletion, activity log
  purge, MISP data update, trash restore/purge, connector pull, package/submodule updates, bulk
  ownership transfer, ATT&CK data update/bulk parse, bulk field parse, blog-from-CVE generation, …) —
  list them with one line each rather than deep-diving; this chapter is about the *mechanism*, not
  each job's business logic (each job type's purpose is covered in its own feature chapter).

#### Roles & Permissions
- Most job types are admin-only to trigger (bulk/administrative operations); a user can see and track
  jobs they personally triggered where applicable (e.g. their own GitHub import).

#### Limitations & Things to Watch
- Single worker thread, one job processed at a time by design — document the throughput implication
  for anyone planning very large bulk operations.

#### Screenshots to capture
- Job list page.
- Job detail page mid-run, showing live log + progress.
- Pause/resume controls in action.

---

## 24. Activity Log & Audit Trail (Platform-Wide)

#### Purpose & Motivation
- Complements the per-rule history (chapter 12) with a platform-wide, cross-feature audit trail —
  the answer to "what has been happening on this instance", used mainly by admins.

#### Key Concepts
- Dot-namespaced actions (e.g. `rule.create`, `bundle.delete`) — every significant action anywhere in
  the platform is logged this way.
- Log definitions — configurable metadata (visibility, description) per action type, editable by an
  admin rather than hard-coded.

#### How It Works
- Every feature calls a shared logging utility on significant actions; entries accumulate centrally.
- Admins browse/search/filter the log, adjust which action types are visible in the public activity
  feed, and can bulk-purge old entries (as a background job).

#### Use Cases
- Investigating who deleted a specific bundle and when.
- Tuning which action types show up on the public-facing activity feed vs. admin-only log.

#### Detailed Capabilities
- Searchable/filterable/paginated admin log view.
- Public activity feed (a curated, visibility-filtered subset of the same log).
- Log definitions management (per-action visibility/description).
- Bulk delete of old log entries.

#### Roles & Permissions
- Full log access: admin only.
- Public activity feed: visible to any authenticated (or anonymous, confirm) user, showing only
  actions marked visible.

#### Limitations & Things to Watch
- Retention: logs grow indefinitely unless purged — document the actual purge job's default/typical
  cadence once confirmed, this matters for anyone doing compliance/audit planning.

#### Screenshots to capture
- Admin logs page (search/filter in use).
- Public activity feed.
- Log definitions management screen.

---

## 25. Administration & Platform Settings

#### Purpose & Motivation
- Someone has to run the instance day to day — this chapter is the admin's operational manual inside
  the report, distinct from the feature-specific admin actions already covered per chapter.

#### Key Concepts
- Instance-level configuration vs. per-feature admin actions (this chapter is about the former:
  users, formats, system settings, backups).
- "Official instance" flag — enables instance telemetry (chapter 22) and is only ever true on
  `rulezet.org` itself.

#### How It Works
- Admin-only pages, gated with the project's standard inline per-route admin check (not a
  blueprint-wide gate, since most of these routes live in the general-purpose blueprint alongside
  regular user pages).

#### Use Cases
- Onboarding: creating the first admin account, reviewing system settings before going live.
- Ongoing: managing users, formats, backups, and environment configuration without touching the
  server directly.

#### Detailed Capabilities
- User list/management.
- Rule format management (`FormatRule` catalogue — enable/disable, "can execute" flag).
- Trash (soft-deleted rules) — restore or permanently purge, individually or in bulk.
- System/package/submodule settings, `.env` configuration editing, test-email sending, API key
  generation for the instance itself.
- Backups: list, trigger, download.
- Instance configuration (the official-instance / telemetry toggle and related setup).
- Platform Insights — instance-wide usage analytics/charts (separate from the per-user dashboard,
  chapter 21).

#### Roles & Permissions
- Everything in this chapter is admin-only, without exception.

#### Limitations & Things to Watch
- `.env`/system settings editing from the UI is inherently sensitive — document exactly what is and
  isn't exposed this way, and any safeguard (confirmation, restricted fields) in place.
- Permanent rule purge from Trash is irreversible — repeat the same warning given in chapters 7/8/15
  about hard deletes, consistently, every time it comes up.

#### Screenshots to capture
- User management list.
- Format management page.
- Trash/purge admin view.
- Backups page.
- System/instance settings page.
- Platform Insights analytics page.

---

## 26. Public REST API

#### Purpose & Motivation
- Not every interaction with Rulezet content should require a human clicking through the UI — the API
  is what lets teams automate rule pulls, integrate Rulezet into their own tooling, or build on top of
  it.

#### Key Concepts
- Public vs. private namespaces per feature.
- API key authentication via the `X-API-KEY` header.
- Swagger/interactive docs available directly on the running instance.

#### How It Works
- Generate an API key from your profile (chapter 6).
- Call the relevant namespace's endpoints with the key in the header; browse/exercise them live via
  the built-in Swagger UI at `/api/`.

#### Use Cases
- Pulling the latest public rules into an internal detection pipeline on a schedule.
- Automating bundle creation/updates from an external CI process.

#### Detailed Capabilities
- Rule namespace (public/private).
- Account namespace (public/private).
- Bundle namespace (public/private).
- Any other namespaces present at time of writing — enumerate precisely from the live Swagger docs
  rather than guessing, so this section never goes stale relative to the actual API surface.

#### Roles & Permissions
- Public namespaces: readable with or without a key depending on the resource's own visibility rules.
- Private namespaces: require a valid API key tied to an authenticated account; actions still respect
  the same owner/admin rules as the UI.

#### Limitations & Things to Watch
- No rate limiting mentioned elsewhere in the project docs — confirm current behavior before writing
  a paragraph here, since this is exactly the kind of detail an integrator will ask about first.

#### Screenshots to capture
- Swagger UI landing page (`/api/`).
- One example request/response expanded in Swagger for a representative endpoint (e.g. rule list).

---
---

# PART III — Technical Architecture & Developer Guide

> This part is written for a different reader: someone who wants to **run, extend, or contribute
> code to** Rulezet, not just use it. Each chapter below follows its own five-subsection pattern
> instead of Part II's eight, because the content is inherently more technical:
>
> 1. Purpose & Scope
> 2. Architecture Overview
> 3. Key Files & Entry Points
> 4. Step-by-Step: How To Extend It
> 5. Conventions & Gotchas
>
> Use short code-block excerpts (file path + line reference) rather than full source dumps — the
> report should point precisely at the real source rather than duplicating it, since the source is
> the ground truth and will drift from any copy pasted here.

---

## 27. System Architecture Overview

#### Purpose & Scope
- The one chapter every contributor reads first — the 30,000-foot view that everything else in
  Part III zooms into.

#### Architecture Overview
- Stack: Flask (Blueprints) + Vue.js 3 (UMD build, no bundler/build step, `['[[', ']]']` template
  delimiters to coexist with Jinja) + PostgreSQL (dev/prod) / SQLite (tests).
- Request flow: browser → Flask blueprint route → `*_core.py` business logic → SQLAlchemy models
  (`app/core/db_class/db.py`) → Postgres; JSON responses hydrate Vue components client-side.
- Three parallel "planes" running alongside the request/response cycle:
  1. The background job worker (chapter 28) — a daemon thread polling for async work.
  2. The activity log (Part II ch. 24) — write-through from nearly every mutating action.
  3. The notification system (Part II ch. 19) — fan-out from the same mutating actions.
- Environments via `FLASKENV`: `development` (Postgres, debug), `testing` (SQLite, CSRF disabled),
  `production` (Postgres). One diagram-in-words: request → environment config → DB choice.

#### Key Files & Entry Points
- `app.py` — CLI entry (`-i` init, `-r` reset DB).
- `wsgi.py` — production entry point.
- `app/core/db_class/db.py` — every SQLAlchemy model, single source of truth for the schema.
- `app/features/<feature>/` — one folder per feature: `<feature>.py` (blueprint/routes),
  `<feature>_core.py` (DB/business logic) — this split is the project's hard rule, not a convention
  to relax.
- `app/api/<feature>/` — REST API mirror of the same features, Flask-RESTX, CSRF-exempt.
- `app/templates/<feature>/`, `app/static/js/<feature>/`, `app/static/css/<feature>/` — the same
  one-folder-per-feature mirroring, all the way down to the frontend.

#### Step-by-Step: How To Extend It
- Adding a whole new feature: create the four mirrored folders (blueprint, templates, JS, CSS) with
  identical names — reference the exact steps from `CLAUDE.md`'s "File organisation" section rather
  than restating them differently here (keep this one canonical).

#### Conventions & Gotchas
- Never place feature-specific JS in `components/`, never place a reusable component inside a feature
  folder — the single most common structural mistake to call out.
- Migrations must be applied to the real dev/prod DB (`flask db migrate` + `flask db upgrade`)
  immediately after any model change — SQLite test fixtures rebuild the schema fresh every run and
  will hide a missing migration until it breaks the real Postgres-backed dev server.

#### Screenshots/diagrams to capture
- A hand-drawn (or diagramming-tool) architecture diagram of the three planes described above — this
  chapter is the one place in the whole report that benefits from an actual diagram rather than a
  screenshot of the running app.

---

## 28. The Background Job Engine

#### Purpose & Scope
- Explains the mechanism behind every "this might take a while" operation surfaced in Part II
  chapter 23 — for a developer who needs to make a *new* operation run this way.

#### Architecture Overview
- `BackgroundJob` (+ `BackgroundJobLog`) rows in the DB are the entire state machine — status,
  payload (arbitrary JSON), timestamps.
- A single daemon thread (`_worker_loop` in `job_worker.py`) polls every ~2 seconds for the next
  pending job and executes its registered handler function inside the Flask app context.
- Handlers are plain functions decorated with `@register_handler('some_job_type')` in
  `job_handlers.py`, stored in a module-level dict keyed by job type — no other registration step
  exists.
- Pause/resume works because each handler is expected to persist enough state in `job.payload` (e.g.
  a resume offset, an accumulated list of processed IDs) to pick back up on the next invocation —
  the handler function itself has no memory between calls; the *payload* is the memory.
- Server-restart recovery: any job left `running` at worker startup is reset to `pending` and a
  warning log entry is appended automatically.

#### Key Files & Entry Points
- `app/features/jobs/job_worker.py` — the loop, `register_handler`, `start_worker(app)`.
- `app/features/jobs/job_handlers.py` — every actual handler function, one `@register_handler(...)`
  per job type (list the current job types here as a table: type string → one-line purpose → which
  Part II feature triggers it).
- `app/static/js/jobs/JobTracker.js` — the frontend component that polls/displays progress.

#### Step-by-Step: How To Extend It
1. Write a handler function `handle_my_new_job(job, app)` in `job_handlers.py`.
2. Decorate it `@register_handler('my_new_job')`.
3. Inside, use `job.payload` to store/restore any offset or accumulator needed for pause/resume —
   follow the existing `_save_offset(job, offset)` pattern rather than inventing a new one.
4. Check for pause/cancel between batches (the existing helpers already used by every handler) so the
   job responds to a user hitting pause instead of running to completion regardless.
5. Enqueue a `BackgroundJob` row with `job_type='my_new_job'` and whatever `payload` the handler
   expects from wherever the feature triggers it.

#### Conventions & Gotchas
- Never assume in-memory state survives between resumes — this is the single most common mistake
  when writing a new handler; everything needed to continue must be in `job.payload`.
- One worker thread means jobs run strictly one at a time — do not design a new job type assuming
  concurrency with other jobs.
- Always write meaningful `BackgroundJobLog` entries at meaningful checkpoints — that log is the
  only visibility an admin has into a stuck or failed job.

#### Screenshots/diagrams to capture
- A simple state diagram of `BackgroundJob.status` transitions (pending → running → paused/completed/
  failed/cancelled, plus the restart-recovery edge back to pending).

---

## 29. The Rule Format Parsing Engine

#### Purpose & Scope
- Explains how Rulezet supports many rule formats through one consistent contract, and exactly how to
  add a brand-new format — the single most valuable "how do I extend this" chapter for a security
  engineer who wants to add support for their own detection language.

#### Architecture Overview
- Every format implements the same abstract contract (`RuleType` in
  `rule_format/abstract_rule_type/rule_type_abstract.py`): `format`, `get_class()`, `validate()`,
  `parse_metadata()`, `get_rule_files()`, `extract_rules_from_file()`.
- Format implementations live one-per-file under `rule_format/available_format/` (e.g.
  `yara_format.py`, `sigma_format.py`, …) — each is a self-contained plugin, no shared mutable state
  expected (`"lightweight and stateless"` per the contract's own docstring).
- Auto-discovery: `load_all_rule_formats()` walks `available_format/` with `pkgutil.iter_modules` and
  imports every module found (skipping the base/default ones) — **a new format file is picked up
  automatically once it exists and defines a `RuleType` subclass**, no manual registration dict to
  edit.
- `main_format.py`'s `Process_rules_by_format()` is the shared pipeline every import/creation path
  goes through: extract → validate → parse metadata → either create the rule or file it as a bad
  rule (Part II chapter 8) if validation fails.
- `field_parser_core.py` is a separate, configurable layer for extracting *specific fields* (like CVE
  IDs) out of raw rule content across formats, independent of the per-format validation contract.

#### Key Files & Entry Points
- `app/features/rule/rule_format/abstract_rule_type/rule_type_abstract.py` — the contract + the
  auto-discovery loader.
- `app/features/rule/rule_format/available_format/*.py` — one file per existing format, the best
  reference set when writing a new one.
- `app/features/rule/rule_format/main_format.py` — the shared processing pipeline.
- `app/features/rule/rule_format/schema_format/` — JSON schema(s) backing structured formats (e.g.
  Sigma's schema) where format validation is schema-driven rather than fully custom code.
- `app/features/rule/field_parser_core.py` — configurable cross-format field extraction (CVE IDs,
  etc.).

#### Step-by-Step: How To Extend It (add a new rule format)
1. Create a new file in `rule_format/available_format/`, e.g. `myformat_format.py`.
2. Define a class implementing `RuleType`: set `format`/`get_class()`, implement `validate()` (the
   most important method — determines whether a submission becomes a rule or a bad rule),
   `parse_metadata()`, `get_rule_files()`, `extract_rules_from_file()`.
3. That's it for wiring — auto-discovery picks it up; **do not** hand-edit a format→class dict (the
   old comment in `main_format.py` describing a manual dict predates the auto-discovery mechanism —
   verify current behavior in code before writing this section, since this is exactly the kind of
   detail that must be double-checked against the live source rather than trusted from memory).
4. Add the format to `FormatRule`'s seed data (`insert_default_formats` in `app/core/utils/init_db.py`)
   so it's selectable in the create-rule form and shows up in the format management admin page
   (Part II chapter 25).
5. If the format needs structured/schema validation rather than custom parsing logic, add a schema
   file under `schema_format/` following the existing Sigma example.

#### Conventions & Gotchas
- `validate()` failing is not an error path to avoid — it's the expected, correct outcome for
  malformed input, and must route to the bad-rule queue rather than being silently swallowed or
  silently accepted.
- Keep implementations stateless — the loader imports every format module once at startup; nothing
  format-specific should depend on request-scoped state living inside the class itself.
- `get_rule_files()`/`extract_rules_from_file()` only matter for the GitHub-import path — a format
  that will only ever be created manually one-rule-at-a-time can implement them minimally, but must
  still implement them (the contract is abstract, not optional).

#### Screenshots/diagrams to capture
- None required (this chapter is source-code-driven) — optionally a small diagram of the
  `Process_rules_by_format()` pipeline (extract → validate → parse → create/bad-rule branch).

---

## 30. Frontend Architecture & Shared Components

#### Purpose & Scope
- Orients a contributor touching the UI: how Vue is wired in without a build step, and which shared
  components must be reused rather than reinvented per feature.

#### Architecture Overview
- Vue.js 3 loaded as a global UMD build (`vue.global.js`), no bundler — every page's script is a
  plain ES module, Jinja renders the initial HTML/data and Vue mounts on top of it.
- Template delimiter conflict resolved by using `['[[', ']]']` for Vue interpolation, leaving Jinja's
  `{{ }}` free for server-side templating in the same file.
- Shared, reusable components live in `app/static/js/components/` (with matching CSS in
  `app/static/css/components/`); feature-specific JS lives in `app/static/js/<feature>/` and must
  never cross into `components/` (repeating the rule from chapter 27 here because it's a frontend-
  specific consequence of it).
- Auth/permission state is bridged from Jinja into Vue at mount time (`const is_admin = {{
  current_user.is_admin() | tojson }}`, etc.) rather than the frontend independently deciding
  permissions — the server remains the source of truth, the frontend just reflects it for UI
  affordances.

#### Key Files & Entry Points
- `app/static/js/components/` — the full shared-component catalogue (list each one with a one-line
  purpose: `SmartEditor`, `CodeViewer`, `DiffViewer`, `ChartViewer`, `Timeline`, `AnsiTerminal`,
  `FileTree`, `UserChip`, `CommentThread`, `LoadingBar`, `KeyValue`, `DataTable`, `LogTable`,
  `ReportModal`, plus the feature-adjacent-but-shared ones: `JobTracker`, `TagInput`, `AttackInput`,
  `BundleRuleSelector`, `BundleStructureEditor`, `AttackMatrix`, `AttackDisplay`, `RuleList`).
- `app/templates/base.html` — the shell every page extends.
- `app/static/css/core.css` — the only place truly global CSS (new CSS variables, banner/card
  classes) belongs.

#### Step-by-Step: How To Extend It (add a new page using shared components)
1. Create the template under `app/templates/<feature>/`, extending `base.html`, following the
   documented page-layout pattern (breadcrumb inside the banner, then cards — see `CLAUDE.md`'s
   layout snippets, reuse verbatim rather than re-deriving the markup).
2. Create the feature JS module under `app/static/js/<feature>/`, importing whichever shared
   components are needed from `components/`.
3. Bridge any auth/ownership state needed from Jinja into the mounted Vue app's `const`s, following
   the `is_admin`/`currentUserId` pattern already used everywhere else, rather than re-querying it
   client-side.
4. Reuse `create_message()` from `toaster.js` for all user feedback — never hand-roll an alert div.

#### Conventions & Gotchas
- `ChartViewer` requires `window.echarts` to already be loaded globally on the page — a blank chart
  with no console error is almost always a missing ECharts CDN include, not a component bug.
- `RuleList` must always be registered together with `TagsDisplaysList`/`VulnerabilityDisplaysList`,
  and needs `dataTable.css` + `code-viewer.css` + `ruleList.css` — a page rendering an empty/broken
  rule table is very often one of these three missing.
- Dark mode relies on the documented CSS variables (`--text-color`, `--subtle-text-color`,
  `--card-bg-color`, `--border-color`, `--light-bg-color`) — never hardcode a color that should
  adapt, and use `var(--subtle-text-color)` (not `--color-text`, which does not exist) for secondary
  text.

#### Screenshots/diagrams to capture
- None required — this chapter is about code organization, not visual output.

---

## 31. Development Conventions & Use Cases to Respect When Coding

#### Purpose & Scope
- The condensed "read this before your first pull request" chapter — every rule here exists because
  violating it has caused a real bug or a real live-server incident in this project's history.

#### Architecture Overview (of the conventions themselves, grouped)
- **Data integrity:** never query `Rule.query` directly — always go through `_active()` in
  `rule_core.py`, which filters out soft-deleted rows; forgetting this silently resurfaces deleted
  rules everywhere from search to the API.
- **Deletion semantics:** rules are soft-deleted (`is_deleted`, `deleted_at`, `deleted_by_id`,
  `delete_batch_uuid`) with a Trash/purge admin flow; comments (in all their forms — per-feature
  tables and the unified polymorphic table) must be explicitly cleaned up whenever an object that can
  own comments is *hard*-deleted, since the polymorphic comment table has no real foreign key to
  cascade automatically.
- **Permissions:** the fixed three-tier model (anonymous / authenticated / owner-or-admin) must be
  enforced on every route that touches a resource — the exact guard pattern
  (`if current_user.id != resource.user_id and not current_user.is_admin(): return ..., 403`) is
  copy-paste reusable and should be, rather than reinvented per feature.
- **Admin page gating:** use the established inline per-route check
  (`if not current_user.is_admin(): return render_template('access_denied.html')`) for admin routes
  mixed into a general-purpose blueprint; reserve a blueprint-wide `before_request` hook only for
  blueprints that are *entirely* admin-exclusive (e.g. connectors) — mixing the two patterns in the
  same blueprint has already caused a real regression (a shared page accidentally fully gated to
  admins) and should not recur.
- **Migrations:** any SQLAlchemy model change needs its Alembic migration generated *and applied to
  the real dev/prod database* immediately — SQLite test fixtures rebuild from the model automatically
  and will not reveal a missing migration; this has broken the live dev server before.
- **Pagination:** any paginated list query needs an explicit `.order_by()` before `.paginate()` —
  Postgres does not guarantee row order otherwise, and newly created rows can silently land on any
  page instead of the first one.
- **Activity logging:** call `log_activity` (dot-namespaced action, e.g. `rule.create`) on every
  significant mutating action — this is what powers both the admin log and the public activity feed
  (Part II chapter 24), and a missing call is invisible until someone goes looking for an entry that
  isn't there.

#### Key Files & Entry Points
- `CLAUDE.md` (repository root) — the canonical, always-up-to-date source for these conventions;
  this chapter summarizes and explains *why* they exist, but `CLAUDE.md` itself is the reference to
  keep open while coding.

#### Step-by-Step: How To Apply This (checklist form for a new PR)
1. Does this change touch a resource with an owner? → apply the owner-or-admin guard pattern.
2. Does this change delete something that can have comments attached? → clean up every comment table
   that can reference it, including the polymorphic one.
3. Does this change alter a SQLAlchemy model? → generate *and apply* the migration before moving on.
4. Does this change add a paginated list? → add an explicit `.order_by()`.
5. Does this change mutate meaningful state? → add a `log_activity` call with a properly
   dot-namespaced action name.
6. Does this change add a new admin-only page inside a mixed blueprint? → use the inline per-route
   check, not a blueprint-wide hook.

#### Conventions & Gotchas
- These are not style preferences — each one maps to a real incident or a real, demonstrated bug
  class in this codebase's history; treat this chapter as load-bearing, not optional guidance.

#### Screenshots/diagrams to capture
- None — this chapter is a pure checklist/reference.

---
---

# PART IV — Appendices

## Appendix A — Glossary of Terms & Acronyms

- Plan: one alphabetized table, two columns (term, one-sentence definition), covering every term
  introduced across Part I chapter 5 plus any format/protocol acronym used anywhere in the report
  (YARA, Sigma, Suricata, Zeek, Wazuh, NSE, CRS, Nova, TLP, PAP, STIX, MISP, ATT&CK, CVE, CIRCL,
  NGSOTI, SOC, etc.). Every acronym's *first use* in any chapter should link here.

## Appendix B — Roadmap & Future Directions

- Reuse and expand the CIRCL slide deck's roadmap slide as a starting point:
  - MISP import/export for rules and bundles.
  - Vulnerability reference integration with `vulnerability.circl.lu` for improved CVE traceability.
- Add any additional roadmap items surfaced during interviews with the team while writing the rest of
  the report — keep this appendix explicitly dated ("as of [month/year]") since a roadmap is the part
  of any report that goes stale fastest.

## Appendix C — Screenshot & Media Master Checklist

- Plan: a single flat checklist aggregating every "Screenshots to capture" list from Part II and
  Part III, in chapter order, as a one-stop shot list for the actual screenshot-taking session —
  avoids re-deriving it chapter by chapter while out capturing images.
- Include a column for status (captured / pending / needs re-shoot after a UI change) so this
  appendix doubles as a living production tracker until the report is finished.

---
---

# Next Steps (for us, not for the published report)

1. You review this plan and flag anything mis-scoped, missing, or out of date (especially the Rule
   Tester suspension note, current job-type catalogue, current API namespace list, and workspace
   sharing model — all marked above as "confirm before writing").
2. Once approved, we go chapter by chapter: you capture the screenshots for a chapter, then I write
   the full prose for it against this outline, in English, ready to drop into the future template.
3. French translation happens per chapter once the English text is stable, not before — translating
   a chapter that's still being edited just means redoing the translation.
