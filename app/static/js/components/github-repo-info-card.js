/**
 * GithubRepoInfoCard — collapsible "live GitHub repository info" card:
 * owner/name/description, KPI strip (stars/forks/issues/watchers/size),
 * info cells (language/license/branch/dates), topics, recent commits,
 * branches and top contributors. Fetches directly from the public GitHub
 * REST API on first expand (no Rulezet backend round-trip).
 *
 * Extracted from app/templates/rule/url_github/detail_url_github.html so
 * any page needing this exact panel doesn't duplicate the markup/JS.
 *
 * Props:
 *   repo-url        (String)  — required; e.g. https://github.com/owner/repo(.git)
 *   start-expanded   (Boolean) — default false
 */
const { ref } = Vue;

function fmtNum(n) {
    if (n === undefined || n === null) return '—';
    if (n >= 1000) return (n / 1000).toFixed(1) + 'k';
    return String(n);
}
function fmtSize(kb) {
    if (!kb) return '—';
    return kb < 1024 ? kb + ' KB' : (kb / 1024).toFixed(1) + ' MB';
}
function fmtDate(iso) {
    if (!iso) return '—';
    return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

async function ghFetch(path) {
    const r = await fetch(`https://api.github.com${path}`, {
        headers: { 'Accept': 'application/vnd.github+json' }
    });
    if (!r.ok) throw new Error(String(r.status));
    return r.json();
}

const GithubRepoInfoCard = {
    name: 'GithubRepoInfoCard',
    delimiters: ['[[', ']]'],
    props: {
        repoUrl: { type: String, required: true },
        startExpanded: { type: Boolean, default: false },
    },
    setup(props) {
        const ghExpanded = ref(props.startExpanded);
        const ghFetched = ref(false);
        const ghRepo = ref(null);
        const ghLoading = ref(false);
        const ghError = ref(null);
        const commits = ref([]);
        const commitsLoading = ref(false);
        const branches = ref([]);
        const branchesLoading = ref(false);
        const contributors = ref([]);
        const contributorsLoading = ref(false);

        function repoPath() {
            return props.repoUrl
                .replace(/^https?:\/\/github\.com\//, '')
                .replace(/\.git$/, '')
                .replace(/\/$/, '');
        }

        async function loadGhData() {
            ghLoading.value = true;
            commitsLoading.value = true;
            branchesLoading.value = true;
            contributorsLoading.value = true;
            ghError.value = null;

            const path = repoPath();
            const [repoRes, commitsRes, branchesRes, contribRes] = await Promise.allSettled([
                ghFetch(`/repos/${path}`),
                ghFetch(`/repos/${path}/commits?per_page=10`),
                ghFetch(`/repos/${path}/branches?per_page=50`),
                ghFetch(`/repos/${path}/contributors?per_page=20&anon=false`),
            ]);

            ghLoading.value = false;
            if (repoRes.status === 'fulfilled') {
                ghRepo.value = repoRes.value;
            } else {
                const code = repoRes.reason && repoRes.reason.message;
                if (code === '403') ghError.value = 'GitHub API rate limit reached. Try again in a few minutes.';
                else if (code === '404') ghError.value = 'Repository not found or is private.';
                else ghError.value = `GitHub API error (${code}).`;
            }

            commitsLoading.value = false;
            if (commitsRes.status === 'fulfilled') commits.value = commitsRes.value;

            branchesLoading.value = false;
            if (branchesRes.status === 'fulfilled') branches.value = branchesRes.value;

            contributorsLoading.value = false;
            if (contribRes.status === 'fulfilled') contributors.value = contribRes.value;
        }

        async function toggleGh() {
            ghExpanded.value = !ghExpanded.value;
            if (ghExpanded.value && !ghFetched.value) {
                ghFetched.value = true;
                await loadGhData();
            }
        }

        if (props.startExpanded) {
            ghFetched.value = true;
            loadGhData();
        }

        return {
            ghExpanded, toggleGh,
            ghRepo, ghLoading, ghError,
            commits, commitsLoading,
            branches, branchesLoading,
            contributors, contributorsLoading,
            fmtNum, fmtSize, fmtDate,
        };
    },
    template: `
    <div class="card border-0 shadow-sm mb-4" style="background:var(--card-bg-color);">
        <div class="card-header border-bottom py-3" style="background:var(--card-bg-color);">
            <button class="gh-toggle-btn" @click="toggleGh" :aria-expanded="ghExpanded">
                <i class="fa-brands fa-github" style="font-size:1rem;color:var(--subtle-text-color);"></i>
                <span class="fw-semibold" style="font-size:.9rem;">GitHub Repository info</span>
                <span v-if="ghLoading" class="spinner-border spinner-border-sm text-secondary ms-1"></span>
                <i class="fa-solid fa-chevron-down gh-chevron" :class="{ 'gh-chevron--open': ghExpanded }"></i>
            </button>
        </div>

        <div class="gh-collapse-body" :class="{ 'gh-collapse-body--open': ghExpanded }">
        <div class="card-body p-4">

            <div v-if="ghError" class="gh-error-box">
                <i class="fa-solid fa-circle-exclamation me-2 text-warning"></i>[[ ghError ]]
            </div>

            <div v-if="ghLoading" class="d-flex flex-column gap-3">
                <div class="placeholder-glow"><span class="placeholder col-7 rounded"></span></div>
                <div class="gh-kpi-grid">
                    <div v-for="i in 5" :key="i" class="gh-kpi placeholder-glow">
                        <span class="placeholder col-10 rounded" style="height:36px;"></span>
                    </div>
                </div>
                <div class="placeholder-glow mt-2">
                    <span class="placeholder col-4 rounded"></span><br>
                    <span class="placeholder col-10 rounded mt-2" style="height:120px;display:block;"></span>
                </div>
            </div>

            <div v-if="ghRepo && !ghLoading">

                <div class="d-flex align-items-start gap-3 mb-4">
                    <img :src="ghRepo.owner.avatar_url" :alt="ghRepo.owner.login"
                         class="rounded-circle flex-shrink-0"
                         style="width:44px;height:44px;border:2px solid var(--border-color);" />
                    <div style="min-width:0;">
                        <div class="d-flex align-items-center gap-2 flex-wrap mb-1">
                            <a :href="ghRepo.owner.html_url" target="_blank" rel="noreferrer"
                               class="fw-semibold text-decoration-none" style="font-size:.9rem;">[[ ghRepo.owner.login ]]</a>
                            <span class="text-muted">/</span>
                            <a :href="ghRepo.html_url" target="_blank" rel="noreferrer"
                               class="fw-bold text-decoration-none" style="font-size:.9rem;">[[ ghRepo.name ]]</a>
                            <span v-if="ghRepo.archived" class="badge bg-warning text-dark">Archived</span>
                            <span v-if="ghRepo.fork" class="badge bg-secondary">Fork</span>
                            <span class="badge" style="font-size:.65rem;"
                                  :class="ghRepo.visibility==='public' ? 'bg-success-subtle text-success' : 'bg-danger-subtle text-danger'">
                                <i class="fa-solid" :class="ghRepo.visibility==='public' ? 'fa-lock-open' : 'fa-lock'"></i>
                                [[ ghRepo.visibility ]]
                            </span>
                        </div>
                        <p v-if="ghRepo.description" class="text-muted mb-0" style="font-size:.85rem;">[[ ghRepo.description ]]</p>
                        <p v-else class="text-muted fst-italic mb-0" style="font-size:.82rem;">No description provided.</p>
                    </div>
                </div>

                <div class="gh-kpi-grid mb-4">
                    <div class="gh-kpi">
                        <div class="gh-kpi-icon" style="background:rgba(255,193,7,.15);color:#e6a817;"><i class="fa-solid fa-star"></i></div>
                        <div><div class="gh-kpi-num">[[ fmtNum(ghRepo.stargazers_count) ]]</div><div class="gh-kpi-lbl">Stars</div></div>
                    </div>
                    <div class="gh-kpi">
                        <div class="gh-kpi-icon" style="background:rgba(13,110,253,.12);color:#0d6efd;"><i class="fa-solid fa-code-branch"></i></div>
                        <div><div class="gh-kpi-num">[[ fmtNum(ghRepo.forks_count) ]]</div><div class="gh-kpi-lbl">Forks</div></div>
                    </div>
                    <div class="gh-kpi">
                        <div class="gh-kpi-icon" style="background:rgba(220,53,69,.12);color:#dc3545;"><i class="fa-solid fa-circle-dot"></i></div>
                        <div><div class="gh-kpi-num">[[ fmtNum(ghRepo.open_issues_count) ]]</div><div class="gh-kpi-lbl">Open issues</div></div>
                    </div>
                    <div class="gh-kpi">
                        <div class="gh-kpi-icon" style="background:rgba(13,202,240,.12);color:#0dcaf0;"><i class="fa-solid fa-eye"></i></div>
                        <div><div class="gh-kpi-num">[[ fmtNum(ghRepo.subscribers_count) ]]</div><div class="gh-kpi-lbl">Watchers</div></div>
                    </div>
                    <div class="gh-kpi">
                        <div class="gh-kpi-icon" style="background:rgba(108,117,125,.12);color:#6c757d;"><i class="fa-solid fa-database"></i></div>
                        <div><div class="gh-kpi-num">[[ fmtSize(ghRepo.size) ]]</div><div class="gh-kpi-lbl">Size</div></div>
                    </div>
                </div>

                <div class="gh-info-grid mb-4">
                    <div class="gh-info-cell" v-if="ghRepo.language">
                        <div class="gh-info-cell-icon" style="background:rgba(13,110,253,.1);color:#0d6efd;"><i class="fa-solid fa-code"></i></div>
                        <div><div class="gh-info-lbl">Language</div><div class="gh-info-val">[[ ghRepo.language ]]</div></div>
                    </div>
                    <div class="gh-info-cell" v-if="ghRepo.license">
                        <div class="gh-info-cell-icon" style="background:rgba(25,135,84,.1);color:#198754;"><i class="fa-solid fa-scale-balanced"></i></div>
                        <div><div class="gh-info-lbl">License</div><div class="gh-info-val">[[ ghRepo.license.name ]]</div></div>
                    </div>
                    <div class="gh-info-cell">
                        <div class="gh-info-cell-icon" style="background:rgba(108,117,125,.1);color:#6c757d;"><i class="fa-solid fa-code-branch"></i></div>
                        <div><div class="gh-info-lbl">Default branch</div><div class="gh-info-val">[[ ghRepo.default_branch ]]</div></div>
                    </div>
                    <div class="gh-info-cell">
                        <div class="gh-info-cell-icon" style="background:rgba(255,193,7,.1);color:#e6a817;"><i class="fa-solid fa-calendar-plus"></i></div>
                        <div><div class="gh-info-lbl">Created</div><div class="gh-info-val">[[ fmtDate(ghRepo.created_at) ]]</div></div>
                    </div>
                    <div class="gh-info-cell">
                        <div class="gh-info-cell-icon" style="background:rgba(13,202,240,.1);color:#0dcaf0;"><i class="fa-solid fa-clock-rotate-left"></i></div>
                        <div><div class="gh-info-lbl">Last push</div><div class="gh-info-val">[[ fmtDate(ghRepo.pushed_at) ]]</div></div>
                    </div>
                    <div class="gh-info-cell" v-if="ghRepo.homepage">
                        <div class="gh-info-cell-icon" style="background:rgba(13,110,253,.1);color:#0d6efd;"><i class="fa-solid fa-link"></i></div>
                        <div>
                            <div class="gh-info-lbl">Homepage</div>
                            <div class="gh-info-val">
                                <a :href="ghRepo.homepage" target="_blank" rel="noreferrer"
                                   class="text-decoration-none" style="word-break:break-all;">[[ ghRepo.homepage ]]</a>
                            </div>
                        </div>
                    </div>
                </div>

                <div v-if="ghRepo.topics && ghRepo.topics.length" class="mb-4">
                    <div class="gh-info-lbl mb-2"><i class="fa-solid fa-tags me-1"></i>Topics</div>
                    <div class="d-flex flex-wrap gap-2">
                        <span v-for="t in ghRepo.topics" :key="t" class="gh-topic">[[ t ]]</span>
                    </div>
                </div>

                <hr style="border-color:var(--border-color);margin:1.5rem 0;" />

                <div class="row g-4 mb-4">
                    <div class="col-lg-7">
                        <div class="gh-sub-header">
                            <i class="fa-solid fa-code-commit"></i> Recent commits
                            <a v-if="ghRepo" :href="ghRepo.html_url + '/commits'" target="_blank" rel="noreferrer"
                               class="ms-auto text-decoration-none" style="font-size:.72rem;color:#0d6efd;text-transform:none;letter-spacing:0;font-weight:400;">
                                See all <i class="fa-solid fa-arrow-up-right-from-square ms-1" style="font-size:.6rem;"></i>
                            </a>
                        </div>
                        <div v-if="commitsLoading" class="placeholder-glow d-flex flex-column gap-2">
                            <span v-for="i in 5" :key="i" class="placeholder rounded" style="height:38px;display:block;"></span>
                        </div>
                        <div v-else-if="!commits.length" class="gh-empty">No commits found.</div>
                        <div v-else>
                            <div v-for="c in commits" :key="c.sha" class="gh-commit-item">
                                <img v-if="c.author && c.author.avatar_url"
                                     :src="c.author.avatar_url" :alt="c.author.login"
                                     class="gh-commit-avatar" />
                                <div class="gh-commit-avatar-fallback" v-else>
                                    <i class="fa-solid fa-user"></i>
                                </div>
                                <div style="min-width:0;flex:1;">
                                    <div class="d-flex align-items-center gap-2 mb-1">
                                        <a :href="c.html_url" target="_blank" rel="noreferrer"
                                           class="gh-sha">[[ c.sha.slice(0,7) ]]</a>
                                        <span v-if="c.author" class="text-muted" style="font-size:.72rem;">
                                            [[ c.author.login ]]
                                        </span>
                                        <span v-else class="text-muted" style="font-size:.72rem;">
                                            [[ c.commit.author.name ]]
                                        </span>
                                        <span class="ms-auto gh-commit-meta flex-shrink-0">
                                            [[ fmtDate(c.commit.author.date) ]]
                                        </span>
                                    </div>
                                    <div class="gh-commit-msg" :title="c.commit.message">
                                        [[ c.commit.message.split('\\n')[0] ]]
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="col-lg-5">
                        <div class="gh-sub-header">
                            <i class="fa-solid fa-code-branch"></i> Branches
                            <a v-if="ghRepo" :href="ghRepo.html_url + '/branches'" target="_blank" rel="noreferrer"
                               class="ms-auto text-decoration-none" style="font-size:.72rem;color:#0d6efd;text-transform:none;letter-spacing:0;font-weight:400;">
                                See all <i class="fa-solid fa-arrow-up-right-from-square ms-1" style="font-size:.6rem;"></i>
                            </a>
                        </div>
                        <div v-if="branchesLoading" class="placeholder-glow d-flex flex-column gap-2">
                            <span v-for="i in 4" :key="i" class="placeholder rounded" style="height:34px;display:block;"></span>
                        </div>
                        <div v-else-if="!branches.length" class="gh-empty">No branches found.</div>
                        <div v-else class="d-flex flex-column gap-1">
                            <div v-for="b in branches" :key="b.name"
                                 class="d-flex align-items-center gap-2 px-3 py-2 rounded-2"
                                 style="background:var(--light-bg-color);border:1px solid var(--border-color);">
                                <i class="fa-solid fa-code-branch" style="font-size:.75rem;color:var(--subtle-text-color);flex-shrink:0;"></i>
                                <a :href="ghRepo.html_url + '/tree/' + b.name" target="_blank" rel="noreferrer"
                                   class="text-decoration-none fw-medium flex-grow-1"
                                   style="font-size:.82rem;font-family:'JetBrains Mono',monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                                    [[ b.name ]]
                                </a>
                                <span v-if="ghRepo && b.name === ghRepo.default_branch"
                                      class="badge bg-primary-subtle text-primary flex-shrink-0" style="font-size:.62rem;">
                                    default
                                </span>
                                <span v-if="b.protected"
                                      class="badge bg-warning-subtle text-warning flex-shrink-0" style="font-size:.62rem;">
                                    protected
                                </span>
                            </div>
                        </div>
                    </div>
                </div>

                <hr style="border-color:var(--border-color);margin:0 0 1.5rem;" />
                <div class="gh-sub-header mb-3">
                    <i class="fa-solid fa-users"></i> Top contributors
                    <a v-if="ghRepo" :href="ghRepo.html_url + '/graphs/contributors'" target="_blank" rel="noreferrer"
                       class="ms-auto text-decoration-none" style="font-size:.72rem;color:#0d6efd;text-transform:none;letter-spacing:0;font-weight:400;">
                        See all <i class="fa-solid fa-arrow-up-right-from-square ms-1" style="font-size:.6rem;"></i>
                    </a>
                </div>
                <div v-if="contributorsLoading" class="placeholder-glow d-flex gap-2">
                    <span v-for="i in 10" :key="i" class="placeholder rounded-circle" style="width:36px;height:36px;display:block;"></span>
                </div>
                <div v-else-if="!contributors.length" class="gh-empty">No contributor data available.</div>
                <div v-else class="d-flex flex-wrap gap-1">
                    <a v-for="c in contributors" :key="c.login"
                       :href="c.html_url" target="_blank" rel="noreferrer"
                       class="gh-contributor" :title="c.login + ' · ' + fmtNum(c.contributions) + ' commits'">
                        <img :src="c.avatar_url" :alt="c.login" />
                        <div class="gh-contributor-login">[[ c.login ]]</div>
                        <div class="gh-contributor-count">[[ fmtNum(c.contributions) ]]</div>
                    </a>
                </div>

            </div>
        </div>
        </div>
    </div>
    `
};

export default GithubRepoInfoCard;
