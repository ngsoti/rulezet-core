const UserContributionStatsComponent = {
    props: {
        userId: {
            type: [String, Number],
            required: true
        }
    },
    delimiters: ['[[', ']]'],
    setup(props) {
        const userStats = Vue.ref({
            total_points: undefined,
            current_level: 1,
            suggestions_accepted: 0,
            rules_owned: 0,
            rules_popular_score: 0,
            rules_liked: 0,
            consecutive_days_active: 0,
            global_rank: null
        });

        const loading = Vue.ref(true);

        // --- CONSTANTS ---
        const LEVEL_THRESHOLDS = {
            1: 0, 2: 500, 3: 15000, 4: 30000, 5: 50000, 10: 150000, 20: 300000, 100: 1500000
        };

        const BADGE_POINTS = {
            'Bronze Contributor': 1000,
            'Silver Contributor': 10000,
            'Gold Contributor': 50000,
            'Curator Rookie': { metric: 'suggestions_accepted', min: 5 },
            'Quality Master': { metric: 'suggestions_accepted', min: 25 }
        };

        // --- METHODS ---
        const getBadgeClass = (badgeName) => {
            if (badgeName.includes('Master')) return 'bg-danger text-white border border-light';
            if (badgeName.includes('Gold')) return 'bg-warning text-dark border border-dark';
            if (badgeName.includes('Silver')) return 'bg-secondary text-white border border-light';
            if (badgeName.includes('Bronze')) return 'bg-bronze text-white border border-dark';
            if (badgeName.includes('Curator')) return 'bg-info text-white';
            if (badgeName.includes('Quality')) return 'bg-success text-white';
            return 'bg-dark text-white';
        };

        const getBadgeIcon = (badgeName) => {
            if (badgeName.includes('Contributor')) return 'fas fa-star';
            if (badgeName.includes('Master')) return 'fas fa-brain';
            if (badgeName.includes('Curator')) return 'fas fa-glasses';
            if (badgeName.includes('Quality')) return 'fas fa-cogs';
            return 'fas fa-certificate';
        };

        const fetchUserStats = async () => {
            loading.value = true;
            try {
                const res = await fetch(`/account/user_contributions/${props.userId}`);
                if (!res.ok) {
                    console.error('Failed to fetch user contributions:', res.statusText);
                    loading.value = false;
                    return;
                }
                const data = await res.json();
                userStats.value = data.user_stats;
            } catch (error) {
                console.error('API Fetch Error:', error);
            } finally {
                loading.value = false;
            }
        };

        // --- COMPUTED PROPERTIES ---
        const computedBadges = Vue.computed(() => {
            if (userStats.value.total_points === undefined) return [];

            const badges = [];
            const stats = userStats.value;

            for (const [badgeName, threshold] of Object.entries(BADGE_POINTS)) {
                if (typeof threshold === 'number') {
                    if (stats.total_points >= threshold) {
                        badges.push({
                            name: badgeName,
                            description: `Awarded for reaching ${threshold.toLocaleString()} total points.`
                        });
                    }
                } else if (typeof threshold === 'object' && threshold.metric) {
                    const value = stats[threshold.metric] || 0;
                    if (value >= threshold.min) {
                        badges.push({
                            name: badgeName,
                            description: `Awarded for having ${threshold.min} or more accepted suggestions.`
                        });
                    }
                }
            }

            if (stats.current_level >= 5) {
                badges.push({
                    name: 'Veteran Contributor',
                    description: 'Achieved level 5 or higher.'
                });
            }

            return badges.sort((a, b) => a.name.localeCompare(b.name));
        });

        const nextLevelThreshold = Vue.computed(() => {
            const currentLevel = userStats.value.current_level;
            const sortedLevels = Object.keys(LEVEL_THRESHOLDS).map(Number).sort((a, b) => a - b);
            const nextLevelIndex = sortedLevels.findIndex(lvl => lvl > currentLevel);

            if (nextLevelIndex !== -1) {
                const nextLevel = sortedLevels[nextLevelIndex];
                return {
                    level: nextLevel,
                    points: LEVEL_THRESHOLDS[nextLevel]
                };
            }

            return { level: currentLevel, points: userStats.value.total_points || 0 };
        });

        const progressPercentage = Vue.computed(() => {
            const currentPoints = userStats.value.total_points;
            const currentLevel = userStats.value.current_level;

            if (currentPoints === undefined) return 0;

            const previousLevelPoints = LEVEL_THRESHOLDS[currentLevel] || 0;
            const nextLevelPoints = nextLevelThreshold.value.points;

            if (nextLevelPoints === currentPoints && nextLevelThreshold.value.level === currentLevel) {
                return 100;
            }

            const levelSpan = nextLevelPoints - previousLevelPoints;
            const pointsInLevel = currentPoints - previousLevelPoints;

            if (levelSpan <= 0) return 0;

            return Math.min(100, (pointsInLevel / levelSpan) * 100).toFixed(2);
        });

        // --- LIFECYCLE ---
        Vue.onMounted(() => {
            fetchUserStats();
        });

        return {
            userStats,
            loading,
            computedBadges,
            nextLevelThreshold,
            progressPercentage,
            getBadgeClass,
            getBadgeIcon
        };
    },
    template: `
    <div class=" p-1">
        <div v-if="!loading && userStats.total_points !== undefined" class="row">
            <!-- Core Stats Card -->
            <div class="col-lg-5 mb-4">
                <div class="card shadow h-100">
                    <div class="card-header bg-primary text-white">
                        <h5 class="mb-0">
                            <i class="fas fa-chart-bar me-2"></i> Core Stats (Level [[ userStats.current_level ]])
                            <i class="fas fa-question-circle text-dark ms-1"
                               title="Current contribution level. Earn points to reach the next one!"></i>
                        </h5>
                    </div>
                    <div class="card-body p-4">
                        <div class="text-center mb-4 p-3 rounded-3" style="background: linear-gradient(135deg, rgba(40, 167, 69, 0.1) 0%, rgba(40, 167, 69, 0.05) 100%); border: 1px solid rgba(40, 167, 69, 0.2);">
                            <small class="text-uppercase fw-bold text-muted" style="letter-spacing: 1px;">Reputation Score</small>
                            <p class="h2 fw-bold text-success mb-0">
                                <i class="fas fa-trophy me-2"></i>[[ userStats.total_points.toLocaleString() ]]
                            </p>
                        </div>

                        <ul class="list-unstyled fw-medium mb-0">
                            <li class="d-flex justify-content-between align-items-center mb-3 p-2 rounded-2 border-start border-primary border-4 shadow-sm bg-light bg-opacity-50">
                                <span><i class="fas fa-globe-americas me-2 text-primary"></i> Global Rank</span>
                                <span class="badge rounded-pill bg-primary shadow-sm" style="min-width: 70px; font-size: 0.9rem; padding: 8px;">
                                    #[[ userStats.global_rank || 'N/A' ]]
                                </span>
                            </li>

                            <li class="d-flex justify-content-between align-items-center mb-3 p-2 rounded-2 border-start border-success border-4 shadow-sm bg-light bg-opacity-50">
                                <span><i class="fas fa-check-circle me-2 text-success"></i> Accepted Suggestions</span>
                                <span class="badge rounded-pill bg-success shadow-sm" style="min-width: 70px; padding: 8px;">
                                    [[ userStats.suggestions_accepted ]]
                                </span>
                            </li>

                            <li class="d-flex justify-content-between align-items-center mb-3 p-2 rounded-2 border-start border-info border-4 shadow-sm bg-light bg-opacity-50">
                                <span><i class="fas fa-cloud-upload-alt me-2 text-info"></i> Rules Imported</span>
                                <span class="badge rounded-pill bg-info text-white shadow-sm" style="min-width: 70px; padding: 8px;">
                                    [[ userStats.rules_owned ]]
                                </span>
                            </li>

                            <li class="d-flex justify-content-between align-items-center mb-3 p-2 rounded-2 border-start border-warning border-4 shadow-sm bg-light bg-opacity-50">
                                <span><i class="fas fa-fire-alt me-2 text-warning"></i> Activity Streak</span>
                                <span class="badge rounded-pill bg-warning text-dark shadow-sm" style="min-width: 70px; padding: 8px;">
                                    [[ userStats.consecutive_days_active ]] days
                                </span>
                            </li>

                            <li class="d-flex justify-content-between align-items-center mb-3 p-2 rounded-2 border-start border-danger border-4 shadow-sm bg-light bg-opacity-50">
                                <span><i class="fas fa-heart me-2 text-danger"></i> Rules Liked</span>
                                <span class="badge rounded-pill bg-danger shadow-sm" style="min-width: 70px; padding: 8px;">
                                    [[ userStats.rules_liked ]]
                                </span>
                            </li>

                            <li class="d-flex justify-content-between align-items-center p-2 rounded-2 border-start border-indigo border-4 shadow-sm bg-light bg-opacity-50" style="border-left-color: #6610f2 !important;">
                                <span><i class="fas fa-star me-2" style="color: #6610f2;"></i> Popularity Score</span>
                                <span class="badge rounded-pill shadow-sm text-white" style="min-width: 70px; padding: 8px; background-color: #6610f2;">
                                    [[ userStats.rules_popular_score.toLocaleString() ]]
                                </span>
                            </li>
                        </ul>
                    </div>
                    <div class="card-footer text-center">
                        <div class="progress" role="progressbar" aria-label="Level Progress"
                             :aria-valuenow="progressPercentage" aria-valuemin="0" aria-valuemax="100"
                             style="height: 20px;">
                            <div class="progress-bar bg-success" :style="{ width: progressPercentage + '%' }">
                                Level [[ userStats.current_level ]] Progress
                            </div>
                        </div>
                        <small class="text-muted mt-2 d-block">
                            Next level (L[[ nextLevelThreshold.level ]]): [[ nextLevelThreshold.points.toLocaleString() ]] points
                        </small>
                    </div>
                </div>
            </div>

            <!-- Earned Badges Card -->
            <div class="col-lg-7 mb-4">
                <div class="card shadow h-100">
                    <div class="card-header bg-secondary text-white">
                        <h5 class="mb-0">
                            <i class="fas fa-award me-2"></i> Earned Badges ([[ computedBadges.length ]])
                            <i class="fas fa-question-circle text-dark ms-1"
                               title="Badges awarded based on points and contribution metrics."></i>
                        </h5>
                    </div>
                    <div class="card-body d-flex flex-wrap align-content-start">
                        <div v-if="computedBadges.length > 0">
                            <span class="badge rounded-pill me-2 mb-2 p-2 badge-custom"
                                  :class="getBadgeClass(badge.name)"
                                  v-for="badge in computedBadges"
                                  :key="badge.name"
                                  :title="badge.description">
                                <i :class="getBadgeIcon(badge.name) + ' me-1'"></i>
                                [[ badge.name ]]
                            </span>
                        </div>
                        <p v-else class="text-muted m-auto">No badges earned yet. Start contributing!</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Loading State -->
        <div v-else class="text-center p-5" style="color: var(--subtle-text-color);">
            <i class="fas fa-spinner fa-spin fa-2x"></i> Loading user stats...
        </div>
    </div>
    `
};

export default UserContributionStatsComponent;