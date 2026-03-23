const UserActivityStatsComponent = {
    props: {
        userId: { type: [String, Number], default: null },
        user_id: { type: [String, Number], default: null },
        apiEndpoint: { type: String, required: true }
    },
    delimiters: ['[[', ']]'],
    setup(props) {
        const activity_data = Vue.ref(null);
        const loading = Vue.ref(true);
        const error = Vue.ref(null);
        
        const barCanvas = Vue.ref(null);
        const pieCanvas = Vue.ref(null);
        const lineCanvas = Vue.ref(null); // Nouveau canvas pour la timeline
        
        let barInstance = null;
        let pieInstance = null;
        let lineInstance = null;

        const actualUserId = Vue.computed(() => props.userId || props.user_id);

        const fetchData = async () => {
            loading.value = true;
            try {
                const endpoint = props.apiEndpoint.replace('{userId}', actualUserId.value);
                const response = await fetch(endpoint);
                const data = await response.json();
                activity_data.value = data;
            } catch (err) {
                error.value = "Erreur de chargement des stats";
            } finally {
                loading.value = false;
            }
        };

        const renderCharts = () => {
            // --- BAR CHART (Votes) ---
            if (barCanvas.value) {
                if (barInstance) barInstance.destroy();
                const s = activity_data.value.activity_stats;
                const labels = ['Rules Likes', 'Rules Dislikes', 'Bundles Likes', 'Bundles Dislikes'];
                const dataValues = [s.rules_likes, s.rules_dislikes, s.bundles_likes, s.bundles_dislikes];

                barInstance = new Chart(barCanvas.value.getContext('2d'), {
                    type: 'bar',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: 'Votes Count',
                            data: dataValues,
                            backgroundColor: ['#4bc04b', '#ff6363', '#36a2eb', '#ff9f40'],
                            borderWidth: 1
                        }]
                    },
                    options: { 
                        responsive: true, 
                        maintainAspectRatio: false,
                        plugins: {
                            title: {
                                display: true,
                                text: 'Community Feedback Overview',
                                font: { size: 16, weight: 'bold' },
                                padding: { bottom: 20 }
                            },
                            legend: {
                                display: true,
                                position: 'bottom',
                                labels: {
                                    padding: 15,
                                    usePointStyle: true,
                                    generateLabels: (chart) => {
                                        const data = chart.data;
                                        return data.labels.map((label, i) => ({
                                            text: `${label}: ${data.datasets[0].data[i]}`, 
                                            fillStyle: data.datasets[0].backgroundColor[i],
                                            index: i
                                        }));
                                    }
                                }
                            }
                        },
                        scales: { y: { beginAtZero: true, ticks: { precision: 0 } } }
                    }
                });
            }

            // --- DOUGHNUT CHART (Formats) ---
            if (pieCanvas.value) {
                if (pieInstance) pieInstance.destroy();
                const dist = activity_data.value.format_distribution;
                const labels = Object.keys(dist);
                const dataValues = Object.values(dist);
                
                pieInstance = new Chart(pieCanvas.value.getContext('2d'), {
                    type: 'doughnut',
                    data: {
                        labels: labels,
                        datasets: [{
                            data: dataValues,
                            backgroundColor: ['#00a8cc', '#005082', '#ff8c00', '#6a0572', '#ab83a1', '#4bc0c0'],
                            hoverOffset: 10
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'bottom',
                                labels: {
                                    boxWidth: 12,
                                    padding: 15,
                                    generateLabels: (chart) => {
                                        const data = chart.data;
                                        return data.labels.map((label, i) => ({
                                            text: `${label} (${data.datasets[0].data[i]})`, 
                                            fillStyle: data.datasets[0].backgroundColor[i],
                                            index: i
                                        }));
                                    }
                                }
                            },
                            title: { display: true, text: 'Rules Distribution by Format', font: { size: 16, weight: 'bold' } }
                        }
                    }
                });
            }

            // --- LINE CHART (Timeline) ---
            if (lineCanvas.value && activity_data.value.timeline) {
                if (lineInstance) lineInstance.destroy();
                const timeline = activity_data.value.timeline;
                lineInstance = new Chart(lineCanvas.value.getContext('2d'), {
                    type: 'line',
                    data: {
                        labels: Object.keys(timeline),
                        datasets: [{
                            label: 'Rules Contribution',
                            data: Object.values(timeline),
                            borderColor: '#6366f1',
                            backgroundColor: 'rgba(99, 102, 241, 0.1)',
                            fill: true,
                            tension: 0.4
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            title: { display: true, text: 'Contribution History', font: { size: 16, weight: 'bold' } },
                            legend: { display: false }
                        }
                    }
                });
            }
        };

        Vue.watch([loading, barCanvas, pieCanvas, lineCanvas], ([L, B, P, Li]) => {
            if (!L && B && P && Li) Vue.nextTick(() => renderCharts());
        });

        Vue.onMounted(() => { if (actualUserId.value) fetchData(); });

        return { activity_data, loading, error, barCanvas, pieCanvas, lineCanvas };
    },
    template: `
    <div class="user-stats-container">
        <div v-if="loading" class="text-center p-5"><div class="spinner-border"></div></div>
        
        <div v-else-if="activity_data" class="content">
            <div class="row mb-4">
                <div class="col-md-4">
                    <div class="card shadow-sm border-0 text-center p-3">
                        <small class="text-muted text-uppercase">Trust Score</small>
                        <div class="h2 fw-bold text-primary">[[ activity_data.activity_stats.trust_score ]]%</div>
                        <div class="small">Community Approval</div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card shadow-sm border-0 text-center p-3">
                        <small class="text-muted text-uppercase">Total Rules</small>
                        <div class="h2 fw-bold">[[ activity_data.activity_stats.total_rules ]]</div>
                        <div class="small">Assets Published</div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card shadow-sm border-0 text-center p-3">
                        <small class="text-muted text-uppercase">Total Bundles</small>
                        <div class="h2 fw-bold text-info">[[ activity_data.activity_stats.total_bundles ]]</div>
                        <div class="small">Collections Shared</div>
                    </div>
                </div>
            </div>

            <div class="row">
                <div class="col-lg-8 mb-4">
                    <div class="card h-100 shadow-sm border-0">
                        <div class="card-body">
                            <div style="height: 300px;"><canvas ref="barCanvas"></canvas></div>
                        </div>
                    </div>
                </div>

                <div class="col-lg-4 mb-4">
                    <div class="card h-100 shadow-sm border-0">
                        <div class="card-body text-center">
                            <div style="height: 300px;"><canvas ref="pieCanvas"></canvas></div>
                        </div>
                    </div>
                </div>

                <div class="col-12 mb-4">
                    <div class="card shadow-sm border-0">
                        <div class="card-body">
                            <div style="height: 250px;"><canvas ref="lineCanvas"></canvas></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    `
};

export default UserActivityStatsComponent;