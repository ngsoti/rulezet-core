import VulnerabilityDisplaysList from '/static/js/vulnerability/vulnerabilityDisplayList.js'
import TagsDisplaysList from '/static/js/tags/tagsDisplaysList.js'

const { ref, computed, onMounted, onBeforeUnmount, nextTick, watch } = Vue
import { message_list, create_message } from '/static/js/toaster.js'

const RulesCarousel = {
    name: 'RulesCarousel',
    delimiters: ['[[', ']]'],

    components: {
        'vulnerability-displays-list': VulnerabilityDisplaysList,
        'tags-displays-list': TagsDisplaysList,
    },

    props: {
        /* URL de l'endpoint Flask qui retourne { rules: [...] } */
        route: {
            type: String,
            required: true,
        },
        /* ID de l'utilisateur courant pour le menu edit/delete */
        currentUserId: {
            type: Number,
            default: null,
        },
        currentUserIsAdmin: {
            type: Boolean,
            default: false,
        },
        currentUserIsConnected: {
            type: Boolean,
            default: false,
        },
    },

    template: `
    <div>
        <!-- Loading -->
        <div v-if="loading" class="text-center py-5">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
        </div>

        <!-- Carousel -->
        <template v-else-if="rules_list.length > 0">
            <div class="carousel-rules-wrapper">

                <button class="carousel-arrow"
                        @click="carouselSlide(-1)"
                        :disabled="carouselIndex === 0"
                        title="Previous">
                    <i class="fa-solid fa-arrow-left"></i>
                </button>

                <!-- Outer overflow hidden -->
                <div class="carousel-rules-outer"
                     :class="{ 'at-start': carouselIndex === 0, 'at-end': carouselIndex >= rules_list.length - carouselVisible }"
                     ref="carouselOuter">

                    <div class="carousel-rules-track"
                         ref="carouselTrack"
                         :style="{
                             transform: 'translateX(-' + carouselOffset + 'px)',
                             transition: isDragging ? 'none' : 'transform 0.42s cubic-bezier(0.4,0,0.2,1)'
                         }"
                         @mousedown="dragStart"
                         @touchstart.passive="touchStart"
                         @touchmove.passive="touchMove"
                         @touchend="touchEnd">

                        <div class="carousel-item-wrap"
                             v-for="(rule, index) in rules_list"
                             :key="rule.uuid || rule.id">

                            <div class="card h-100 shadow-sm border-0"
                                 style="position: relative; overflow: hidden; border-radius: 12px;">

                                <div class="premium-accent-line"></div>

                                <div class="card-watermark">
                                    <i class="fa-solid fa-shield-halved"></i>
                                </div>

                                <div class="position-absolute top-0 end-0 mt-3 me-3 shadow-sm z-index-2">
                                    <span class="badge rounded-pill bg-dark pt-1">[[ rule.format.toUpperCase() ]]</span>
                                </div>

                                <div class="card-body d-flex flex-column p-4 z-index-1">
                                    <div class="mb-3 pe-5">
                                        <h5 class="fw-bold mb-1">
                                            <a :href="'/rule/detail_rule/' + rule.id"
                                               class="fw-bold h5 mb-4 border-start border-primary border-4 ps-3 custom-rule-link"
                                               title="See more about this rule">
                                                [[ rule.title ]]
                                            </a>
                                        </h5>
                                        <div class="d-flex align-items-center gap-2 mt-2">
                                            <div class="avatar-circle-xs" title="Author of the rule">
                                                [[ rule.author === 'Unknown' ? rule.editor[0].toUpperCase() : rule.author[0].toUpperCase() ]]
                                            </div>
                                            <small class="text-muted fw-medium" title="Author of the rule">
                                                [[ rule.author === 'Unknown' ? rule.editor : rule.author ]]
                                            </small>
                                            <span class="text-muted opacity-50">|</span>
                                            <small class="text-muted" title="Last modification of the rule">
                                                [[ fromNow(rule.last_modif) ]]
                                            </small>
                                        </div>
                                    </div>

                                    <div class="flex-grow-1">
                                        <p class="text-muted small lh-base" title="Description of the rule">
                                            <template v-if="!rule.show_full">
                                                [[ rule.description.substring(0, 140) ]]
                                                <span v-if="rule.description.length > 140">...</span>
                                                <a v-if="rule.description.length > 140"
                                                   href="#"
                                                   @click.prevent="rule.show_full = true"
                                                   class="text-primary text-decoration-none fw-semibold ms-1">Read more</a>
                                            </template>
                                            <template v-else>
                                                [[ rule.description ]]
                                                <a href="#"
                                                   @click.prevent="rule.show_full = false"
                                                   class="text-primary text-decoration-none fw-semibold ms-1">Show less</a>
                                            </template>
                                        </p>
                                    </div>

                                    <div class="mb-3" @click.stop>
                                        <vulnerability-displays-list object-type="rule" :object-id="rule.id" :max-visible="1">
                                        </vulnerability-displays-list>
                                    </div>
                                    <div class="mb-3" @click.stop>
                                        <tags-displays-list object-type="rule" :object-id="rule.id" :max-visible="1">
                                        </tags-displays-list>
                                    </div>

                                    <div class="d-flex justify-content-between align-items-center pt-3 border-top mt-auto bg-transparent">
                                        <div class="btn-group shadow-sm border rounded-pill overflow-hidden">
                                            <button @click="doVote('up', rule.id); animateClick($event)"
                                                    class="btn btn-sm px-3 border-0 border-end border-light shadow-none btn-animate home-btn"
                                                    title="Like this rule">
                                                <i class="fas fa-thumbs-up text-primary me-1"></i> [[ rule.vote_up ]]
                                            </button>
                                            <button @click="doVote('down', rule.id); animateClick($event)"
                                                    class="btn btn-sm px-3 border-0 shadow-none btn-animate home-btn"
                                                    title="Dislike this rule">
                                                <i class="fas fa-thumbs-down text-danger me-1"></i> [[ rule.vote_down ]]
                                            </button>
                                        </div>

                                        <div class="d-flex gap-2">
                                            <button
                                                @click="doFavorite(rule.id); $event.currentTarget.classList.add('star-animate')"
                                                @animationend="$event.currentTarget.classList.remove('star-animate')"
                                                :title="rule.is_favorited ? 'Unfavorite this rule' : 'Favorite this rule'"
                                                class="btn btn-sm rounded-circle shadow-sm p-0 d-flex align-items-center justify-content-center transition-all home-btn"
                                                style="width: 32px; height: 32px;">
                                                <i class="fa-star" :class="rule.is_favorited ? 'fas text-warning' : 'far'"></i>
                                            </button>

                                            <div class="dropdown">
                                                <button class="btn btn-sm rounded-circle shadow-sm p-0 d-flex align-items-center justify-content-center home-btn"
                                                        style="width: 32px; height: 32px;"
                                                        data-bs-toggle="dropdown">
                                                    <i class="fas fa-ellipsis-h"></i>
                                                </button>
                                                <ul class="dropdown-menu dropdown-menu-end shadow border-0">
                                                    <li v-if="currentUserId === rule.user_id || currentUserIsAdmin">
                                                        <a class="dropdown-item" :href="'rule/edit_rule/' + rule.id">
                                                            <i class="fas fa-edit me-2 text-muted"></i> Edit Rule
                                                        </a>
                                                    </li>
                                                    <li>
                                                        <a class="dropdown-item" :href="'/rule/report/' + rule.id">
                                                            <i class="fas fa-flag me-2 text-muted"></i> Report issue
                                                        </a>
                                                    </li>
                                                </ul>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>

                    </div>
                </div>

                <!-- Flèche droite -->
                <button class="carousel-arrow"
                        @click="carouselSlide(1)"
                        :disabled="carouselIndex >= rules_list.length - carouselVisible"
                        title="Next">
                    <i class="fa-solid fa-arrow-right"></i>
                </button>

            </div>

            <!-- Dots -->
            <div class="carousel-rules-dots">
                <button class="carousel-rules-dot"
                        v-for="(_, i) in carouselDots"
                        :key="i"
                        :class="{ active: i === carouselIndex }"
                        @click="carouselGoTo(i)">
                </button>
            </div>
        </template>

        <!-- Empty state -->
        <div v-else class="col-12 text-center py-5">
            <img src="https://cdn-icons-png.flaticon.com/512/7486/7486744.png" alt="No rules"
                 style="width: 80px; opacity: 0.3;">
            <p class="text-muted mt-3">No recent rules found. Check back later!</p>
        </div>
    </div>
    `,

    setup(props) {
        /* ── données ── */
        const loading    = ref(true)
        const rules_list = ref([])

        /* ── carousel ── */
        const carouselIndex   = ref(0)
        const carouselOffset  = ref(0)
        const carouselVisible = ref(3)
        const isDragging      = ref(false)
        let   dragStartX      = 0
        let   touchStartX     = 0
        let   resizeObserver  = null

        const carouselOuter = ref(null)
        const carouselTrack = ref(null)

        const carouselDots = computed(() =>
            Math.max(0, rules_list.value.length - carouselVisible.value + 1)
        )

        /* ── fetch ── */
        async function fetchRules() {
            loading.value = true
            try {
                const res = await fetch(props.route)
                if (res.ok) {
                    const data = await res.json()
                    rules_list.value = (data.rules || []).map(r => ({ ...r, show_full: false }))
                }
            } catch (e) {
                console.error('[RulesCarousel] fetch error:', e)
            } finally {
                loading.value = false
                await nextTick()
                updateVisible()
                if (carouselOuter.value) {
                    resizeObserver = new ResizeObserver(() => updateVisible())
                    resizeObserver.observe(carouselOuter.value)
                }
            }
        }

        /* ── carousel helpers ── */
        function getItemWidth() {
            if (!carouselTrack.value) return 0
            const item = carouselTrack.value.querySelector('.carousel-item-wrap')
            if (!item) return 0
            return item.offsetWidth + 24
        }

        function updateVisible() {
            const w = carouselOuter.value?.offsetWidth || window.innerWidth
            if      (w < 576)  carouselVisible.value = 1
            else if (w < 992)  carouselVisible.value = 2
            else               carouselVisible.value = 3
            const max = Math.max(0, rules_list.value.length - carouselVisible.value)
            if (carouselIndex.value > max) carouselIndex.value = max
            updateOffset()
        }

        function updateOffset() {
            carouselOffset.value = carouselIndex.value * getItemWidth()
        }

        function carouselSlide(dir) {
            const max = Math.max(0, rules_list.value.length - carouselVisible.value)
            carouselIndex.value = Math.max(0, Math.min(carouselIndex.value + dir, max))
            updateOffset()
        }

        function carouselGoTo(i) {
            carouselIndex.value = i
            updateOffset()
        }

        /* drag souris */
        function dragStart(e) {
            isDragging.value = true
            dragStartX = e.clientX
            window.addEventListener('mousemove', dragMove)
            window.addEventListener('mouseup',   dragEnd)
        }
        function dragMove(e) {
            if (!isDragging.value) return
            carouselOffset.value = carouselIndex.value * getItemWidth() + (dragStartX - e.clientX)
        }
        function dragEnd(e) {
            if (!isDragging.value) return
            isDragging.value = false
            window.removeEventListener('mousemove', dragMove)
            window.removeEventListener('mouseup',   dragEnd)
            const diff = dragStartX - e.clientX
            if (Math.abs(diff) > 60) carouselSlide(diff > 0 ? 1 : -1)
            else updateOffset()
        }

        /* swipe tactile */
        function touchStart(e) { touchStartX = e.touches[0].clientX }
        function touchMove(e) {
            carouselOffset.value = carouselIndex.value * getItemWidth() + (touchStartX - e.touches[0].clientX)
        }
        function touchEnd(e) {
            const diff = touchStartX - e.changedTouches[0].clientX
            if (Math.abs(diff) > 50) carouselSlide(diff > 0 ? 1 : -1)
            else updateOffset()
        }

        /* ── vote / favorite ── */
        async function doVote(voteType, ruleId) {
            if (!props.currentUserIsConnected) { window.location.href = '/account/login'; return }
            const res  = await fetch(`/rule/vote_rule?id=${ruleId}&vote_type=${voteType}`)
            const data = await res.json()
            const rule = rules_list.value.find(r => r.id === ruleId)
            if (rule) { rule.vote_up = data.vote_up; rule.vote_down = data.vote_down }
        }

        async function doFavorite(ruleId) {
            if (!props.currentUserIsConnected) { window.location.href = '/account/login'; return }
            const res  = await fetch(`/rule/favorite/${ruleId}`)
            const data = await res.json()
            if (res.ok) {
                const rule = rules_list.value.find(r => r.id === ruleId)
                if (rule) rule.is_favorited = data.is_favorited
            }
            create_message(data.message, data.toast_class, false, null, '/rule/owner_rules')
        }

        function animateClick(event) {
            const btn = event.currentTarget
            btn.classList.add('click-pop')
            setTimeout(() => btn.classList.remove('click-pop'), 300)
        }

        /* dayjs safe wrapper */
        function fromNow(dateStr) {
            if (!dateStr) return ''
            const djs = window.dayjs
            if (djs) {
                try {
                    return djs.utc ? djs.utc(dateStr).fromNow() : djs(dateStr).fromNow()
                } catch (_) {}
            }
            const diff  = Date.now() - new Date(dateStr).getTime()
            const mins  = Math.floor(diff / 60000)
            const hours = Math.floor(diff / 3600000)
            const days  = Math.floor(diff / 86400000)
            if (mins  < 1)  return 'just now'
            if (mins  < 60) return `${mins}m ago`
            if (hours < 24) return `${hours}h ago`
            if (days  < 30) return `${days}d ago`
            return new Date(dateStr).toLocaleDateString()
        }

        watch(() => props.route, fetchRules)

        onMounted(() => fetchRules())
        onBeforeUnmount(() => {
            if (resizeObserver) resizeObserver.disconnect()
            window.removeEventListener('mousemove', dragMove)
            window.removeEventListener('mouseup',   dragEnd)
        })

        return {
            loading, rules_list,
            carouselIndex, carouselOffset, carouselVisible, carouselDots, isDragging,
            carouselOuter, carouselTrack,
            carouselSlide, carouselGoTo,
            dragStart, dragMove, dragEnd,
            touchStart, touchMove, touchEnd,
            doVote, doFavorite, animateClick, fromNow,
        }
    }
}

export default RulesCarousel