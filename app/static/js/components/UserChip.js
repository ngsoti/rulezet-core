/**
 * UserChip — inline user avatar + name with a hover tooltip card.
 *
 * Props:
 *   user-id   (Number)  — required; used to fetch tooltip data + link target
 *   username  (String)  — display name (shown immediately, no fetch needed)
 *   avatar    (String)  — avatar URL (optional; falls back to initials)
 *   size      (String)  — 'xs' | 'sm' | 'md' | 'lg' (default 'xs')
 *   show-name (Boolean) — whether to render the text label (default true)
 *
 * Usage (Vue template):
 *   <user-chip :user-id="rule.user_id" :username="rule.editor" :avatar="rule.editor_avatar" />
 */

const { defineComponent, ref, computed, onMounted, onBeforeUnmount, h, Teleport } = Vue;

const _cache = {};

function fetchMini(userId) {
    if (_cache[userId]) return Promise.resolve(_cache[userId]);
    return fetch(`/account/user_mini/${userId}`)
        .then(r => r.ok ? r.json() : null)
        .then(data => { if (data) _cache[userId] = data; return data; });
}

function getInitials(name) {
    if (!name) return '?';
    return name.trim()[0].toUpperCase();
}

const UserChip = defineComponent({
    name: 'UserChip',
    delimiters: ['[[', ']]'],
    props: {
        userId:   { type: Number, required: true },
        username: { type: String, default: '' },
        avatar:   { type: String, default: null },
        size:     { type: String, default: 'xs' },
        showName: { type: Boolean, default: true },
    },

    setup(props) {
        const tooltipData    = ref(null);
        const tooltipVisible = ref(false);
        const tooltipStyle   = ref({});
        const chipRef        = ref(null);
        let showTimer = null;
        let hideTimer = null;
        let tooltipEl = null;

        const sizeMap = { xs: 22, sm: 28, md: 36, lg: 64 };
        const px = computed(() => sizeMap[props.size] || 22);

        const displayName = computed(() => props.username || (tooltipData.value && tooltipData.value.username) || '?');
        const initials    = computed(() => getInitials(displayName.value));

        function positionTooltip() {
            if (!chipRef.value) return;
            const rect = chipRef.value.getBoundingClientRect();
            const scrollY = window.scrollY;
            const scrollX = window.scrollX;
            // try below first, flip to above if not enough space
            let top = rect.bottom + scrollY + 6;
            let left = rect.left + scrollX;
            if (rect.bottom + 220 > window.innerHeight) {
                top = rect.top + scrollY - 220 - 6;
            }
            if (left + 260 > window.innerWidth) {
                left = window.innerWidth - 268;
            }
            tooltipStyle.value = { top: top + 'px', left: left + 'px' };
        }

        function onMouseEnter() {
            clearTimeout(hideTimer);
            showTimer = setTimeout(async () => {
                positionTooltip();
                if (!tooltipData.value) {
                    tooltipData.value = await fetchMini(props.userId);
                }
                tooltipVisible.value = true;
                positionTooltip();
            }, 150);
        }

        function onMouseLeave() {
            clearTimeout(showTimer);
            hideTimer = setTimeout(() => {
                tooltipVisible.value = false;
            }, 120);
        }

        function onTooltipEnter() { clearTimeout(hideTimer); }
        function onTooltipLeave() {
            hideTimer = setTimeout(() => { tooltipVisible.value = false; }, 120);
        }

        // expose tooltip handler refs so the teleported tooltip can cancel hide
        return {
            tooltipData, tooltipVisible, tooltipStyle, chipRef,
            px, displayName, initials,
            onMouseEnter, onMouseLeave, onTooltipEnter, onTooltipLeave,
        };
    },

    template: `
<span style="display:inline-flex;align-items:center;gap:5px;vertical-align:middle;">
  <a
    ref="chipRef"
    :href="'/account/detail_user/' + userId"
    class="user-chip-anchor"
    style="display:inline-flex;align-items:center;gap:5px;text-decoration:none;color:inherit;"
    @mouseenter="onMouseEnter"
    @mouseleave="onMouseLeave"
    @click.stop
  >
    <!-- Avatar -->
    <span
      class="user-chip-avatar"
      :style="{
        width: px + 'px', height: px + 'px',
        fontSize: (px * 0.42) + 'px',
        flexShrink: 0,
        display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
        borderRadius: '50%',
        overflow: 'hidden',
        background: avatar ? 'transparent' : 'var(--bs-primary)',
        color: '#fff',
        fontWeight: '700',
        border: '1.5px solid var(--border-color, #dee2e6)',
      }"
    >
      <img v-if="avatar" :src="avatar" :style="{width:'100%',height:'100%',objectFit:'cover'}" />
      <template v-else>[[ initials ]]</template>
    </span>
    <!-- Name -->
    <span v-if="showName" class="user-chip-name" style="font-size:0.8rem;color:var(--subtle-text-color);">
      [[ displayName ]]
    </span>
  </a>

  <!-- Tooltip teleported to body -->
  <teleport to="body">
    <div
      v-if="tooltipVisible"
      class="user-chip-tooltip"
      :style="[tooltipStyle, {position:'absolute',zIndex:9999,minWidth:'240px',maxWidth:'280px'}]"
      @mouseenter="onTooltipEnter"
      @mouseleave="onTooltipLeave"
    >
      <div class="user-chip-tooltip__inner">
        <!-- Header -->
        <div class="d-flex align-items-center gap-3 mb-2">
          <span
            class="user-chip-avatar user-chip-tooltip__avatar"
            style="width:44px;height:44px;font-size:18px;flex-shrink:0;display:inline-flex;align-items:center;justify-content:center;border-radius:50%;overflow:hidden;background:var(--bs-primary);color:#fff;font-weight:700;border:2px solid var(--border-color,#dee2e6);"
          >
            <img v-if="(tooltipData && tooltipData.avatar) || avatar"
                 :src="(tooltipData && tooltipData.avatar) || avatar"
                 style="width:100%;height:100%;object-fit:cover;" />
            <template v-else>[[ initials ]]</template>
          </span>
          <div>
            <div class="fw-semibold" style="font-size:.9rem;color:var(--text-color);">[[ displayName ]]</div>
            <div v-if="tooltipData && tooltipData.location" class="text-muted" style="font-size:.75rem;">
              <i class="fa-solid fa-location-dot me-1" style="font-size:.65rem;"></i>[[ tooltipData.location ]]
            </div>
            <div v-else-if="!tooltipData" class="user-chip-tooltip__skeleton" style="height:10px;width:80px;margin-top:4px;"></div>
          </div>

          <!-- Admin / Roles — top-right of the header row -->
          <div v-if="tooltipData && ((tooltipData.roles && tooltipData.roles.length) || tooltipData.is_admin)"
               class="d-flex flex-wrap justify-content-end gap-1 ms-auto" style="max-width:100px;">
            <span v-if="tooltipData.is_admin" class="badge bg-warning text-dark" style="font-size:.65rem;">
              <i class="fa-solid fa-crown me-1"></i>Admin
            </span>
            <span v-for="r in tooltipData.roles" :key="r.id"
                  class="badge bg-primary-subtle text-primary" style="font-size:.65rem;">
              <i class="fa-solid fa-user-shield me-1"></i>[[ r.name ]]
            </span>
          </div>
        </div>

        <!-- Bio -->
        <p v-if="tooltipData && tooltipData.bio"
           class="mb-2 text-muted"
           style="font-size:.78rem;line-height:1.4;max-height:52px;overflow:hidden;">
          [[ tooltipData.bio ]]
        </p>

        <!-- Stats row -->
        <div v-if="tooltipData" class="d-flex gap-3 mb-2" style="font-size:.75rem;color:var(--subtle-text-color);">
          <span><i class="fa-solid fa-file-shield me-1 opacity-50"></i><strong>[[ tooltipData.rules_count ]]</strong> rules</span>
          <span><i class="fa-solid fa-users me-1 opacity-50"></i><strong>[[ tooltipData.followers ]]</strong> followers</span>
          <span v-if="tooltipData.created_at"><i class="fa-regular fa-calendar me-1 opacity-50"></i>[[ tooltipData.created_at ]]</span>
        </div>
        <div v-else class="d-flex gap-3 mb-2">
          <span class="user-chip-tooltip__skeleton" style="height:10px;width:55px;"></span>
          <span class="user-chip-tooltip__skeleton" style="height:10px;width:65px;"></span>
        </div>

        <!-- View profile link -->
        <a :href="'/account/detail_user/' + userId"
           class="btn btn-sm btn-outline-primary w-100 mt-1"
           style="font-size:.75rem;padding:3px 0;"
           @click.stop>
          <i class="fa-solid fa-arrow-up-right-from-square me-1"></i>View profile
        </a>
      </div>
    </div>
  </teleport>
</span>
`,
});

export default UserChip;
