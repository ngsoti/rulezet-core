export default {
    props: {
        currentPage: { type: Number, required: true },
        totalPages: { type: Number, required: true }
    },
    emits: ['change-page'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const inputPage = Vue.ref(props.currentPage);
        const isEditing = Vue.ref(false);

        const visiblePages = Vue.computed(() => {
            const total = props.totalPages;
            const current = props.currentPage;
            const delta = 2; 
            
            if (total <= 10) {
                return Array.from({ length: total }, (_, i) => i + 1);
            }

            const range = [];
            const left = current - delta;
            const right = current + delta;

            range.push(1); 

            if (left > 2) range.push('...');

            for (let i = Math.max(2, left); i <= Math.min(total - 1, right); i++) {
                range.push(i);
            }

            if (right < total - 1) range.push('...');

            range.push(total); 

            return range;
        });

        const goToPage = () => {
            const val = parseInt(inputPage.value);
            if (!isNaN(val) && val >= 1 && val <= props.totalPages) {
                emit('change-page', val);
            } else {
                inputPage.value = props.currentPage;
            }
            isEditing.value = false;
        };

        return { visiblePages, emit, isEditing, inputPage, goToPage };
    },
    template: `
    <nav v-if="totalPages > 1" class="d-flex flex-column align-items-center my-4">
        <ul class="pagination pagination-sm shadow-sm rounded border-0 mb-2">
            <li class="page-item" :class="{ disabled: currentPage === 1 }">
                <a class="page-link border-0 text-dark" href="#" @click.prevent="emit('change-page', currentPage - 1)">
                    <i class="fas fa-chevron-left"></i>
                </a>
            </li>
            
            <li v-for="(page, index) in visiblePages" :key="index" 
                class="page-item" :class="{ active: page === currentPage }">
                
                <a v-if="page !== '...'" class="page-link border-0 fw-bold" href="#" 
                   @click.prevent="emit('change-page', page)">
                    [[ page ]]
                </a>

                <a v-else class="page-link border-0 text-muted" href="#" 
                   @click.prevent="isEditing = !isEditing" style="cursor: pointer;">
                    ...
                </a>
            </li>

            <li class="page-item" :class="{ disabled: currentPage === totalPages }">
                <a class="page-link border-0 text-dark" href="#" @click.prevent="emit('change-page', currentPage + 1)">
                    <i class="fas fa-chevron-right"></i>
                </a>
            </li>
        </ul>

        <div v-if="isEditing" class="animate__animated animate__fadeIn">
            <div class="input-group input-group-sm" style="width: 130px;">
                <input 
                    type="number" 
                    v-model="inputPage" 
                    class="form-control text-center shadow-none" 
                    placeholder="Page..."
                    @keyup.enter="goToPage"
                    v-focus
                >
                <button class="btn btn-primary" type="button" @click="goToPage">Go</button>
            </div>
        </div>
        <div v-else @click="isEditing = true" class="text-muted small" style="cursor: pointer; font-size: 0.7rem;">
            Page [[ currentPage ]] of [[ totalPages ]]
        </div>
    </nav>
    `,
    directives: {
        focus: {
            mounted(el) {
                el.focus();
                el.select();
            }
        }
    }
};