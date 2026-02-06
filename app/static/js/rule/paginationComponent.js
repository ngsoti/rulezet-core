export default {
    props: {
        currentPage: { type: Number, required: true },
        totalPages: { type: Number, required: true }
    },
    emits: ['change-page'],
    delimiters: ['[[', ']]'],
    setup(props, { emit }) {
        const visiblePages = Vue.computed(() => {
            const pages = [];
            const total = props.totalPages;
            const current = props.currentPage;
            if (total <= 7) {
                for (let i = 1; i <= total; i++) pages.push(i);
            } else {
                if (current <= 4) pages.push(1, 2, 3, 4, 5, '...', total);
                else if (current >= total - 3) pages.push(1, '...', total - 4, total - 3, total - 2, total - 1, total);
                else pages.push(1, '...', current - 1, current, current + 1, '...', total);
            }
            return pages;
        });

        return { visiblePages, emit };
    },
    template: `
    <nav v-if="totalPages > 1" class="d-flex justify-content-center my-4">
        <ul class="pagination pagination-sm shadow-sm rounded">
            <li class="page-item" :class="{ disabled: currentPage === 1 }">
                <a class="page-link border-0" href="#" @click.prevent="emit('change-page', currentPage - 1)">
                    <i class="fas fa-chevron-left"></i>
                </a>
            </li>
            
            <li v-for="page in visiblePages" :key="page" class="page-item" :class="{ active: page === currentPage, disabled: page === '...' }">
                <a class="page-link border-0" href="#" @click.prevent="page !== '...' && emit('change-page', page)">
                    [[ page ]]
                </a>
            </li>

            <li class="page-item" :class="{ disabled: currentPage === totalPages }">
                <a class="page-link border-0" href="#" @click.prevent="emit('change-page', currentPage + 1)">
                    <i class="fas fa-chevron-right"></i>
                </a>
            </li>
        </ul>
    </nav>
    `
};