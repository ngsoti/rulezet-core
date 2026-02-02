export const emodji_picker = {
    map: {
        '❤️': 'heart',
        '🔥': 'fire',
        '😂': 'joy',
        '🙌': 'raised_hands',
        '🚀': 'rocket',
        '😮': 'wow',
        '😢': 'sad',
        '💯': 'hundred',
        '🎉': 'party'
    },

    getIcons() {
        return Object.keys(this.map);
    },
    getSlug(emoji) {
        return this.map[emoji] || emoji;
    },

    getEmoji(slug) {
        return Object.keys(this.map).find(key => this.map[key] === slug) || slug;
    }
};