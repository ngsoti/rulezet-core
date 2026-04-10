/**
 * toaster.js — Rulezet custom toast system
 * Drop-in replacement — same API: create_message(), display_toast()
 * No Bootstrap Toast dependency.
 */

const { nextTick, ref } = Vue
export const message_list = ref([])

const DURATION = 8000  // ms before auto-dismiss

function manage_icon(toast_class) {
  switch (toast_class) {
    case 'success-subtle':
    case 'success':
      return 'fas fa-check'
    case 'warning-subtle':
    case 'warning':
      return 'fas fa-triangle-exclamation'
    case 'danger-subtle':
    case 'danger':
    case 'error':
      return 'fas fa-xmark'
    case 'info-subtle':
    case 'info':
      return 'fas fa-circle-info'
    default:
      return 'fas fa-bell'
  }
}

/**
 * Map Bootstrap "bg-xxx-subtle" class names → our variant names
 * e.g. "success-subtle" → "success"
 */
function to_variant(toast_class) {
  return (toast_class || '').replace('-subtle', '') || 'info'
}

function dismiss(id) {
  const el = document.getElementById('rz-toast-' + id)
  if (!el) return
  el.classList.remove('rz-show')
  el.classList.add('rz-hide')
  setTimeout(() => {
    message_list.value = message_list.value.filter(m => m.id !== id)
  }, 300)
}

export async function create_message(message, toast_class, not_hide, icon) {
  const id = Math.random().toString(36).slice(2)
  if (!icon) icon = manage_icon(toast_class)
  const variant = to_variant(toast_class)

  const message_loc = { id, message, toast_class, variant, icon, not_hide }
  message_list.value.push(message_loc)
  await nextTick()

  const el = document.getElementById('rz-toast-' + id)
  if (!el) return

  // Set progress bar duration
  const bar = el.querySelector('.rz-toast__bar')
  if (bar) {
    if (not_hide) {
      bar.style.display = 'none'
    } else {
      bar.style.animationDuration = DURATION + 'ms'
    }
  }

  // Trigger slide-in (double rAF ensures transition fires after paint)
  requestAnimationFrame(() => {
    requestAnimationFrame(() => el.classList.add('rz-show'))
  })

  // Auto-dismiss
  if (!not_hide) {
    setTimeout(() => dismiss(id), DURATION)
  }

  // Expose dismiss on close button
  el.querySelector('.rz-toast__close')?.addEventListener('click', () => dismiss(id))
}

export async function display_toast(res, not_hide = false) {
  const loc = await res.json()
  if (typeof loc['message'] === 'object') {
    for (let i in loc['message']) {
      await create_message(loc['message'][i], loc['toast_class'][i], not_hide, loc['icon'])
    }
  } else {
    await create_message(loc['message'], loc['toast_class'], not_hide, loc['icon'])
  }
}