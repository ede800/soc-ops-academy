import type { Block, Lang } from '../types'

export const r = String.raw
export const p = (text: string): Block => ({ type: 'p', text })
export const h = (text: string): Block => ({ type: 'h', text })
export const ul = (...items: string[]): Block => ({ type: 'list', items })
export const ol = (...items: string[]): Block => ({ type: 'list', items, ordered: true })
export const table = (headers: string[], ...rows: string[][]): Block => ({ type: 'table', headers, rows })
export const code = (lang: Lang, title: string, content: string): Block => ({
  type: 'code',
  lang,
  title,
  code: content.trim(),
})
export const links = (...items: { to: string; label: string }[]): Block => ({ type: 'links', items })
export const info = (title: string, text: string): Block => ({ type: 'callout', tone: 'info', title, text })
export const tip = (title: string, text: string): Block => ({ type: 'callout', tone: 'tip', title, text })
export const warn = (title: string, text: string): Block => ({ type: 'callout', tone: 'warn', title, text })
export const danger = (title: string, text: string): Block => ({ type: 'callout', tone: 'danger', title, text })
