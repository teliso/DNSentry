import { EN, EN_PATTERNS } from './en';

export type Language = 'zh' | 'en';

const STORAGE_KEY = 'dnsentry.language';
const ATTRIBUTES = ['placeholder', 'title', 'aria-label', 'alt'];

function initialLanguage(): Language {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === 'zh' || saved === 'en') return saved;
  } catch {
    /* storage unavailable */
  }
  return navigator.language?.toLowerCase().startsWith('zh') ? 'zh' : 'en';
}

/** Translates Chinese UI text into the current language; other text is returned unchanged. */
export function translate(text: string, language: Language): string {
  if (language === 'zh' || !/[一-龥]/.test(text)) return text;
  const lead = text.match(/^\s*/)?.[0] ?? '';
  const trail = text.match(/\s*$/)?.[0] ?? '';
  return lead + translateCore(text.trim()) + trail;
}

const PUNCTUATION: Record<string, string> = { '，': ', ', '。': '. ', '；': '; ', '：': ': ', '、': ', ' };

function translateCore(core: string): string {
  if (!/[一-龥]/.test(core)) return core;
  const exact = EN[core];
  if (exact !== undefined) return exact;
  for (const [pattern, replacement] of EN_PATTERNS) {
    const match = core.match(pattern);
    // Captured parts (names, other phrases) are translated as well.
    if (match) return replacement.replace(/\$(\d)/g, (_, index) => translateCore(match[Number(index)] ?? ''));
  }
  // Texts joined with " · " are translated piece by piece.
  if (core.includes(' · ')) return core.split(' · ').map(translateCore).join(' · ');
  // Several clauses: translate piece by piece.
  const pieces = core.split(/([，。；：、])/);
  if (pieces.length > 1) {
    return pieces
      .map((piece) => PUNCTUATION[piece] ?? translateCore(piece.trim()))
      .join('')
      .replace(/\s+([,.;:])/g, '$1')
      .trim();
  }
  return core;
}

class I18n {
  language = $state<Language>(initialLanguage());

  set(language: Language) {
    this.language = language;
    try {
      localStorage.setItem(STORAGE_KEY, language);
    } catch {
      /* storage unavailable */
    }
    document.documentElement.lang = language === 'zh' ? 'zh-CN' : 'en';
    apply(document.body);
  }

  /** For strings built in code (confirm dialogs, document title). */
  t = (text: string) => translate(text, this.language);
}

export const i18n = new I18n();
export const t = (text: string) => i18n.t(text);
/** confirm() with the question translated. */
export const ask = (text: string) => confirm(t(text));

// The interface text is Chinese in the source; for other languages the DOM is
// translated in place. originals remembers the Chinese text of each node so
// switching back (or a new value set by the framework) works.
const textOriginals = new WeakMap<Node, { original: string; shown: string }>();
const attrOriginals = new WeakMap<Element, Map<string, { original: string; shown: string }>>();

function applyText(node: Text) {
  const known = textOriginals.get(node);
  if (known && node.data === known.shown) {
    const next = translate(known.original, i18n.language);
    if (next !== known.shown) {
      node.data = next;
      known.shown = next;
    }
    return;
  }
  const original = node.data;
  const shown = translate(original, i18n.language);
  textOriginals.set(node, { original, shown });
  if (shown !== original) node.data = shown;
}

function applyAttributes(element: Element) {
  for (const name of ATTRIBUTES) {
    const value = element.getAttribute(name);
    if (value === null) continue;
    let map = attrOriginals.get(element);
    if (!map) attrOriginals.set(element, (map = new Map()));
    const known = map.get(name);
    if (known && value === known.shown) {
      const next = translate(known.original, i18n.language);
      if (next !== known.shown) {
        element.setAttribute(name, next);
        known.shown = next;
      }
      continue;
    }
    const shown = translate(value, i18n.language);
    map.set(name, { original: value, shown });
    if (shown !== value) element.setAttribute(name, shown);
  }
}

function apply(root: Node) {
  if (root.nodeType === Node.TEXT_NODE) {
    applyText(root as Text);
    return;
  }
  if (root.nodeType !== Node.ELEMENT_NODE && root.nodeType !== Node.DOCUMENT_FRAGMENT_NODE) return;
  if (root.nodeType === Node.ELEMENT_NODE) {
    const element = root as Element;
    if (element.tagName === 'SCRIPT' || element.tagName === 'STYLE') return;
    applyAttributes(element);
  }
  for (const child of Array.from(root.childNodes)) apply(child);
}

let observer: MutationObserver | undefined;

/** Starts translating the page and keeps following the framework's updates. */
export function startI18n() {
  document.documentElement.lang = i18n.language === 'zh' ? 'zh-CN' : 'en';
  if (observer) return;
  observer = new MutationObserver((records) => {
    observer?.disconnect();
    for (const record of records) {
      if (record.type === 'characterData') apply(record.target);
      else if (record.type === 'attributes') applyAttributes(record.target as Element);
      else record.addedNodes.forEach((node) => apply(node));
    }
    observe();
  });
  const observe = () => observer?.observe(document.body, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ATTRIBUTES });
  apply(document.body);
  observe();
}
