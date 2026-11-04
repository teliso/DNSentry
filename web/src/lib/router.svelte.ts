/** Pages and their tabs. The first tab of a page is its default. */
export const PAGES = {
  overview: [],
  logs: ['queries', 'program'],
  filters: ['rules', 'sources', 'services', 'schedule', 'blocking'],
  dns: ['upstreams', 'routes', 'records', 'cache', 'advanced'],
  settings: ['network', 'account', 'notifications', 'encryption', 'logging', 'maintenance']
} as const;

export type Page = keyof typeof PAGES;
/** `page` or `page/tab`, as written after `#` in the address bar. */
export type Target = Page | `${Page}/${string}`;

/** Names from earlier versions keep working for bookmarks. */
const LEGACY: Record<string, string> = {
  sources: 'filters/sources',
  rules: 'filters/rules',
  records: 'dns/records',
  upstreams: 'dns/upstreams'
};

function parse(hash: string): { page: Page; tab: string } {
  const [first = '', second = ''] = hash.replace(/^#\/?/, '').split('/');
  const [name, tab] = (LEGACY[first] ?? `${first}/${second}`).split('/');
  const page = (name in PAGES ? name : 'overview') as Page;
  const tabs = PAGES[page] as readonly string[];
  return { page, tab: tabs.includes(tab) ? tab : (tabs[0] ?? '') };
}

class Router {
  current = $state<Page>('overview');
  tab = $state('');

  constructor() {
    this.sync();
    window.addEventListener('hashchange', () => this.sync());
  }

  private sync() {
    const next = parse(window.location.hash);
    const pageChanged = next.page !== this.current;
    this.current = next.page;
    this.tab = next.tab;
    if (pageChanged) window.scrollTo({ top: 0 });
  }

  href(target: Target) {
    return `#${target}`;
  }

  go(target: Target) {
    if (window.location.hash !== `#${target}`) window.location.hash = target;
  }
}

export const router = new Router();
