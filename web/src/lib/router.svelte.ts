export const ROUTES = ['overview', 'logs', 'filters', 'sources', 'records', 'dns', 'settings'] as const;
export type Route = (typeof ROUTES)[number];

/** Old hash names keep working for bookmarks. */
const LEGACY: Record<string, Route> = { rules: 'filters', upstreams: 'dns' };

function parse(hash: string): Route {
  const name = hash.replace(/^#\/?/, '').split('/')[0];
  const route = LEGACY[name] ?? name;
  return (ROUTES as readonly string[]).includes(route) ? (route as Route) : 'overview';
}

class Router {
  current = $state<Route>(parse(window.location.hash));

  constructor() {
    window.addEventListener('hashchange', () => {
      const next = parse(window.location.hash);
      if (next !== this.current) {
        this.current = next;
        window.scrollTo({ top: 0 });
      }
    });
  }

  go(route: Route) {
    if (window.location.hash !== `#${route}`) window.location.hash = route;
  }
}

export const router = new Router();
