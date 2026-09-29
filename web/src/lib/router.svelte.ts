export const ROUTES = ['overview', 'filters', 'sources', 'logs', 'upstreams', 'settings'] as const;
export type Route = (typeof ROUTES)[number];

const LEGACY: Record<string, Route> = { rules: 'filters' };

function parse(hash: string): Route {
  const name = hash.replace(/^#\/?/, '');
  const route = LEGACY[name] ?? name;
  return (ROUTES as readonly string[]).includes(route) ? (route as Route) : 'overview';
}

class Router {
  current = $state<Route>(parse(window.location.hash));

  constructor() {
    window.addEventListener('hashchange', () => {
      this.current = parse(window.location.hash);
    });
  }

  go(route: Route) {
    if (window.location.hash !== `#${route}`) window.location.hash = route;
  }
}

export const router = new Router();
