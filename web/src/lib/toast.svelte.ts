export type Toast = { id: number; tone: 'success' | 'error' | 'info'; text: string };

class Toasts {
  items = $state<Toast[]>([]);
  private nextId = 1;

  private push(tone: Toast['tone'], text: string, ttl: number) {
    const id = this.nextId++;
    this.items.push({ id, tone, text });
    if (this.items.length > 4) this.items.shift();
    window.setTimeout(() => this.dismiss(id), ttl);
  }

  success = (text: string) => this.push('success', text, 4000);
  info = (text: string) => this.push('info', text, 6000);
  error = (text: string) => this.push('error', text, 8000);
  dismiss = (id: number) => {
    this.items = this.items.filter((item) => item.id !== id);
  };
}

export const toasts = new Toasts();
