import { mount } from 'svelte';
import App from './App.svelte';
import './app.css';
import './lib/theme.svelte';
import { prepareI18n, startI18n } from './lib/i18n/index.svelte';

void prepareI18n().then(() => {
  mount(App, { target: document.getElementById('app')! });
  startI18n();
});
