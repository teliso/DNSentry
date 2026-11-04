import { mount } from 'svelte';
import App from './App.svelte';
import './app.css';
import './lib/theme.svelte';
import { startI18n } from './lib/i18n/index.svelte';

mount(App, { target: document.getElementById('app')! });
startI18n();
