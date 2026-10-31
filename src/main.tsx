import { createRoot } from 'react-dom/client';
import App from './App.tsx';
import './index.css';

// Safely register minimal service worker for PWA installability in supported browsers
if (typeof window !== 'undefined' && 'serviceWorker' in navigator && process.env.NODE_ENV !== 'test') {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch((err) => {
      if (process.env.NODE_ENV === 'development') {
        console.debug('ServiceWorker registration skipped or failed:', err);
      }
    });
  });
}

createRoot(document.getElementById('root')!).render(<App />);
