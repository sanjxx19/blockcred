export const ISSUER_URL = (import.meta.env.VITE_ISSUER_URL || 'http://localhost:4000').replace(/\/+$/, '');
export const VERIFIER_URL = (import.meta.env.VITE_VERIFIER_URL || 'http://localhost:5000').replace(/\/+$/, '');
export const EXPLORER_TX_URL = import.meta.env.VITE_EXPLORER_TX_URL || ''; // e.g. https://amoy.polygonscan.com/tx/
