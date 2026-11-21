import { useEffect, useState } from 'react';
import Issuer from './pages/Issuer.jsx';
import Verifier from './pages/Verifier.jsx';
import Wallet from './pages/Wallet.jsx';

const ROUTES = {
  wallet: { label: 'Wallet', subtitle: 'Student', Component: Wallet },
  issuer: { label: 'Issuer', subtitle: 'University', Component: Issuer },
  verifier: { label: 'Verifier', subtitle: 'Employer', Component: Verifier },
};

function parseHash() {
  const [path, query = ''] = window.location.hash.replace(/^#\/?/, '').split('?');
  return { route: ROUTES[path] ? path : 'wallet', params: new URLSearchParams(query) };
}

export default function App() {
  const [{ route, params }, setLocation] = useState(parseHash);
  useEffect(() => {
    const onChange = () => setLocation(parseHash());
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);
  const { Component } = ROUTES[route];

  return (
    <>
      <header className="topbar">
        <a className="brand" href="#/wallet">
          <span className="logo">◆</span> BlockCred
        </a>
        <nav>
          {Object.entries(ROUTES).map(([key, r]) => (
            <a key={key} href={`#/${key}`} className={key === route ? 'active' : ''}>
              {r.label}
              <small>{r.subtitle}</small>
            </a>
          ))}
        </nav>
      </header>
      <main>
        <Component key={`${route}?${params}`} params={params} />
      </main>
      <footer>
        Verifiable credentials with did:web, SD-JWT VC and on-chain trust anchors · demo build
      </footer>
    </>
  );
}
