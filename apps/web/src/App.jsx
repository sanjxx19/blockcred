import { useEffect, useState } from 'react';
import AdminDashboard from './pages/AdminDashboard.jsx';
import AuthPage from './pages/AuthPage.jsx';
import EmployerDashboard from './pages/EmployerDashboard.jsx';
import StudentDashboard from './pages/StudentDashboard.jsx';
import UniversityDashboard from './pages/UniversityDashboard.jsx';
import { currentUser, logout } from './lib/session.js';

const DASHBOARDS = {
  admin: { label: 'Accreditation admin', Component: AdminDashboard },
  university: { label: 'University', Component: UniversityDashboard },
  student: { label: 'Student wallet', Component: StudentDashboard },
  employer: { label: 'Employer', Component: EmployerDashboard },
};

export default function App() {
  const [me, setMe] = useState(undefined);

  useEffect(() => {
    currentUser().then(setMe);
  }, []);

  const doLogout = async () => {
    await logout(me);
    setMe(null);
  };

  if (me === undefined) return <div className="loading">Loading…</div>;
  const dash = me && DASHBOARDS[me.user.role];

  return (
    <>
      <header className="topbar">
        <span className="brand">
          <span className="logo">◆</span> BlockCred
        </span>
        {me && (
          <div className="user">
            <span>
              <strong>{me.user.name}</strong>
              <small>{dash.label} · {me.user.email}</small>
            </span>
            <button className="secondary" onClick={doLogout}>Log out</button>
          </div>
        )}
      </header>
      <main>{me ? <dash.Component me={me} onLogout={doLogout} /> : <AuthPage onAuthenticated={setMe} />}</main>
      <footer>did:web · SD-JWT VC · EVM trust registry · open-source demo</footer>
    </>
  );
}
