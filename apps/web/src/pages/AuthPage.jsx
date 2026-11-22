import { useState } from 'react';
import { Card, Field, Notice } from '../components/ui.jsx';
import { login, signup } from '../lib/session.js';

const ROLES = {
  student: {
    title: 'Student',
    blurb: 'Receive your degrees in a personal wallet and choose exactly what to share with employers.',
    nameLabel: 'Full name',
  },
  university: {
    title: 'University',
    blurb: 'Issue tamper-proof degrees to your students once the accreditation body approves you.',
    nameLabel: 'Institution name',
  },
  employer: {
    title: 'Employer',
    blurb: 'Ask candidates to prove their qualifications and get an instant, verifiable answer.',
    nameLabel: 'Organisation name',
  },
};

export default function AuthPage({ onAuthenticated }) {
  const [mode, setMode] = useState('login');
  const [role, setRole] = useState('student');
  const [form, setForm] = useState({ name: '', email: '', password: '', confirm: '' });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  const submit = async (e) => {
    e.preventDefault();
    setError(null);
    if (mode === 'signup') {
      if (form.password.length < 8) return setError('Password must be at least 8 characters.');
      if (form.password !== form.confirm) return setError('Passwords do not match.');
    }
    setBusy(true);
    try {
      const me =
        mode === 'login'
          ? await login({ email: form.email, password: form.password })
          : await signup({ role, email: form.email, password: form.password, name: form.name });
      onAuthenticated(me);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="auth">
      <div className="hero">
        <h1>
          <span className="logo">◆</span> BlockCred
        </h1>
        <p>
          Degrees that students own and employers can verify in seconds, secured by <strong>did:web</strong> identities,{' '}
          <strong>selective-disclosure credentials</strong> and an <strong>on-chain trust registry</strong>.
        </p>
        <ol className="muted small">
          <li>The accreditation admin approves universities on-chain.</li>
          <li>Universities issue degrees to students' e-mail addresses.</li>
          <li>Students receive them in their wallet and answer employers' requests.</li>
          <li>Employers see a cryptographically verified result.</li>
        </ol>
      </div>

      <Card>
        <div className="tabs">
          <button className={mode === 'login' ? 'tab active' : 'tab'} onClick={() => setMode('login')}>Log in</button>
          <button className={mode === 'signup' ? 'tab active' : 'tab'} onClick={() => setMode('signup')}>Create account</button>
        </div>

        <form onSubmit={submit} className="grid">
          {mode === 'signup' && (
            <>
              <div className="roles">
                {Object.entries(ROLES).map(([key, r]) => (
                  <button type="button" key={key} className={`role ${role === key ? 'selected' : ''}`} onClick={() => setRole(key)}>
                    <strong>{r.title}</strong>
                    <span>{r.blurb}</span>
                  </button>
                ))}
              </div>
              <Field label={ROLES[role].nameLabel}>
                <input required value={form.name} onChange={set('name')} autoComplete="name" />
              </Field>
            </>
          )}
          <Field label="E-mail" hint={mode === 'signup' && role === 'student' ? '(use the address your university has on file)' : ''}>
            <input required type="email" value={form.email} onChange={set('email')} autoComplete="email" />
          </Field>
          <Field label="Password">
            <input required type="password" value={form.password} onChange={set('password')} autoComplete={mode === 'login' ? 'current-password' : 'new-password'} />
          </Field>
          {mode === 'signup' && (
            <Field label="Confirm password">
              <input required type="password" value={form.confirm} onChange={set('confirm')} autoComplete="new-password" />
            </Field>
          )}
          {mode === 'signup' && role === 'student' && (
            <p className="muted small">
              Your password also encrypts your wallet key on this device before anything is sent. The platform never sees it, so a
              forgotten password cannot be recovered.
            </p>
          )}
          <Notice kind="error">{error}</Notice>
          <button type="submit" disabled={busy}>
            {busy ? 'Please wait…' : mode === 'login' ? 'Log in' : `Create ${ROLES[role].title.toLowerCase()} account`}
          </button>
          {mode === 'login' && (
            <p className="muted small">
              Accreditation admin? Use <code>ADMIN_EMAIL</code> / <code>ADMIN_PASSWORD</code> from your <code>.env</code>.
            </p>
          )}
        </form>
      </Card>
    </div>
  );
}
