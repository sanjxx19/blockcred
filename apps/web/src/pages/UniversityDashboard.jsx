import { useState } from 'react';
import { Card, Field, Notice, Stat, StatusBadge, TxLink } from '../components/ui.jsx';
import { api } from '../lib/api.js';
import { useAction, usePolling } from '../lib/hooks.js';

const EMPTY = { student_email: '', student_id: '', name: '', degree: '', major: '', cgpa: '', graduation_date: '' };
const CSV_TEMPLATE = `student_email,student_id,name,degree,major,cgpa,graduation_date
asha@example.com,CS2022001,Asha Rao,B.Tech,Computer Science,8.92,2026-06-15`;
const DIGILOCKER_MOCK = {
  documents: [
    {
      uri: 'in.gov.digilocker.mock-DGCER-0001',
      doctype: 'DGCER',
      data: { email: 'rohan@example.com', rollNo: 'ME2022044', studentName: 'Rohan Das', course: 'B.Tech', branch: 'Mechanical', cgpa: '8.10', resultDate: '2026-06-20T00:00:00+05:30' },
    },
  ],
};

export default function UniversityDashboard() {
  const overview = usePolling(() => api('/university/overview'), 10000);
  const creds = usePolling(() => api('/university/credentials'), 10000);
  const { busy, msg, setMsg, run } = useAction();
  const [record, setRecord] = useState(EMPTY);
  const [csv, setCsv] = useState(CSV_TEMPLATE);
  const [filter, setFilter] = useState('');

  const reload = () => Promise.all([overview.reload(), creds.reload()]);
  const issuer = overview.data?.issuer;
  const stats = overview.data?.stats;
  const active = issuer?.status === 'active';
  const summary = (r) =>
    `${r.added} record(s) added: ${r.deliveredNow} delivered to student wallets now, ${r.awaitingSignup} waiting for the student to sign up.`;

  const addOne = (e) => {
    e.preventDefault();
    run(async () => {
      const r = await api('/university/credentials', { method: 'POST', body: { records: [{ ...record, cgpa: Number(record.cgpa) }] } });
      setRecord(EMPTY);
      await reload();
      return r;
    }, summary);
  };

  const upload = () =>
    run(async () => {
      const r = await api('/university/credentials', { method: 'POST', body: csv, raw: true, headers: { 'content-type': 'text/csv' } });
      await reload();
      return r;
    }, summary);

  const importMock = () =>
    run(async () => {
      const r = await api('/university/import/digilocker', { method: 'POST', body: DIGILOCKER_MOCK });
      await reload();
      return r;
    }, summary);

  const revoke = (c) => {
    const reason = window.prompt(`Revoke ${c.claims.degree} for ${c.claims.name}? Reason:`, 'Issued in error');
    if (reason === null) return;
    run(async () => {
      const r = await api(`/university/credentials/${c.id}/revoke`, { method: 'POST', body: { reason } });
      await reload();
      return r;
    }, (r) => (r.txHash ? 'Revoked on-chain. Verifiers will now reject it.' : 'Record cancelled before issuance.'));
  };

  const anchor = () =>
    run(async () => {
      const r = await api('/university/anchor', { method: 'POST', body: {} });
      await reload();
      return r;
    }, (r) => (r.anchored ? `Anchored ${r.anchored} credential(s) in one transaction.` : r.skipped || 'Nothing new to anchor.'));

  const rotate = (compromised) => {
    const text = compromised
      ? 'Mark the current key as COMPROMISED? Every credential it signed will immediately stop verifying.'
      : 'Rotate the signing key? Existing credentials remain valid.';
    if (!window.confirm(text)) return;
    run(async () => {
      const r = await api('/university/rotate-key', { method: 'POST', body: { compromised } });
      await reload();
      return r;
    }, 'Signing key rotated. The DID document now lists the new key.');
  };

  const set = (k) => (e) => setRecord({ ...record, [k]: e.target.value });
  const rows = (creds.data?.credentials ?? []).filter((c) =>
    !filter ? true : `${c.student_email} ${c.claims.name} ${c.claims.student_id}`.toLowerCase().includes(filter.toLowerCase()),
  );

  return (
    <div className="grid">
      <Notice kind={msg?.kind} onClose={() => setMsg(null)}>{msg?.text}</Notice>
      {overview.error && <Notice kind="error">{overview.error.message}</Notice>}

      {issuer && issuer.status !== 'active' && (
        <Notice kind={issuer.status === 'pending' ? 'info' : 'error'}>
          {issuer.status === 'pending' && 'Your institution is waiting for approval by the accreditation admin. You can issue degrees once it is approved and registered on-chain.'}
          {issuer.status === 'suspended' && 'Your institution has been suspended by the accreditation body. Its credentials currently fail verification.'}
          {issuer.status === 'rejected' && 'Your accreditation request was rejected. Contact the accreditation body.'}
        </Notice>
      )}

      {issuer && (
        <Card title={issuer.name} actions={<StatusBadge status={issuer.status} />}>
          <div className="stats">
            <Stat label="Decentralised identifier (DID)" value={<a href={`/issuers/${issuer.slug}/did.json`} target="_blank" rel="noreferrer"><code className="small">{issuer.did}</code></a>} />
            <Stat label="On-chain status" value={issuer.onChainStatus} />
            <Stat label="Controller account (gas)" value={<><code className="small">{issuer.controller}</code><br />{issuer.controllerBalance ? `${Number(issuer.controllerBalance).toFixed(4)} ETH` : ''}</>} />
            <Stat label="Signing keys" value={issuer.keys.map((k) => `${k.id} (${k.status})`).join(', ')} />
            <Stat label="Awaiting sign-up / issued / revoked" value={`${stats.awaiting} / ${stats.issued} / ${stats.revoked}`} />
            <Stat label="Waiting to be anchored" value={stats.pending_anchor} />
          </div>
          <div className="row">
            <button className="secondary" disabled={busy || !active} onClick={anchor}>Anchor pending batch now</button>
            <button className="secondary" disabled={busy || !active} onClick={() => rotate(false)}>Rotate signing key</button>
            <button className="danger" disabled={busy || !active} onClick={() => rotate(true)}>Report key compromised</button>
          </div>
        </Card>
      )}

      <Card title="Issue a degree">
        <p className="muted small">
          The degree is signed and delivered to the student's wallet as soon as an account with this e-mail exists. If the
          student hasn't signed up yet, it waits and is delivered automatically when they do.
        </p>
        <form className="form-grid" onSubmit={addOne}>
          <Field label="Student e-mail"><input required type="email" value={record.student_email} onChange={set('student_email')} /></Field>
          <Field label="Student / roll number"><input required value={record.student_id} onChange={set('student_id')} /></Field>
          <Field label="Full name"><input required value={record.name} onChange={set('name')} /></Field>
          <Field label="Degree"><input required placeholder="B.Tech" value={record.degree} onChange={set('degree')} /></Field>
          <Field label="Major / branch"><input value={record.major} onChange={set('major')} /></Field>
          <Field label="CGPA (0–10)"><input required type="number" min="0" max="10" step="0.01" value={record.cgpa} onChange={set('cgpa')} /></Field>
          <Field label="Graduation date"><input required type="date" value={record.graduation_date} onChange={set('graduation_date')} /></Field>
          <div className="form-actions"><button type="submit" disabled={busy || !active}>Issue degree</button></div>
        </form>
      </Card>

      <Card title="Bulk upload" actions={<button className="secondary" onClick={importMock} disabled={busy || !active}>Import from DigiLocker (mock)</button>}>
        <p className="muted small">CSV columns: student_email, student_id, name, degree, major, cgpa, graduation_date. Up to 5,000 rows.</p>
        <input type="file" accept=".csv,text/csv" onChange={async (e) => e.target.files?.[0] && setCsv(await e.target.files[0].text())} />
        <textarea rows={5} value={csv} onChange={(e) => setCsv(e.target.value)} spellCheck={false} />
        <button onClick={upload} disabled={busy || !active}>Upload CSV</button>
      </Card>

      <Card title={`Records (${creds.data?.credentials.length ?? 0})`} actions={<input className="search" placeholder="Search name, e-mail, ID…" value={filter} onChange={(e) => setFilter(e.target.value)} />}>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Student</th>
                <th>Degree</th>
                <th>Status</th>
                <th>Anchored</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((c) => (
                <tr key={c.id}>
                  <td>
                    <strong>{c.claims.name}</strong> <span className="muted small">({c.claims.student_id})</span>
                    <br />
                    <span className="muted small">{c.student_email}</span>
                  </td>
                  <td>
                    {c.claims.degree} {c.claims.major && `· ${c.claims.major}`}
                    <br />
                    <span className="muted small">CGPA {c.claims.cgpa} · {c.claims.graduation_date}</span>
                  </td>
                  <td>
                    <StatusBadge status={c.status} />
                    {c.revocation_tx && <><br /><TxLink hash={c.revocation_tx} /></>}
                  </td>
                  <td>{c.anchor_tx ? <TxLink hash={c.anchor_tx} /> : c.status === 'issued' ? <span className="muted small">next batch</span> : '—'}</td>
                  <td>{c.status !== 'revoked' && <button className="danger" disabled={busy} onClick={() => revoke(c)}>{c.status === 'issued' ? 'Revoke' : 'Cancel'}</button>}</td>
                </tr>
              ))}
              {!rows.length && (
                <tr><td colSpan={5} className="muted">No records yet.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
