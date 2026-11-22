import { useState } from 'react';
import { CLAIM_LABELS, DEGREE_DISCLOSABLE_CLAIMS } from '@blockcred/sdk/credential';
import { Card, ClaimTable, CopyButton, Field, Notice, Qr, StatusBadge, VerdictBadge } from '../components/ui.jsx';
import { api } from '../lib/api.js';
import { useAction, usePolling } from '../lib/hooks.js';

const CHECK_LABELS = {
  didResolved: 'Issuer identity (did:web) resolved',
  signature: 'Issuer signature & disclosures valid',
  notExpired: 'Not expired',
  holderBinding: 'Presented by the rightful holder',
  issuerAccredited: 'Issuer accredited on-chain',
  schemaRegistered: 'Credential type registered on-chain',
  notRevoked: 'Not revoked on-chain',
  anchored: 'Included in an anchored batch',
};

function Result({ request }) {
  const r = request.result;
  if (!r) return <p className="muted">Waiting for the student to respond.</p>;
  return (
    <div className="result">
      <p>
        <VerdictBadge verdict={r.verdict} /> {r.error && <span className="muted">{r.error}</span>}
      </p>
      {r.valid && (
        <>
          <p className="muted small">
            Issued by <strong>{r.issuer.name}</strong> on {new Date(r.credential.issuedAt).toLocaleDateString()}
            {r.credential.anchoredAt && <> · anchored on-chain {new Date(r.credential.anchoredAt).toLocaleString()}</>}
          </p>
          {request.claims_purged ? <p className="muted">Shared values were deleted after the retention period.</p> : <ClaimTable claims={r.disclosed} />}
          {r.missingFields?.length > 0 && <p className="muted small">Not shared by the student: {r.missingFields.map((f) => CLAIM_LABELS[f]).join(', ')}</p>}
        </>
      )}
      <ul className="checks">
        {Object.entries(CHECK_LABELS).map(([k, label]) =>
          k in (r.checks ?? {}) ? <li key={k} className={r.checks[k] ? 'ok' : 'bad'}>{r.checks[k] ? '✓' : '✗'} {label}</li> : null,
        )}
      </ul>
    </div>
  );
}

export default function EmployerDashboard() {
  const list = usePolling(() => api('/employer/requests'), 4000);
  const { busy, msg, setMsg, run } = useAction();
  const [form, setForm] = useState({ studentEmail: '', purpose: 'Employment background verification', fields: ['degree', 'graduation_date'] });
  const [created, setCreated] = useState(null);
  const [open, setOpen] = useState(null);

  const toggle = (f) => setForm({ ...form, fields: form.fields.includes(f) ? form.fields.filter((x) => x !== f) : [...form.fields, f] });

  const submit = (e) => {
    e.preventDefault();
    run(async () => {
      const r = await api('/employer/requests', { method: 'POST', body: form });
      setCreated({ ...r, email: form.studentEmail });
      setForm({ ...form, studentEmail: '' });
      await list.reload();
      return r;
    }, (r) =>
      form.studentEmail
        ? r.studentHasAccount
          ? `Request sent to ${form.studentEmail}'s inbox.`
          : `Request saved. ${form.studentEmail} doesn't have an account yet and will see it when they sign up.`
        : 'Open request created. Share the code or QR below.',
    );
  };

  const requests = list.data?.requests ?? [];
  const link = created && !created.email ? created.code : null;

  return (
    <div className="grid">
      <Notice kind={msg?.kind} onClose={() => setMsg(null)}>{msg?.text}</Notice>

      <Card title="Request a verification">
        <form className="grid" onSubmit={submit}>
          <Field label="Candidate's e-mail" hint="(optional: leave empty to get a shareable code/QR instead)">
            <input type="email" value={form.studentEmail} onChange={(e) => setForm({ ...form, studentEmail: e.target.value })} />
          </Field>
          <Field label="Purpose (shown to the candidate)">
            <input required value={form.purpose} onChange={(e) => setForm({ ...form, purpose: e.target.value })} />
          </Field>
          <fieldset>
            <legend>Ask only for what you need (data minimisation)</legend>
            {DEGREE_DISCLOSABLE_CLAIMS.map((f) => (
              <label key={f} className="check">
                <input type="checkbox" checked={form.fields.includes(f)} onChange={() => toggle(f)} />
                {CLAIM_LABELS[f]}
              </label>
            ))}
          </fieldset>
          <button disabled={busy || !form.fields.length}>Send request</button>
        </form>
        {link && (
          <div className="request">
            <Qr text={link} size={180} />
            <div>
              <p>Ask the candidate to open <strong>Have a request code?</strong> in their wallet and paste or scan:</p>
              <code>{link}</code>
              <CopyButton text={link} label="Copy code" />
            </div>
          </div>
        )}
      </Card>

      <Card title={`My requests (${requests.length})`}>
        {requests.length === 0 && <p className="muted">No requests yet.</p>}
        {requests.map((r) => (
          <div key={r.id} className="request-item">
            <div className="row spread" onClick={() => setOpen(open === r.id ? null : r.id)} style={{ cursor: 'pointer' }}>
              <div>
                <strong>{r.student_name ?? r.student_email ?? 'Open request'}</strong> {r.student_email && r.student_name && <span className="muted small">({r.student_email})</span>}
                <br />
                <span className="muted small">
                  {r.purpose} · {r.requested_fields.map((f) => CLAIM_LABELS[f]).join(', ')} · {new Date(r.created_at).toLocaleString()}
                </span>
              </div>
              <div className="row">
                {r.verdict ? <VerdictBadge verdict={r.verdict} /> : <StatusBadge status={r.status} />}
                <span className="muted">{open === r.id ? '▾' : '▸'}</span>
              </div>
            </div>
            {open === r.id && (
              <>
                {!r.student_email && r.status === 'pending' && <p className="small">Code: <code>{r.id}</code> <CopyButton text={r.id} label="Copy" /></p>}
                <Result request={r} />
              </>
            )}
          </div>
        ))}
      </Card>
    </div>
  );
}
