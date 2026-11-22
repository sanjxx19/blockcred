import { useEffect, useMemo, useState } from 'react';
import { CLAIM_LABELS, DEGREE_DISCLOSABLE_CLAIMS } from '@blockcred/sdk/credential';
import { decodeSdJwt, presentSdJwt } from '@blockcred/sdk/sdjwt';
import { Card, ClaimTable, Field, Notice, QrScanner, StatusBadge, TxLink, VerdictBadge } from '../components/ui.jsx';
import { api } from '../lib/api.js';
import { useAction, usePolling } from '../lib/hooks.js';
import { getHolderKey, holderSigner, unlockWallet } from '../lib/session.js';

const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

function ConsentPanel({ request, credentials, onRespond, onDecline, busy }) {
  const usable = credentials.filter((c) => c.status === 'issued');
  const [credId, setCredId] = useState(usable[0]?.id ?? '');
  const [fields, setFields] = useState(request.fields);
  const toggle = (f) => setFields(fields.includes(f) ? fields.filter((x) => x !== f) : [...fields, f]);

  return (
    <div className="consent">
      <p>
        <strong>{request.employer}</strong> wants to verify your degree.
        <br />
        <span className="muted">Purpose: {request.purpose}</span>
      </p>
      {usable.length === 0 ? (
        <p className="muted">You have no valid credentials to share yet.</p>
      ) : (
        <>
          <Field label="Credential to use">
            <select value={credId} onChange={(e) => setCredId(e.target.value)}>
              {usable.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.decoded.claims.degree} {c.decoded.claims.major ? `(${c.decoded.claims.major})` : ''} · {c.issuer.name}
                </option>
              ))}
            </select>
          </Field>
          <fieldset>
            <legend>Fields to share. Anything unticked stays cryptographically hidden.</legend>
            {DEGREE_DISCLOSABLE_CLAIMS.map((f) => (
              <label key={f} className="check">
                <input type="checkbox" checked={fields.includes(f)} onChange={() => toggle(f)} />
                {CLAIM_LABELS[f]} {request.fields.includes(f) && <span className="tag">requested</span>}
              </label>
            ))}
          </fieldset>
        </>
      )}
      <div className="row">
        <button disabled={busy || !credId} onClick={() => onRespond(credentials.find((c) => c.id === credId), fields)}>
          I consent: share {fields.length} field(s)
        </button>
        <button className="secondary" disabled={busy} onClick={onDecline}>Decline</button>
      </div>
    </div>
  );
}

export default function StudentDashboard({ me, onLogout }) {
  const [key, setKey] = useState(undefined);
  const [unlockPw, setUnlockPw] = useState('');
  const [open, setOpen] = useState(null);
  const [code, setCode] = useState('');
  const [codeRequest, setCodeRequest] = useState(null);
  const [scanning, setScanning] = useState(false);
  const { busy, msg, setMsg, run } = useAction();

  const creds = usePolling(() => api('/student/credentials'), 8000);
  const reqs = usePolling(() => api('/student/requests'), 5000);
  const consents = usePolling(() => api('/student/consents'), 15000);

  useEffect(() => {
    getHolderKey(me.user.id).then((k) => setKey(k && k.thumbprint === me.student.thumbprint ? k : null));
  }, [me]);

  const credentials = useMemo(
    () => (creds.data?.credentials ?? []).map((c) => ({ ...c, decoded: decodeSdJwt(c.sdJwt) })),
    [creds.data],
  );
  const pending = (reqs.data?.requests ?? []).filter((r) => r.status === 'pending');
  const past = (reqs.data?.requests ?? []).filter((r) => r.status !== 'pending');

  const respond = (request) => async (credential, fields) =>
    run(async () => {
      const presentation = await presentSdJwt({
        sdJwt: credential.sdJwt,
        disclose: fields,
        holderSigner: holderSigner(key),
        aud: request.aud,
        nonce: request.nonce,
      });
      const anchorProof = credential.anchor ? { root: credential.anchor.root, proof: credential.anchor.proof } : undefined;
      const r = await api(`/student/requests/${request.id}/respond`, { method: 'POST', body: { presentation, anchorProof } });
      setOpen(null);
      setCodeRequest(null);
      await Promise.all([reqs.reload(), consents.reload()]);
      return r;
    }, (r) => `Shared with ${request.employer}. Their result: ${r.verdict}`);

  const declineReq = (request) => () =>
    run(async () => {
      await api(`/student/requests/${request.id}/decline`, { method: 'POST', body: {} });
      setOpen(null);
      setCodeRequest(null);
      await Promise.all([reqs.reload(), consents.reload()]);
    }, 'Request declined. Nothing was shared.');

  const lookupCode = (text) =>
    run(async () => {
      const id = String(text).match(UUID_RE)?.[0];
      if (!id) throw new Error('That does not look like a request code');
      const r = await api(`/student/requests/${id}`);
      if (r.status !== 'pending') throw new Error(`This request is ${r.status}`);
      setCodeRequest(r);
    });

  const removeCred = (c) => {
    if (!window.confirm('Remove this credential from your wallet? (The university can re-issue it.)')) return;
    run(async () => {
      await api(`/student/credentials/${c.id}`, { method: 'DELETE' });
      await creds.reload();
    }, 'Removed from your wallet.');
  };

  const eraseAccount = () => {
    if (!window.confirm('Permanently delete your account, wallet key and all credentials in it?')) return;
    run(async () => {
      await api('/student/account', { method: 'DELETE' });
      await onLogout();
    });
  };

  if (key === undefined) return null;
  if (key === null) {
    return (
      <Card title="Unlock your wallet on this device">
        <p className="muted">Your wallet key is stored encrypted. Enter your password to unlock it in this browser.</p>
        <form
          className="row"
          onSubmit={(e) => {
            e.preventDefault();
            run(async () => setKey(await unlockWallet(me, unlockPw)));
          }}
        >
          <input type="password" value={unlockPw} onChange={(e) => setUnlockPw(e.target.value)} placeholder="Password" />
          <button disabled={busy}>Unlock</button>
        </form>
        <Notice kind={msg?.kind}>{msg?.text}</Notice>
      </Card>
    );
  }

  return (
    <div className="grid">
      <Notice kind={msg?.kind} onClose={() => setMsg(null)}>{msg?.text}</Notice>

      <Card title={`Verification requests ${pending.length ? `(${pending.length} waiting)` : ''}`}>
        {pending.length === 0 && <p className="muted">No pending requests. Employers can send requests to <strong>{me.user.email}</strong>.</p>}
        {pending.map((r) => (
          <div key={r.id} className="request-item">
            <div className="row spread">
              <div>
                <strong>{r.employer}</strong> · {r.purpose}
                <br />
                <span className="muted small">
                  Asks for: {r.fields.map((f) => CLAIM_LABELS[f]).join(', ')} · expires {new Date(r.expiresAt).toLocaleDateString()}
                </span>
              </div>
              {open !== r.id && <button onClick={() => setOpen(r.id)}>Review</button>}
            </div>
            {open === r.id && <ConsentPanel request={r} credentials={credentials} busy={busy} onRespond={respond(r)} onDecline={declineReq(r)} />}
          </div>
        ))}
        <details>
          <summary className="small">Have a request code or QR from an employer?</summary>
          <div className="row">
            <input value={code} onChange={(e) => setCode(e.target.value)} placeholder="Paste request code" />
            <button className="secondary" onClick={() => lookupCode(code)} disabled={!code}>Open</button>
            <button className="secondary" onClick={() => setScanning(true)}>Scan QR</button>
          </div>
          {scanning && <QrScanner onResult={(t) => { setScanning(false); lookupCode(t); }} onClose={() => setScanning(false)} />}
          {codeRequest && <ConsentPanel request={codeRequest} credentials={credentials} busy={busy} onRespond={respond(codeRequest)} onDecline={declineReq(codeRequest)} />}
        </details>
      </Card>

      <Card title={`My credentials (${credentials.length})`}>
        {credentials.length === 0 && (
          <p className="muted">No credentials yet. When your university issues a degree to <strong>{me.user.email}</strong>, it appears here automatically.</p>
        )}
        {credentials.map((c) => (
          <details key={c.id} className="credential">
            <summary>
              <strong>{c.decoded.claims.degree}</strong> {c.decoded.claims.major && `in ${c.decoded.claims.major}`} · {c.issuer.name}{' '}
              <StatusBadge status={c.status} />
            </summary>
            <ClaimTable claims={Object.fromEntries(c.decoded.disclosures.map((d) => [d.name, d.value]))} />
            <p className="muted small">
              Issuer <code>{c.issuer.did}</code>
              <br />
              Received {new Date(c.receivedAt).toLocaleString()} · valid until {new Date(c.decoded.payload.exp * 1000).toLocaleDateString()}
              <br />
              On-chain anchor: {c.anchor ? <TxLink hash={c.anchor.txHash} /> : 'pending (next batch)'}
            </p>
            <button className="danger" onClick={() => removeCred(c)} disabled={busy}>Remove from wallet</button>
          </details>
        ))}
      </Card>

      <Card title="Sharing history">
        {(consents.data?.consents ?? []).length === 0 ? (
          <p className="muted">You haven't shared anything yet.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>When</th>
                  <th>Employer</th>
                  <th>Purpose</th>
                  <th>Shared fields</th>
                  <th>Result</th>
                </tr>
              </thead>
              <tbody>
                {consents.data.consents.map((c, i) => (
                  <tr key={i}>
                    <td>{new Date(c.at).toLocaleString()}</td>
                    <td>{c.employer_name}</td>
                    <td>{c.purpose}</td>
                    <td>{c.disclosed_fields.map((f) => CLAIM_LABELS[f] ?? f).join(', ') || '—'}</td>
                    <td><VerdictBadge verdict={c.verdict} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {past.length > 0 && <p className="muted small">{past.length} past request(s) answered, declined or expired.</p>}
      </Card>

      <Card title="Account & privacy">
        <p className="muted small">
          Wallet key fingerprint <code>{me.student.thumbprint}</code>. The private key is stored non-extractable in this browser
          and removed when you log out.
        </p>
        <button className="danger" onClick={eraseAccount} disabled={busy}>Delete my account and wallet</button>
      </Card>
    </div>
  );
}
