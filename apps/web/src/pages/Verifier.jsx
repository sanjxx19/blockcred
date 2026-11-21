import { useEffect, useState } from 'react';
import { CLAIM_LABELS, DEGREE_DISCLOSABLE_CLAIMS } from '@blockcred/sdk/credential';
import { Card, ClaimTable, CopyButton, Notice, Qr, VerdictBadge } from '../components/ui.jsx';
import { api } from '../lib/api.js';
import { VERIFIER_URL } from '../lib/config.js';

const CHECK_LABELS = {
  didResolved: 'Issuer DID resolved',
  signature: 'Issuer signature & disclosures',
  notExpired: 'Not expired',
  holderBinding: 'Presented by the rightful holder (key binding)',
  issuerAccredited: 'Issuer accredited on-chain',
  schemaRegistered: 'Credential type registered on-chain',
  notRevoked: 'Not revoked (on-chain bitstring)',
  anchored: 'Included in an anchored batch (optional)',
};

export default function Verifier() {
  const [fields, setFields] = useState(['degree', 'graduation_date']);
  const [purpose, setPurpose] = useState('Employment background verification');
  const [session, setSession] = useState(null);
  const [state, setState] = useState(null);
  const [msg, setMsg] = useState(null);

  useEffect(() => {
    if (!session) return undefined;
    let stop = false;
    const tick = async () => {
      try {
        const s = await api(VERIFIER_URL, `/requests/${session.id}`, { headers: { 'x-poll-token': session.pollToken } });
        if (stop) return;
        setState(s);
        if (s.status === 'pending' || s.status === 'processing') setTimeout(tick, 1500);
      } catch (e) {
        if (!stop) setMsg({ kind: 'error', text: e.message });
      }
    };
    tick();
    return () => {
      stop = true;
    };
  }, [session]);

  const create = async () => {
    setMsg(null);
    setState(null);
    try {
      setSession(await api(VERIFIER_URL, '/requests', { method: 'POST', body: { fields, purpose } }));
    } catch (e) {
      setMsg({ kind: 'error', text: e.message });
    }
  };

  const requestJson = session ? JSON.stringify(session.request) : '';
  const result = state?.result;

  return (
    <div className="grid">
      <Notice kind={msg?.kind} onClose={() => setMsg(null)}>
        {msg?.text}
      </Notice>

      <Card title="New verification request">
        <label>
          Purpose (shown to the student)
          <input value={purpose} onChange={(e) => setPurpose(e.target.value)} />
        </label>
        <fieldset>
          <legend>Request these fields (data minimisation: ask only for what you need)</legend>
          {DEGREE_DISCLOSABLE_CLAIMS.map((f) => (
            <label key={f} className="check">
              <input type="checkbox" checked={fields.includes(f)} onChange={(e) => setFields(e.target.checked ? [...fields, f] : fields.filter((x) => x !== f))} />
              {CLAIM_LABELS[f]}
            </label>
          ))}
        </fieldset>
        <button onClick={create}>Create request</button>
      </Card>

      {session && (
        <Card title="Ask the student to scan or paste this request">
          <div className="request">
            <Qr text={requestJson} size={260} />
            <div>
              <p className="muted small">Single-use nonce, valid until {new Date(session.expiresAt).toLocaleTimeString()}.</p>
              <textarea rows={6} readOnly value={requestJson} />
              <CopyButton text={requestJson} label="Copy request JSON" />
              <p>
                Status: <strong>{state?.status ?? 'pending'}</strong>
              </p>
            </div>
          </div>
        </Card>
      )}

      {result && (
        <Card title="Result">
          <p>
            <VerdictBadge verdict={result.verdict} />
            {result.error && <span className="muted"> — {result.error}</span>}
          </p>
          {result.valid && (
            <>
              <p className="muted small">
                Issued by <strong>{result.issuer.name}</strong> (<code>{result.issuer.did}</code>) on{' '}
                {new Date(result.credential.issuedAt).toLocaleDateString()}
                {result.credential.anchoredAt && <> · anchored {new Date(result.credential.anchoredAt).toLocaleString()}</>}
              </p>
              {state.claimsPurged ? <p className="muted">Disclosed values were purged after the retention period.</p> : <ClaimTable claims={result.disclosed} />}
              {result.missingFields?.length > 0 && <p className="muted">Student chose not to disclose: {result.missingFields.map((f) => CLAIM_LABELS[f] ?? f).join(', ')}</p>}
            </>
          )}
          <ul className="checks">
            {Object.entries(CHECK_LABELS).map(([k, label]) =>
              k in (result.checks ?? {}) ? (
                <li key={k} className={result.checks[k] ? 'ok' : 'bad'}>
                  {result.checks[k] ? '✓' : '✗'} {label}
                </li>
              ) : null,
            )}
          </ul>
        </Card>
      )}
    </div>
  );
}
