import { useCallback, useEffect, useState } from 'react';
import { CLAIM_LABELS, DEGREE_DISCLOSABLE_CLAIMS } from '@blockcred/sdk/credential';
import { Card, ClaimTable, Notice, QrScanner, TxLink, VerdictBadge } from '../components/ui.jsx';
import { ISSUER_URL } from '../lib/config.js';
import {
  deleteCredential,
  getHolderKey,
  listConsents,
  listCredentials,
  parseRequest,
  presentToVerifier,
  redeemOffer,
  refreshAnchorProof,
  wipeWallet,
} from '../lib/wallet.js';

export default function Wallet({ params }) {
  const [holder, setHolder] = useState(null);
  const [credentials, setCredentials] = useState([]);
  const [consents, setConsents] = useState([]);
  const [issuerUrl, setIssuerUrl] = useState(params.get('issuer') || ISSUER_URL);
  const [offerCode, setOfferCode] = useState(params.get('code') || '');
  const [requestText, setRequestText] = useState('');
  const [request, setRequest] = useState(null);
  const [selectedCred, setSelectedCred] = useState('');
  const [fields, setFields] = useState([]);
  const [scanning, setScanning] = useState(false);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState(null);
  const [result, setResult] = useState(null);

  const refresh = useCallback(async () => {
    setHolder(await getHolderKey({ create: false }));
    setCredentials(await listCredentials());
    setConsents(await listConsents());
  }, []);

  useEffect(() => {
    refresh().catch((e) => setMsg({ kind: 'error', text: e.message }));
  }, [refresh]);

  const guard = (fn) => async (...args) => {
    setBusy(true);
    setMsg(null);
    try {
      await fn(...args);
    } catch (e) {
      setMsg({ kind: 'error', text: e.message });
    } finally {
      setBusy(false);
    }
  };

  const onRedeem = guard(async () => {
    const cred = await redeemOffer(issuerUrl, offerCode.trim());
    setOfferCode('');
    window.history.replaceState(null, '', '#/wallet');
    await refresh();
    setMsg({ kind: 'success', text: `Credential ${cred.id.slice(0, 8)}… stored in your wallet.` });
  });

  const loadRequest = (text) => {
    try {
      const req = parseRequest(text);
      setRequest(req);
      setRequestText(text);
      setFields(req.fields.filter((f) => DEGREE_DISCLOSABLE_CLAIMS.includes(f)));
      setResult(null);
      if (!selectedCred && credentials[0]) setSelectedCred(credentials[0].id);
      setMsg(null);
    } catch (e) {
      setRequest(null);
      setMsg({ kind: 'error', text: `Invalid request: ${e.message}` });
    }
  };

  const onPresent = guard(async () => {
    const cred = credentials.find((c) => c.id === selectedCred);
    if (!cred) throw new Error('Choose a credential');
    const res = await presentToVerifier(cred, request, fields);
    setResult(res);
    setRequest(null);
    setRequestText('');
    await refresh();
  });

  const onAnchor = guard(async (cred) => {
    const proof = await refreshAnchorProof(cred);
    setMsg(proof ? { kind: 'success', text: 'Anchor proof saved.' } : { kind: 'info', text: 'Not anchored yet. Try again shortly.' });
    await refresh();
  });

  const onDelete = guard(async (cred) => {
    if (!window.confirm('Delete this credential from your wallet?')) return;
    await deleteCredential(cred.id);
    await refresh();
  });

  const onWipe = guard(async () => {
    if (!window.confirm('Erase your wallet key, all credentials and your consent history? This cannot be undone.')) return;
    await wipeWallet();
    await refresh();
    setMsg({ kind: 'success', text: 'Wallet erased.' });
  });

  const onCreateKey = guard(async () => {
    await getHolderKey();
    await refresh();
  });

  return (
    <div className="grid">
      <Notice kind={msg?.kind} onClose={() => setMsg(null)}>
        {msg?.text}
      </Notice>

      <Card title="My wallet" actions={holder && <button className="danger" onClick={onWipe} disabled={busy}>Erase wallet</button>}>
        {holder ? (
          <p className="muted">
            Holder key thumbprint <code>{holder.thumbprint}</code>
            <br />
            Non-extractable P-256 key stored in this browser since {new Date(holder.createdAt).toLocaleString()}.
          </p>
        ) : (
          <>
            <p className="muted">No wallet key yet. One is created automatically when you receive your first credential.</p>
            <button onClick={onCreateKey} disabled={busy}>Create wallet key</button>
          </>
        )}
      </Card>

      <Card title="Receive a credential">
        <label>
          Issuer URL
          <input value={issuerUrl} onChange={(e) => setIssuerUrl(e.target.value)} />
        </label>
        <label>
          Offer code
          <input value={offerCode} onChange={(e) => setOfferCode(e.target.value)} placeholder="Paste the one-time code from your institution" />
        </label>
        <button onClick={onRedeem} disabled={busy || !offerCode.trim()}>
          {busy ? 'Working…' : 'Accept credential'}
        </button>
      </Card>

      <Card title={`Credentials (${credentials.length})`}>
        {credentials.length === 0 && <p className="muted">No credentials yet.</p>}
        {credentials.map((c) => (
          <details key={c.id} className="credential">
            <summary>
              <strong>{c.decoded.claims.degree ?? 'Credential'}</strong> · {c.decoded.claims.issuer_name ?? c.issuerDid}
              <span className="muted"> · received {new Date(c.receivedAt).toLocaleDateString()}</span>
            </summary>
            <ClaimTable claims={Object.fromEntries(c.decoded.disclosures.map((d) => [d.name, d.value]))} />
            <p className="muted small">
              Issuer <code>{c.issuerDid}</code> · status index {c.decoded.payload.status?.blockcred?.idx} · expires{' '}
              {new Date(c.decoded.payload.exp * 1000).toLocaleDateString()}
              <br />
              Anchor: {c.anchorProof ? <>root <code>{c.anchorProof.root.slice(0, 12)}…</code> tx <TxLink hash={c.anchorProof.txHash} /></> : 'not fetched'}
            </p>
            <div className="row">
              <button className="secondary" onClick={() => onAnchor(c)} disabled={busy}>Fetch anchor proof</button>
              <button className="danger" onClick={() => onDelete(c)} disabled={busy}>Delete</button>
            </div>
          </details>
        ))}
      </Card>

      <Card title="Share with a verifier">
        {!request && (
          <>
            <label>
              Verification request
              <textarea rows={4} value={requestText} onChange={(e) => setRequestText(e.target.value)} placeholder="Paste the request JSON shown by the verifier, or scan its QR code" />
            </label>
            <div className="row">
              <button onClick={() => loadRequest(requestText)} disabled={!requestText.trim()}>Review request</button>
              <button className="secondary" onClick={() => setScanning(true)}>Scan QR</button>
            </div>
            {scanning && (
              <QrScanner
                onResult={(text) => {
                  setScanning(false);
                  loadRequest(text);
                }}
                onClose={() => setScanning(false)}
              />
            )}
          </>
        )}
        {request && (
          <div className="consent">
            <p>
              <strong>{request.verifier?.name ?? request.aud}</strong> asks to verify your credential.
              <br />
              <span className="muted">Purpose: {request.purpose}</span>
              <br />
              <span className="muted small">Audience: <code>{request.aud}</code></span>
            </p>
            <label>
              Credential
              <select value={selectedCred} onChange={(e) => setSelectedCred(e.target.value)}>
                <option value="">Choose…</option>
                {credentials.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.decoded.claims.degree} — {c.decoded.claims.issuer_name}
                  </option>
                ))}
              </select>
            </label>
            <fieldset>
              <legend>Fields to disclose (everything else stays hidden)</legend>
              {DEGREE_DISCLOSABLE_CLAIMS.map((f) => (
                <label key={f} className="check">
                  <input
                    type="checkbox"
                    checked={fields.includes(f)}
                    onChange={(e) => setFields(e.target.checked ? [...fields, f] : fields.filter((x) => x !== f))}
                  />
                  {CLAIM_LABELS[f]} {request.fields.includes(f) && <span className="tag">requested</span>}
                </label>
              ))}
            </fieldset>
            <div className="row">
              <button onClick={onPresent} disabled={busy || !selectedCred}>
                {busy ? 'Sharing…' : `I consent — share ${fields.length} field(s)`}
              </button>
              <button className="secondary" onClick={() => setRequest(null)}>Decline</button>
            </div>
          </div>
        )}
        {result && (
          <p>
            Verifier response: <VerdictBadge verdict={result.verdict} />
            {result.missingFields?.length > 0 && <span className="muted"> (withheld: {result.missingFields.join(', ')})</span>}
          </p>
        )}
      </Card>

      <Card title="Consent history">
        {consents.length === 0 ? (
          <p className="muted">Nothing shared yet.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Verifier</th>
                <th>Purpose</th>
                <th>Fields</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {consents.map((c) => (
                <tr key={c.id}>
                  <td>{new Date(c.at).toLocaleString()}</td>
                  <td>{c.verifier}</td>
                  <td>{c.purpose}</td>
                  <td>{c.fields.join(', ') || '—'}</td>
                  <td><VerdictBadge verdict={c.verdict} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
