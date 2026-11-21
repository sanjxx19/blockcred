import { useCallback, useEffect, useState } from 'react';
import { Card, CopyButton, Notice, Qr, TxLink } from '../components/ui.jsx';
import { api } from '../lib/api.js';
import { ISSUER_URL } from '../lib/config.js';

const SAMPLE_CSV = `student_id,name,degree,major,cgpa,graduation_date
CS2022001,Asha Rao,B.Tech,Computer Science,8.92,2026-06-15
CS2022002,Vikram Singh,B.Tech,Computer Science,7.45,2026-06-15
EC2022010,Meera Iyer,B.Tech,Electronics,9.31,2026-06-15`;

const SAMPLE_DIGILOCKER = {
  documents: [
    {
      uri: 'in.gov.digilocker.mock-DGCER-2026-0001',
      doctype: 'DGCER',
      issuer: { name: 'Demo Institute of Technology' },
      data: { rollNo: 'ME2022044', studentName: 'Rohan Das', course: 'B.Tech', branch: 'Mechanical', cgpa: '8.10', resultDate: '2026-06-20T00:00:00+05:30' },
    },
  ],
};

export default function Issuer() {
  const [apiKey, setApiKey] = useState(() => sessionStorage.getItem('issuerApiKey') || '');
  const [status, setStatus] = useState(null);
  const [csv, setCsv] = useState(SAMPLE_CSV);
  const [offers, setOffers] = useState([]);
  const [credentials, setCredentials] = useState([]);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState(null);

  const call = useCallback((path, opts = {}) => api(ISSUER_URL, path, { apiKey, ...opts }), [apiKey]);

  const load = useCallback(async () => {
    if (!apiKey) return;
    const [s, c] = await Promise.all([call('/admin/status'), call('/admin/credentials?limit=200')]);
    setStatus(s);
    setCredentials(c.credentials);
  }, [apiKey, call]);

  useEffect(() => {
    load().catch((e) => setMsg({ kind: 'error', text: e.message }));
  }, [load]);

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

  const saveKey = (k) => {
    setApiKey(k);
    sessionStorage.setItem('issuerApiKey', k);
  };

  const issueCsv = guard(async () => {
    const res = await call('/admin/offers', { method: 'POST', body: csv, raw: true, headers: { 'content-type': 'text/csv' } });
    setOffers(res.offers);
    setMsg({ kind: 'success', text: `${res.offers.length} offer(s) created. Codes are shown once — hand them to students now.` });
    await load();
  });

  const importDigiLocker = guard(async () => {
    const res = await call('/admin/import/digilocker', { method: 'POST', body: SAMPLE_DIGILOCKER });
    setOffers(res.offers);
    setMsg({ kind: 'success', text: 'Imported mock DigiLocker record as a credential offer.' });
    await load();
  });

  const anchorNow = guard(async () => {
    const res = await call('/admin/anchor', { method: 'POST', body: {} });
    setMsg({ kind: 'success', text: res.anchored ? `Anchored ${res.anchored} credential(s) in one transaction.` : res.skipped || 'Nothing to anchor.' });
    await load();
  });

  const revoke = guard(async (cred) => {
    const reason = window.prompt(`Revoke credential for ${cred.subject_ref}? Reason:`, 'Issued in error');
    if (reason === null) return;
    const res = await call(`/admin/credentials/${cred.id}/revoke`, { method: 'POST', body: { reason } });
    setMsg({ kind: 'success', text: `Revoked on-chain (tx ${res.txHash.slice(0, 12)}…).` });
    await load();
  });

  const onFile = async (e) => {
    const file = e.target.files?.[0];
    if (file) setCsv(await file.text());
  };

  return (
    <div className="grid">
      <Notice kind={msg?.kind} onClose={() => setMsg(null)}>
        {msg?.text}
      </Notice>

      <Card title="Issuer portal">
        <label>
          Admin API key <span className="muted small">(ISSUER_ADMIN_API_KEY from .env; kept in this tab only)</span>
          <input type="password" value={apiKey} onChange={(e) => saveKey(e.target.value)} autoComplete="off" />
        </label>
        {status && (
          <div className="stats">
            <div><span>DID</span><code>{status.issuer.did}</code></div>
            <div><span>On-chain accreditation</span><strong className={status.chain.accredited ? 'ok' : 'bad'}>{status.chain.accredited ? 'Accredited' : 'NOT accredited'}</strong></div>
            <div><span>Controller</span><code>{status.chain.controller}</code> ({Number(status.chain.controllerBalance).toFixed(4)} native)</div>
            <div><span>Chain</span>{status.chain.chainId} · block {status.chain.blockNumber}</div>
            <div><span>Credentials</span>{status.stats.credentials} issued · {status.stats.revoked} revoked · {status.stats.pending_anchor} awaiting anchor</div>
            <div><span>Open offers</span>{status.stats.open_offers}</div>
          </div>
        )}
      </Card>

      <Card title="Create credential offers" actions={<button className="secondary" onClick={importDigiLocker} disabled={busy || !apiKey}>Import from DigiLocker (mock)</button>}>
        <p className="muted small">Columns: student_id, name, degree, major, cgpa, graduation_date. Up to 5,000 rows per upload.</p>
        <input type="file" accept=".csv,text/csv" onChange={onFile} />
        <textarea rows={6} value={csv} onChange={(e) => setCsv(e.target.value)} spellCheck={false} />
        <button onClick={issueCsv} disabled={busy || !apiKey}>{busy ? 'Working…' : 'Create offers'}</button>
        {offers.length > 0 && (
          <div className="offers">
            {offers.map((o) => (
              <div key={o.offerId} className="offer">
                <Qr text={o.walletLink} size={140} />
                <div>
                  <strong>{o.name}</strong> <span className="muted">({o.studentId})</span>
                  <br />
                  <code className="small">{o.offerCode}</code>
                  <div className="row">
                    <CopyButton text={o.offerCode} label="Copy code" />
                    <CopyButton text={o.walletLink} label="Copy wallet link" />
                    <a className="button secondary" href={o.walletLink} target="_blank" rel="noreferrer">Open in wallet</a>
                  </div>
                  <span className="muted small">Expires {new Date(o.expiresAt).toLocaleString()}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card title={`Issued credentials (${credentials.length})`} actions={<><button className="secondary" onClick={guard(load)} disabled={busy || !apiKey}>Refresh</button><button onClick={anchorNow} disabled={busy || !apiKey}>Anchor pending batch</button></>}>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Student</th>
                <th>Issued</th>
                <th>Status idx</th>
                <th>Batch anchor</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {credentials.map((c) => (
                <tr key={c.id}>
                  <td>{c.subject_ref}</td>
                  <td>{new Date(c.issued_at).toLocaleString()}</td>
                  <td>{c.status_index}</td>
                  <td>{c.merkle_root ? <TxLink hash={c.anchor_tx} /> : <span className="muted">pending</span>}</td>
                  <td>{c.revoked_at ? <span className="badge badge-bad" title={c.revocation_reason}>Revoked</span> : <span className="badge badge-ok">Active</span>}</td>
                  <td>{!c.revoked_at && <button className="danger" onClick={() => revoke(c)} disabled={busy}>Revoke</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
