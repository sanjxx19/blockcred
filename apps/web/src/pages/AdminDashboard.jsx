import { Card, Notice, Stat, StatusBadge, TxLink } from '../components/ui.jsx';
import { api } from '../lib/api.js';
import { useAction, usePolling } from '../lib/hooks.js';

export default function AdminDashboard() {
  const { data, error, reload } = usePolling(() => api('/admin/overview'), 8000);
  const { busy, msg, setMsg, run } = useAction();

  const act = (issuer, action) =>
    run(async () => {
      if (action !== 'approve' && !window.confirm(`${action} ${issuer.name}?`)) return null;
      const r = await api(`/admin/issuers/${issuer.id}/${action}`, { method: 'POST', body: {} });
      await reload();
      return r;
    }, (r) => r && `${issuer.name}: ${r.status}${r.txHash ? ' (on-chain tx confirmed)' : ''}`);

  const chain = data?.chain;
  const pending = data?.issuers.filter((i) => i.status === 'pending') ?? [];

  return (
    <div className="grid">
      <Notice kind={msg?.kind} onClose={() => setMsg(null)}>{msg?.text}</Notice>
      {error && <Notice kind="error">{error.message}</Notice>}

      <Card title="Accreditation overview">
        <p className="muted small">
          You are the accreditation body. Approving an institution registers its DID and controller account in the on-chain{' '}
          <code>IssuerRegistry</code>. Only accredited institutions' credentials verify.
        </p>
        {data && (
          <div className="stats">
            <Stat label="Institutions" value={data.issuers.length} />
            <Stat label="Awaiting approval" value={pending.length} />
            <Stat label="Students" value={data.users.student ?? 0} />
            <Stat label="Employers" value={data.users.employer ?? 0} />
            <Stat label="Credentials issued" value={(data.credentials.issued ?? 0) + (data.credentials.revoked ?? 0)} />
            <Stat label="Revoked" value={data.credentials.revoked ?? 0} />
          </div>
        )}
      </Card>

      <Card title="Institutions">
        {data?.issuers.length === 0 && <p className="muted">No universities have signed up yet. Create a University account in another browser window.</p>}
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Institution</th>
                <th>DID</th>
                <th>Status</th>
                <th>Issued</th>
                <th>Registration tx</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {data?.issuers.map((i) => (
                <tr key={i.id}>
                  <td>
                    <strong>{i.name}</strong>
                    <br />
                    <span className="muted small">{i.email}</span>
                  </td>
                  <td>
                    <a href={`/issuers/${i.slug}/did.json`} target="_blank" rel="noreferrer"><code className="small">{i.did}</code></a>
                  </td>
                  <td><StatusBadge status={i.status} /></td>
                  <td>{i.issued}</td>
                  <td><TxLink hash={i.registered_tx} /></td>
                  <td className="row">
                    {(i.status === 'pending' || i.status === 'rejected') && <button disabled={busy} onClick={() => act(i, 'approve')}>Approve</button>}
                    {i.status === 'pending' && <button className="danger" disabled={busy} onClick={() => act(i, 'reject')}>Reject</button>}
                    {i.status === 'active' && <button className="danger" disabled={busy} onClick={() => act(i, 'suspend')}>Suspend</button>}
                    {i.status === 'suspended' && <button disabled={busy} onClick={() => act(i, 'reinstate')}>Reinstate</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card title="Blockchain">
        {chain?.error && <Notice kind="error">Chain unavailable: {chain.error}</Notice>}
        {chain && !chain.error && (
          <div className="stats">
            <Stat label="Chain ID / block" value={`${chain.chainId} · #${chain.blockNumber}`} />
            <Stat label="Governor account" value={<code className="small">{chain.governor}</code>} />
            <Stat label="Governor balance" value={`${Number(chain.governorBalance).toFixed(4)}`} />
            <Stat label="Has GOVERNOR_ROLE" value={chain.governorAuthorized ? '✓ yes' : '✗ no'} />
            <Stat label="IssuerRegistry" value={<code className="small">{chain.contracts.IssuerRegistry}</code>} />
            <Stat label="RevocationRegistry" value={<code className="small">{chain.contracts.RevocationRegistry}</code>} />
            <Stat label="MerkleAnchor" value={<code className="small">{chain.contracts.MerkleAnchor}</code>} />
          </div>
        )}
      </Card>
    </div>
  );
}
