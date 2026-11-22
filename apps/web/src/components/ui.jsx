import { useEffect, useRef, useState } from 'react';
import QRCode from 'qrcode';
import { CLAIM_LABELS } from '@blockcred/sdk/credential';
import { EXPLORER_TX_URL } from '../lib/config.js';

export function Card({ title, children, actions }) {
  return (
    <section className="card">
      {(title || actions) && (
        <header className="card-header">
          {title && <h2>{title}</h2>}
          {actions && <div className="row">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function Notice({ kind = 'info', children, onClose }) {
  if (!children) return null;
  return (
    <div className={`notice notice-${kind}`} role={kind === 'error' ? 'alert' : 'status'}>
      <span>{children}</span>
      {onClose && (
        <button className="link" onClick={onClose} aria-label="Dismiss">
          ×
        </button>
      )}
    </div>
  );
}

export function Qr({ text, size = 240 }) {
  const [url, setUrl] = useState(null);
  const [error, setError] = useState(null);
  useEffect(() => {
    let cancelled = false;
    QRCode.toDataURL(text, { errorCorrectionLevel: 'M', margin: 1, width: size })
      .then((u) => !cancelled && setUrl(u))
      .catch((e) => !cancelled && setError(e.message));
    return () => {
      cancelled = true;
    };
  }, [text, size]);
  if (error) return <p className="muted">QR unavailable: {error}</p>;
  return url ? <img className="qr" src={url} width={size} height={size} alt="QR code" /> : null;
}

export function CopyButton({ text, label = 'Copy' }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      className="secondary"
      onClick={async () => {
        await navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
    >
      {copied ? 'Copied ✓' : label}
    </button>
  );
}

const VERDICT_TEXT = {
  VALID: 'Valid credential',
  REVOKED: 'Revoked by issuer',
  UNTRUSTED_ISSUER: 'Untrusted issuer',
  INVALID_SIGNATURE: 'Invalid signature',
  EXPIRED: 'Expired',
  HOLDER_BINDING_FAILED: 'Holder binding failed',
  REPLAY_DETECTED: 'Replay detected',
  UNKNOWN_SCHEMA: 'Unknown credential type',
  WRONG_STATUS_REGISTRY: 'Untrusted status registry',
  NOT_ANCHORED: 'Not anchored on-chain',
  ISSUER_UNREACHABLE: 'Issuer DID unreachable',
  INVALID_FORMAT: 'Malformed presentation',
  DECLINED: 'Declined by student',
  ERROR: 'Verification error',
};

export function VerdictBadge({ verdict }) {
  if (!verdict) return null;
  return <span className={`badge ${verdict === 'VALID' ? 'badge-ok' : 'badge-bad'}`}>{VERDICT_TEXT[verdict] ?? verdict}</span>;
}

export function ClaimTable({ claims }) {
  const entries = Object.entries(claims ?? {});
  if (!entries.length) return <p className="muted">No claims disclosed.</p>;
  return (
    <table className="claims">
      <tbody>
        {entries.map(([k, v]) => (
          <tr key={k}>
            <th>{CLAIM_LABELS[k] ?? k}</th>
            <td>{String(v)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function TxLink({ hash }) {
  if (!hash) return null;
  const short = `${hash.slice(0, 10)}…${hash.slice(-6)}`;
  return EXPLORER_TX_URL ? (
    <a href={`${EXPLORER_TX_URL}${hash}`} target="_blank" rel="noreferrer">
      {short}
    </a>
  ) : (
    <code title={hash}>{short}</code>
  );
}

/** QR scanner using the native BarcodeDetector API (Chrome/Edge/Android). */
export function QrScanner({ onResult, onClose }) {
  const videoRef = useRef(null);
  const onResultRef = useRef(onResult);
  onResultRef.current = onResult;
  const [error, setError] = useState(null);
  useEffect(() => {
    if (!('BarcodeDetector' in window)) {
      setError('QR scanning is not supported in this browser. Paste the request instead.');
      return undefined;
    }
    let stream;
    let stopped = false;
    const detector = new window.BarcodeDetector({ formats: ['qr_code'] });
    (async () => {
      try {
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
        videoRef.current.srcObject = stream;
        await videoRef.current.play();
        while (!stopped) {
          const codes = await detector.detect(videoRef.current).catch(() => []);
          if (codes.length) {
            onResultRef.current(codes[0].rawValue);
            break;
          }
          await new Promise((r) => setTimeout(r, 300));
        }
      } catch (e) {
        setError(`Camera unavailable: ${e.message}`);
      }
    })();
    return () => {
      stopped = true;
      stream?.getTracks().forEach((t) => t.stop());
    };
  }, []);
  return (
    <div className="scanner">
      {error ? <Notice kind="error">{error}</Notice> : <video ref={videoRef} muted playsInline />}
      <button className="secondary" onClick={onClose}>
        Close scanner
      </button>
    </div>
  );
}

const STATUS_STYLE = {
  active: 'ok', issued: 'ok', completed: 'ok', anchored: 'ok',
  pending: 'warn', awaiting_student: 'warn', processing: 'warn',
  suspended: 'bad', revoked: 'bad', rejected: 'bad', declined: 'bad', failed: 'bad', expired: 'muted',
};
const STATUS_TEXT = { awaiting_student: 'Awaiting student sign-up' };

export function StatusBadge({ status }) {
  if (!status) return null;
  return <span className={`badge badge-${STATUS_STYLE[status] ?? 'muted'}`}>{STATUS_TEXT[status] ?? status.replace(/_/g, ' ')}</span>;
}

export function Field({ label, hint, children }) {
  return (
    <label>
      <span>
        {label} {hint && <span className="muted small">{hint}</span>}
      </span>
      {children}
    </label>
  );
}

export function Stat({ label, value }) {
  return (
    <div className="stat">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
