import { useCallback, useEffect, useRef, useState } from 'react';

/** Loads data, re-polls every `intervalMs` (so other accounts' actions show up), exposes reload(). */
export function usePolling(loader, intervalMs = 8000) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const loaderRef = useRef(loader);
  loaderRef.current = loader;

  const reload = useCallback(async () => {
    try {
      setData(await loaderRef.current());
      setError(null);
    } catch (e) {
      setError(e);
    }
  }, []);

  useEffect(() => {
    reload();
    const t = setInterval(() => document.visibilityState === 'visible' && reload(), intervalMs);
    return () => clearInterval(t);
  }, [reload, intervalMs]);

  return { data, error, reload };
}

/** Wraps an async action with busy state and a message for the <Notice>. */
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState(null);
  const run = useCallback(async (fn, successText) => {
    setBusy(true);
    setMsg(null);
    try {
      const r = await fn();
      if (successText) setMsg({ kind: 'success', text: typeof successText === 'function' ? successText(r) : successText });
      return r;
    } catch (e) {
      setMsg({ kind: 'error', text: e.message });
      return undefined;
    } finally {
      setBusy(false);
    }
  }, []);
  return { busy, msg, setMsg, run };
}
