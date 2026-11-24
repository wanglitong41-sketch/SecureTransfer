let chain = Promise.resolve();
export function digest(
  buffer: ArrayBuffer,
  retain: boolean,
  signal: AbortSignal,
): Promise<{ sha256: string; buffer?: ArrayBuffer }> {
  const work = chain.then(
    () =>
      new Promise<{ sha256: string; buffer?: ArrayBuffer }>((resolve, reject) => {
        if (signal.aborted) {
          reject(signal.reason);
          return;
        }
        const worker = new Worker(new URL('./hash-worker.ts', import.meta.url), { type: 'module' });
        const cleanup = () => {
          signal.removeEventListener('abort', abort);
          worker.terminate();
        };
        const abort = () => {
          cleanup();
          reject(new DOMException('Cancelled', 'AbortError'));
        };
        signal.addEventListener('abort', abort, { once: true });
        worker.onmessage = (event: MessageEvent<{ sha256?: string; buffer?: ArrayBuffer }>) => {
          cleanup();
          if (typeof event.data.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(event.data.sha256)) {
            reject(new Error('Hash calculation failed'));
            return;
          }
          resolve({
            sha256: event.data.sha256,
            ...(event.data.buffer ? { buffer: event.data.buffer } : {}),
          });
        };
        worker.onerror = () => {
          cleanup();
          reject(new Error('Hash worker failed'));
        };
        worker.postMessage({ buffer, retain }, [buffer]);
      }),
  );
  chain = work.then(
    () => {},
    () => {},
  );
  return work;
}
