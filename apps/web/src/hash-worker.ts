export {};
self.onmessage = async (event: MessageEvent<{ buffer: ArrayBuffer; retain: boolean }>) => {
  try {
    const buffer = event.data.buffer;
    const digest = await crypto.subtle.digest('SHA-256', buffer);
    const sha256 = [...new Uint8Array(digest)]
      .map((value) => value.toString(16).padStart(2, '0'))
      .join('');
    self.postMessage(
      { sha256, ...(event.data.retain ? { buffer } : {}) },
      { transfer: event.data.retain ? [buffer] : [] },
    );
  } catch {
    self.postMessage({ error: 'Hash calculation failed' });
  }
};
