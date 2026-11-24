import { MESSAGE_TYPES as T } from '@securetransfer/protocol';
import type { JsonObject, PublicKeyProof } from '@securetransfer/protocol';
import type { ConnectionManager } from './connection';

interface LocalKey {
  keyId: string;
  username: string;
  privateKey: CryptoKey;
}
function database(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('securetransfer-keys', 1);
    request.onupgradeneeded = () => request.result.createObjectStore('keys', { keyPath: 'keyId' });
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
async function keyStore<T>(
  mode: IDBTransactionMode,
  run: (store: IDBObjectStore) => IDBRequest<T>,
) {
  const db = await database();
  try {
    return await new Promise<T>((resolve, reject) => {
      const tx = db.transaction('keys', mode);
      const request = run(tx.objectStore('keys'));
      tx.oncomplete = () => resolve(request.result);
      tx.onabort = () => reject(tx.error);
      tx.onerror = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}
export async function localKeys(username: string): Promise<LocalKey[]> {
  const keys: LocalKey[] = await keyStore('readonly', (store) => store.getAll());
  return keys.filter((key) => key.username === username.toLowerCase());
}
const encode = (buffer: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(buffer)));
async function proof(data: JsonObject, privateKey: CryptoKey): Promise<PublicKeyProof> {
  const { challengeId, keyId, signingDataBase64 } = data;
  if (
    typeof challengeId !== 'string' ||
    typeof keyId !== 'string' ||
    typeof signingDataBase64 !== 'string'
  )
    throw new Error('Invalid public key challenge');
  const bytes = Uint8Array.from(atob(signingDataBase64), (char) => char.charCodeAt(0));
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, bytes);
  return { challengeId, keyId, signatureBase64: encode(signature) };
}
export async function enrollKey(
  manager: ConnectionManager,
  username: string,
  label: string,
  password: string,
) {
  const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
    'verify',
  ]);
  const publicKeySpki = encode(await crypto.subtle.exportKey('spki', keys.publicKey));
  const challenge = await manager.request(T.KEY_CHALLENGE, { publicKeySpki, label });
  const signed = await proof(challenge, keys.privateKey);
  const local = {
    keyId: signed.keyId,
    username: username.toLowerCase(),
    privateKey: keys.privateKey,
  };
  await keyStore('readwrite', (store) => store.put(local));
  try {
    await manager.request(T.KEY_ENROLL, { ...signed, password });
  } catch (error) {
    await forgetKey(local.keyId);
    throw error;
  }
}
export async function loginWithLocalKey(manager: ConnectionManager, key: LocalKey) {
  const challenge = await manager.request(T.KEY_CHALLENGE, {
    username: key.username,
    keyId: key.keyId,
  });
  if (challenge['keyId'] !== key.keyId) throw new Error('Invalid public key challenge');
  return manager.loginWithKey(await proof(challenge, key.privateKey));
}
export async function forgetKey(keyId: string) {
  await keyStore('readwrite', (store) => store.delete(keyId));
}
