export interface PublicKeyChallenge {
  challengeId: string;
  keyId: string;
  username: string;
  origin: string;
  nonceBase64: string;
  signingDataBase64: string;
  expiresAt: string;
}
export interface PublicKeyProof {
  challengeId: string;
  keyId: string;
  signatureBase64: string;
}
export type TransferDirection = 'upload' | 'download';
export interface TransferProgress {
  direction: TransferDirection;
  name: string;
  size: number;
  confirmed: number;
  state: 'hashing' | 'transferring' | 'verifying' | 'completed' | 'failed' | 'paused';
}

export interface RegisteredKey {
  keyId: string;
  label: string;
  createdAt: string;
}
export interface UploadCheckpoint {
  transferId: string;
  name: string;
  size: number;
  sha256: string;
  confirmedOffset: number;
  state: string;
  updatedAt: string;
  fileId?: string;
}
