import { decodeMessage, encodeMessage, MESSAGE_TYPES as T } from '@securetransfer/protocol';
import type {
  JsonObject,
  MessageType,
  UserProfile,
  FileRecord,
  ProtocolMessage,
} from '@securetransfer/protocol';

export type LinkState = 'idle' | 'connecting' | 'open' | 'reconnecting' | 'closed';
export interface LinkStatus {
  state: LinkState;
  reason: string;
}
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
function profile(data: JsonObject): UserProfile {
  if (
    typeof data['userId'] !== 'string' ||
    !uuid.test(data['userId']) ||
    typeof data['username'] !== 'string' ||
    typeof data['expiresAt'] !== 'string' ||
    !Number.isFinite(Date.parse(data['expiresAt']))
  )
    throw new Error('Invalid session response');
  return { userId: data['userId'], username: data['username'], expiresAt: data['expiresAt'] };
}
export class ConnectionManager {
  private socket: WebSocket | undefined;
  private pending = new Map<
    number,
    {
      resolve: (value: ProtocolMessage) => void;
      type: MessageType;
      transferId: bigint;
      reject: (reason: Error) => void;
      timer: ReturnType<typeof setTimeout>;
    }
  >();
  private channels = new Map<
    bigint,
    { receive: (message: ProtocolMessage) => void; close: (error: Error) => void }
  >();
  private retired = new Set<bigint>();
  private dataChain = Promise.resolve();
  private nextDataAt = 0;
  private nextId = 1;
  private retries = 0;
  private intentional = true;
  private retryTimer: ReturnType<typeof setTimeout> | undefined;
  private state: LinkState = 'idle';
  private token: string | undefined;
  private opening: Promise<void> | undefined;
  private rejectOpening: ((error: Error) => void) | undefined;
  constructor(
    private readonly url: string,
    private readonly onStatus: (status: LinkStatus) => void,
    private readonly onSession: (user: UserProfile | null) => void = () => {},
  ) {}
  private update(state: LinkState, reason = '') {
    this.state = state;
    this.onStatus({ state, reason });
  }
  connect(): Promise<void> {
    if (this.socket?.readyState === WebSocket.OPEN && this.state === 'open')
      return Promise.resolve();
    if (this.opening) return this.opening;
    this.intentional = false;
    clearTimeout(this.retryTimer);
    this.update('connecting');
    const socket = new WebSocket(this.url);
    this.socket = socket;
    socket.binaryType = 'arraybuffer';
    this.retired.clear();
    this.opening = new Promise<void>((resolve, reject) => {
      this.rejectOpening = reject;
      socket.onopen = () => {
        void (async () => {
          if (this.socket !== socket || this.intentional) return;
          if (this.token)
            this.onSession(profile(await this.rawRequest(T.AUTH_RESUME, { token: this.token })));
          if (this.socket !== socket || this.intentional) return;
          this.opening = undefined;
          this.rejectOpening = undefined;
          this.update('open');
          resolve();
        })().catch((error: unknown) => {
          this.clearSession();
          socket.close(1008, 'Session restore failed');
          reject(error instanceof Error ? error : new Error('Session restore failed'));
        });
      };
    });
    socket.onmessage = (event: MessageEvent<unknown>) => {
      if (this.socket !== socket || this.intentional) return;
      try {
        if (!(event.data instanceof ArrayBuffer)) throw new Error('Expected binary response');
        const message = decodeMessage(new Uint8Array(event.data));

        if (message.header.requestId === 0) {
          const channel = this.channels.get(message.header.transferId);
          if (channel) channel.receive(message);
          else if (!this.retired.has(message.header.transferId))
            throw new Error('Unmatched transfer');
          return;
        }
        if (
          (message.header.messageType !== T.RESULT && message.header.messageType !== T.ERROR) ||
          !message.json
        )
          throw new Error('Unexpected response');
        const pending = this.pending.get(message.header.requestId);
        if (!pending) throw new Error('Unmatched response');
        const creating = pending.type === T.UPLOAD_INIT || pending.type === T.DOWNLOAD_INIT;
        if (creating && message.header.messageType === T.RESULT) {
          if (message.header.transferId === 0n || message.header.offset !== 0n)
            throw new Error('Invalid task creation');
        } else if (message.header.transferId !== pending.transferId)
          throw new Error('Unexpected transfer ID');
        if (!creating && pending.transferId === 0n && message.header.offset !== 0n)
          throw new Error('Unexpected response offset');
        clearTimeout(pending.timer);
        this.pending.delete(message.header.requestId);
        if (message.header.messageType === T.ERROR)
          pending.reject(new Error(String(message.json['code'])));
        else {
          this.retries = 0;
          pending.resolve(message);
        }
      } catch {
        socket.close(1002, 'Invalid server response');
      }
    };
    socket.onerror = () => {};
    socket.onclose = (event) => {
      if (this.socket !== socket) return;
      this.socket = undefined;
      this.rejectOpening?.(new Error('Connection closed'));
      this.opening = undefined;
      this.rejectOpening = undefined;
      this.rejectPending(new Error('Connection closed'));
      if (this.intentional || [1000, 1008, 1002, 1009].includes(event.code)) {
        this.clearSession();
        this.update('closed', event.reason || '连接已关闭');
        return;
      }
      const delay = Math.min(1000 * 2 ** Math.min(this.retries++, 5), 30000);
      this.update('reconnecting', '连接中断，正在恢复');
      this.retryTimer = setTimeout(
        () => {
          void this.connect().catch(() => {});
        },
        Math.min(30000, delay + Math.random() * delay * 0.2),
      );
    };
    return this.opening;
  }
  private async rawRequest(type: MessageType, body: JsonObject = {}): Promise<JsonObject> {
    return (await this.rawPacket(type, body)).json!;
  }
  private rawPacket(
    type: MessageType,
    body: JsonObject = {},
    transferId = 0n,
    offset = 0n,
  ): Promise<ProtocolMessage> {
    if (this.socket?.readyState !== WebSocket.OPEN)
      return Promise.reject(new Error('Connection is not open'));
    if (this.pending.size >= 16 || this.socket.bufferedAmount >= 1024 * 1024)
      return Promise.reject(new Error('Connection is busy'));
    let id = this.nextId;
    while (this.pending.has(id)) id = id === 0xffffffff ? 1 : id + 1;
    this.nextId = id === 0xffffffff ? 1 : id + 1;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => {
          this.pending.delete(id);
          reject(new Error('Request timeout'));
        },
        type === T.TRANSFER_FINISH ? 120000 : 10000,
      );
      this.pending.set(id, { resolve, reject, timer, type, transferId });
      try {
        this.socket!.send(encodeMessage(type, id, body, transferId, offset));
      } catch (error) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(error instanceof Error ? error : new Error('Send failed'));
      }
    });
  }
  async request(type: MessageType, body: JsonObject = {}) {
    await this.connect();
    return this.rawRequest(type, body);
  }
  async requestPacket(type: MessageType, body: JsonObject = {}, transferId = 0n, offset = 0n) {
    await this.connect();
    return this.rawPacket(type, body, transferId, offset);
  }
  get isReady() {
    return this.state === 'open' && this.socket?.readyState === WebSocket.OPEN;
  }
  attachTransfer(
    id: bigint,
    receive: (message: ProtocolMessage) => void,
    close: (error: Error) => void,
  ) {
    if (this.channels.has(id)) throw new Error('Duplicate transfer channel');
    const channel = { receive, close };
    this.channels.set(id, channel);
    return () => {
      if (this.channels.get(id) !== channel) return;
      this.channels.delete(id);
      this.retired.add(id);
      if (this.retired.size > 20) this.retired.delete(this.retired.values().next().value!);
    };
  }
  sendTransfer(
    type: MessageType,
    content: JsonObject | Uint8Array,
    id: bigint,
    offset: number,
    signal: AbortSignal,
  ) {
    const socket = this.socket;
    const work = this.dataChain
      .catch(() => {})
      .then(async () => {
        signal.throwIfAborted();
        if (!socket || socket !== this.socket || socket.readyState !== WebSocket.OPEN)
          throw new Error('Connection closed');
        if (type === T.FILE_CHUNK || type === T.CHUNK_ACK) {
          const wait = this.nextDataAt - performance.now();
          if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
          this.nextDataAt = performance.now() + 6;
        }
        if (socket.bufferedAmount >= 1024 * 1024) {
          const start = performance.now();
          while (socket.bufferedAmount > 256 * 1024) {
            signal.throwIfAborted();
            if (socket.readyState !== WebSocket.OPEN || performance.now() - start > 30000)
              throw new Error('Send buffer timeout');
            await new Promise((resolve) => setTimeout(resolve, 10));
          }
        }
        signal.throwIfAborted();
        if (socket !== this.socket || socket.readyState !== WebSocket.OPEN)
          throw new Error('Connection closed');
        socket.send(encodeMessage(type, 0, content, id, BigInt(offset)));
      });
    this.dataChain = work;
    return work;
  }
  probe(sequence: number) {
    return this.request(T.PROBE, { sequence });
  }
  async register(username: string, password: string) {
    return this.request(T.REGISTER, { username, password });
  }
  async login(username: string, password: string) {
    return this.acceptSession(await this.request(T.LOGIN, { username, password }));
  }
  async loginWithKey(proof: import('@securetransfer/protocol').PublicKeyProof) {
    return this.acceptSession(await this.request(T.KEY_LOGIN, { ...proof }));
  }
  private acceptSession(result: JsonObject) {
    const user = profile(result);
    if (typeof result['token'] !== 'string' || !/^[a-f0-9]{64}$/.test(result['token']))
      throw new Error('Invalid session token');
    this.token = result['token'];
    this.onSession(user);
    return user;
  }
  async logout() {
    try {
      if (this.token) await this.request(T.LOGOUT);
    } finally {
      this.disconnect();
    }
  }
  async listFiles(after?: string) {
    const result = await this.request(T.LIST_FILES, after ? { after } : {});
    if (
      !Array.isArray(result['items']) ||
      (result['nextAfter'] !== null &&
        (typeof result['nextAfter'] !== 'string' || !uuid.test(result['nextAfter'])))
    ) {
      throw new Error('Invalid file list');
    }
    const items = result['items'].map((item: unknown): FileRecord => {
      if (typeof item !== 'object' || !item) throw new Error('Invalid file');
      const row = item as JsonObject;
      if (
        typeof row['fileId'] !== 'string' ||
        !uuid.test(row['fileId']) ||
        typeof row['name'] !== 'string' ||
        typeof row['size'] !== 'number' ||
        !Number.isSafeInteger(row['size']) ||
        row['size'] < 0 ||
        typeof row['sha256'] !== 'string' ||
        !/^[a-f0-9]{64}$/.test(row['sha256']) ||
        typeof row['createdAt'] !== 'string'
      ) {
        throw new Error('Invalid file');
      }
      return row as unknown as FileRecord;
    });
    return { items, nextAfter: result['nextAfter'] as string | null };
  }
  async deleteFile(fileId: string) {
    await this.request(T.DELETE_FILE, { fileId });
  }
  private rejectPending(error: Error) {
    for (const request of this.pending.values()) {
      clearTimeout(request.timer);
      request.reject(error);
    }
    this.pending.clear();
    for (const channel of this.channels.values()) channel.close(error);
    this.channels.clear();
  }
  private clearSession() {
    this.token = undefined;
    this.onSession(null);
  }
  disconnect() {
    this.intentional = true;
    clearTimeout(this.retryTimer);
    this.rejectOpening?.(new Error('Connection closed by user'));
    this.opening = undefined;
    this.rejectOpening = undefined;
    this.rejectPending(new Error('Connection closed by user'));
    this.clearSession();
    this.socket?.close(1000, 'User disconnected');
    this.update('closed', '已主动断开');
  }
}
