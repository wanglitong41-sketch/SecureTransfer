<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from 'vue';
import { MESSAGE_TYPES as T } from '@securetransfer/protocol';
import { enrollKey, forgetKey, localKeys, loginWithLocalKey } from '../public-keys';
import type {
  FileRecord,
  UserProfile,
  TransferProgress,
  RegisteredKey,
  UploadCheckpoint,
} from '@securetransfer/protocol';
import type { ConnectionManager, LinkStatus } from '../connection';

import { TransferClient } from '../transfers';
import type { SavedDownload } from '../transfers';

const props = defineProps<{
  manager: ConnectionManager;
  user: UserProfile | null;
  link: LinkStatus;
}>();
const username = ref(''),
  password = ref(''),
  error = ref(''),
  notice = ref('');
const busy = ref(false),
  files = ref<FileRecord[]>([]),
  nextAfter = ref<string | null>(null);
const confirming = ref<string | null>(null);

interface Job {
  id: number;
  sourceId?: string;
  progress: TransferProgress;
  saved?: SavedDownload;
  error?: string;
  controller: AbortController | null;
}
const jobs = ref<Job[]>([]);
const activeCount = computed(() => jobs.value.filter((job) => job.controller).length);
const transferBusy = computed(() => activeCount.value >= 3);
const downloadSlotsFull = computed(
  () =>
    jobs.value.filter(
      (job) => job.progress.direction === 'download' && (job.saved || job.controller),
    ).length >= 3,
);
const keys = ref<RegisteredKey[]>([]);
const availableKeys = ref<Awaited<ReturnType<typeof localKeys>>>([]);
const keyPassword = ref('');
const keyLabel = ref('此浏览器');
const keyChoice = ref('');
const selectedFiles = ref<string[]>([]);
const checkpoints = ref<UploadCheckpoint[]>([]);
const checkpointAfter = ref<string | null>(null);
const transfers = new TransferClient(props.manager);
let sequence = 0;

function percent(task: TransferProgress) {
  return task.size
    ? Math.floor((task.confirmed / task.size) * 100)
    : task.state === 'completed'
      ? 100
      : 0;
}
function transferLabel(task: TransferProgress) {
  return {
    hashing: '正在计算校验值',
    transferring: task.direction === 'upload' ? '正在上传' : '正在下载',
    verifying: '正在校验文件',
    completed: task.direction === 'upload' ? '上传已完成' : '下载已校验',
    failed: '传输未完成',
    paused: '已暂停',
  }[task.state];
}
function clearSaved(job: Job) {
  if (job.saved) URL.revokeObjectURL(job.saved.url);
  delete job.saved;
}
function clearJobs() {
  for (const job of jobs.value) {
    job.controller?.abort('leave');
    clearSaved(job);
  }
  jobs.value = [];
}
function removeJob(job: Job) {
  clearSaved(job);
  jobs.value = jobs.value.filter((entry) => entry.id !== job.id);
}
async function runTransfer(
  job: Job,
  work: (
    signal: AbortSignal,
    progress: (value: TransferProgress) => void,
  ) => Promise<SavedDownload | void>,
) {
  if (transferBusy.value || !props.user) return;
  jobs.value.push(job);
  const current = jobs.value.at(-1)!;
  const signal = current.controller!.signal;
  const userId = props.user.userId;
  try {
    const result = await work(signal, (value) => {
      current.progress = value;
    });
    if (result && signal.aborted) URL.revokeObjectURL(result.url);
    else if (result) current.saved = result;
    if (
      props.user?.userId === userId &&
      current.progress.direction === 'upload' &&
      current.progress.state === 'completed'
    ) {
      await loadFiles();
    }
  } catch (issue) {
    current.progress = { ...current.progress, state: 'failed' };
    const code = issue instanceof Error ? issue.message : '';
    if (signal.reason === 'cancel') notice.value = '传输已取消。';
    else if (signal.reason !== 'leave')
      current.error = messages[code] ?? '连接中断或传输失败。可在待续传上传中重新选择原文件。';
  } finally {
    current.controller = null;
    if (
      props.user?.userId === userId &&
      current.progress.direction === 'upload' &&
      props.link.state === 'open'
    ) {
      await loadCheckpoints().catch(() => {});
    }
  }
}
function uploadFile(event: Event, checkpoint?: string) {
  const input = event.target as HTMLInputElement;
  const selection = Array.from(input.files ?? []);
  input.value = '';
  if (selection.length > 3 - activeCount.value) {
    error.value = '每次最多同时运行 3 项传输，请减少选择的文件数。';
    return;
  }
  for (const file of selection) {
    const job: Job = {
      id: ++sequence,
      controller: new AbortController(),
      progress: {
        direction: 'upload',
        name: file.name,
        size: file.size,
        confirmed: 0,
        state: 'hashing',
      },
    };
    void runTransfer(job, async (signal, progress) => {
      await transfers.upload(file, progress, signal, checkpoint ? BigInt(checkpoint) : undefined);
    });
  }
}
function downloadSelection() {
  const selected = files.value.filter((file) => selectedFiles.value.includes(file.fileId));
  const downloadCount = jobs.value.filter(
    (job) => job.progress.direction === 'download' && (job.saved || job.controller),
  ).length;
  if (selected.length > Math.min(3 - activeCount.value, 3 - downloadCount)) {
    error.value = '请减少选择的文件数或关闭已完成的保存入口。';
    return;
  }
  selectedFiles.value = [];
  for (const file of selected) downloadFile(file);
}
function downloadFile(file: FileRecord) {
  if (downloadSlotsFull.value) {
    error.value = '请关闭已完成的保存入口，再开始新的下载。';
    return;
  }
  for (const entry of jobs.value) {
    if (!entry.controller && entry.sourceId === file.fileId) removeJob(entry);
  }
  void runTransfer(
    {
      id: ++sequence,
      sourceId: file.fileId,
      controller: new AbortController(),
      progress: {
        direction: 'download',
        name: file.name,
        size: file.size,
        confirmed: 0,
        state: 'transferring',
      },
    },
    (signal, progress) => transfers.download(file, progress, signal),
  );
}
async function loadCheckpoints(append = false) {
  const userId = props.user?.userId;
  const after = append ? checkpointAfter.value : null;
  const result = await props.manager.request(T.LIST_UPLOADS, after ? { after } : {});
  if (userId !== props.user?.userId) return;
  const paused = (result['items'] as UploadCheckpoint[]).filter(({ state }) => state === 'PAUSED');
  checkpoints.value = append ? [...checkpoints.value, ...paused] : paused;
  checkpointAfter.value = result['nextAfter'] as string | null;
}
async function loadKeys() {
  const result = await props.manager.request(T.KEY_LIST);
  keys.value = result['items'] as RegisteredKey[];
}
function registerKey() {
  const submitted = keyPassword.value;
  keyPassword.value = '';
  void perform(async () => {
    await enrollKey(props.manager, props.user!.username, keyLabel.value.trim(), submitted);
    await loadKeys();
    notice.value = '公钥已登记。';
  });
}
function revokeKey(id: string) {
  const submitted = keyPassword.value;
  keyPassword.value = '';
  void perform(async () => {
    await props.manager.request(T.KEY_REMOVE, { keyId: id, password: submitted });
    await forgetKey(id);
    notice.value = '公钥已撤销，请重新登录。';
  });
}
function signInWithKey() {
  const selected = availableKeys.value.find((key) => key.keyId === keyChoice.value);
  if (selected)
    void perform(async () => {
      await loginWithLocalKey(props.manager, selected);
    });
}
watch(username, (value) => {
  void localKeys(value)
    .then((items) => {
      if (value !== username.value) return;
      availableKeys.value = items;
      keyChoice.value = items[0]?.keyId ?? '';
    })
    .catch(() => {
      availableKeys.value = [];
    });
});
watch(
  () => props.user?.userId,
  () => {
    clearJobs();
    selectedFiles.value = [];
    keys.value = [];
    checkpoints.value = [];
    checkpointAfter.value = null;
    keyPassword.value = '';
    if (!props.user) {
      void localKeys(username.value)
        .then((items) => {
          availableKeys.value = items;
          keyChoice.value = items[0]?.keyId ?? '';
        })
        .catch(() => {
          availableKeys.value = [];
        });
    }
  },
);
onUnmounted(clearJobs);

const messages: Record<string, string> = {
  USERNAME_TAKEN: '用户名已被注册，请选择其他名称。',
  UNAUTHORIZED: '用户名、密码或会话无效，请重新登录。',
  RATE_LIMITED: '操作较频繁，请稍后再试。',
  FILE_NOT_FOUND: '文件已不存在或不属于当前用户，请刷新列表。',
  INVALID_MESSAGE: '请检查用户名和密码格式。',
  INVALID_STATE: '当前连接状态已变化，请重新登录。',
  HASH_MISMATCH: '文件校验失败，未发布或保存损坏文件。',
  SIZE_LIMIT_EXCEEDED: '单文件不能超过 100 MiB。',
  QUOTA_EXCEEDED: '存储配额不足，请先删除不需要的文件。',
  TASK_BUSY: '文件正在使用，请稍后重试。',
};
async function perform(work: () => Promise<void>) {
  busy.value = true;
  error.value = '';
  notice.value = '';
  try {
    await work();
  } catch (issue) {
    const message = issue instanceof Error ? issue.message : '';
    error.value = messages[message] ?? '操作未完成，请检查连接后重试。';
  } finally {
    busy.value = false;
  }
}
function authenticate(register = false) {
  const submitted = password.value;
  password.value = '';
  void perform(async () => {
    if (register) {
      await props.manager.register(username.value, submitted);
      notice.value = '注册成功，请输入密码登录。';
    } else {
      await props.manager.login(username.value, submitted);
    }
  });
}
async function loadFiles(append = false) {
  const response = await props.manager.listFiles(
    append ? (nextAfter.value ?? undefined) : undefined,
  );
  files.value = append ? [...files.value, ...response.items] : response.items;
  nextAfter.value = response.nextAfter;
  selectedFiles.value = selectedFiles.value.filter((id) =>
    files.value.some((file) => file.fileId === id),
  );
}
function refresh() {
  void perform(() => loadFiles());
}
function remove(fileId: string) {
  void perform(async () => {
    await props.manager.deleteFile(fileId);
    confirming.value = null;
    await loadFiles();
    notice.value = '文件已删除。';
  });
}
watch(
  () => [props.user?.userId, props.link.state],
  () => {
    if (!props.user) {
      files.value = [];
      nextAfter.value = null;
      confirming.value = null;
    } else if (props.link.state === 'open') {
      refresh();
      void loadKeys().catch(() => {});
      void loadCheckpoints().catch(() => {});
    }
  },
);
</script>

<template>
  <section class="account-panel" aria-labelledby="account-heading">
    <template v-if="!user">
      <div class="account-copy">
        <p class="eyebrow">个人文件空间</p>
        <h2 id="account-heading">登录你的账户</h2>
        <p>文件仅对所属用户可见。页面刷新后需要重新登录。</p>
      </div>
      <form class="auth-form" @submit.prevent="authenticate()">
        <label
          >用户名<input
            v-model="username"
            name="username"
            autocomplete="username"
            required
            pattern="[A-Za-z0-9_]{3,32}"
            minlength="3"
            maxlength="32"
            placeholder="3–32 位字母、数字或下划线"
        /></label>
        <label
          >密码<input
            v-model="password"
            name="password"
            type="password"
            autocomplete="current-password"
            required
            minlength="8"
            maxlength="128"
            placeholder="8–128 个字符"
        /></label>
        <div class="connection-actions">
          <button type="submit" :disabled="busy">登录</button>
          <button
            type="button"
            class="secondary"
            :disabled="busy || !username || password.length < 8"
            @click="authenticate(true)"
          >
            注册账户
          </button>
        </div>
      </form>
      <div v-if="availableKeys.length" class="connection-actions">
        <label v-if="availableKeys.length > 1"
          >本机密钥
          <select v-model="keyChoice">
            <option v-for="key in availableKeys" :key="key.keyId" :value="key.keyId">
              {{ key.keyId }}
            </option>
          </select>
        </label>
        <button type="button" :disabled="busy" @click="signInWithKey">使用公钥登录</button>
      </div>
    </template>
    <template v-else>
      <div class="workspace-heading">
        <div>
          <p class="eyebrow">个人文件空间</p>
          <h2 id="account-heading">{{ user.username }} 的文件</h2>
        </div>
        <button
          type="button"
          class="secondary"
          :disabled="busy || link.state !== 'open'"
          @click="
            clearJobs();
            perform(() => manager.logout());
          "
        >
          退出登录
        </button>
      </div>
      <div class="workspace-toolbar">
        <p>{{ link.state === 'open' ? '会话已认证' : '连接中断，正在尝试恢复会话…' }}</p>
        <button type="button" :disabled="busy || link.state !== 'open'" @click="refresh">
          刷新文件
        </button>
      </div>
      <label class="upload-control">
        上传文件（最大 100 MiB）
        <input
          type="file"
          aria-label="上传文件"
          :disabled="busy || transferBusy || link.state !== 'open'"
          multiple
          @change="uploadFile($event)"
        />
      </label>

      <section
        v-for="job in jobs"
        :key="job.id"
        class="transfer-progress"
        :aria-label="job.progress.name"
      >
        <strong>{{ transferLabel(job.progress) }} · {{ job.progress.name }}</strong>
        <progress aria-label="传输进度" :value="percent(job.progress)" max="100"></progress>
        <span data-testid="transfer-progress"
          >{{ percent(job.progress) }}% · {{ job.progress.confirmed.toLocaleString() }} /
          {{ job.progress.size.toLocaleString() }} B</span
        >
        <div class="connection-actions">
          <template v-if="job.controller">
            <button
              v-if="job.progress.direction === 'upload' && job.progress.state === 'transferring'"
              type="button"
              class="secondary"
              @click="job.controller?.abort('pause')"
            >
              暂停上传
            </button>
            <button
              type="button"
              class="secondary"
              :disabled="job.progress.state === 'verifying' || job.controller.signal.aborted"
              @click="job.controller?.abort('cancel')"
            >
              取消传输
            </button>
          </template>
          <button v-else-if="!job.saved" type="button" class="secondary" @click="removeJob(job)">
            移除记录
          </button>
        </div>
        <p v-if="job.error" role="alert">{{ job.error }}</p>
        <div v-if="job.saved" class="download-ready">
          <p>完整性校验通过，请保存文件：{{ job.saved.name }}</p>
          <a :href="job.saved.url" :download="job.saved.name">保存文件</a>
          <button type="button" class="secondary" @click="removeJob(job)">关闭保存入口</button>
        </div>
      </section>
      <details v-if="checkpoints.length || checkpointAfter" open>
        <summary>待续传上传</summary>
        <div
          v-for="checkpoint in checkpoints"
          :key="checkpoint.transferId"
          class="transfer-progress"
        >
          <span
            >{{ checkpoint.name }} · 已确认
            {{ checkpoint.confirmedOffset.toLocaleString() }} B</span
          >
          <label
            >选择原文件续传
            <input
              type="file"
              :disabled="transferBusy || link.state !== 'open'"
              @change="uploadFile($event, checkpoint.transferId)"
            />
          </label>
          <button
            type="button"
            class="secondary"
            @click="
              perform(async () => {
                await manager.requestPacket(T.CANCEL_TRANSFER, {}, BigInt(checkpoint.transferId));
                await loadCheckpoints();
              })
            "
          >
            放弃断点
          </button>
        </div>
        <button v-if="checkpointAfter" type="button" @click="perform(() => loadCheckpoints(true))">
          更多上传记录
        </button>
      </details>
      <details>
        <summary>公钥管理</summary>
        <form class="auth-form" @submit.prevent="registerKey">
          <label>密钥名称<input v-model="keyLabel" maxlength="48" required /></label>
          <label
            >当前账号密码<input
              v-model="keyPassword"
              type="password"
              autocomplete="current-password"
              required
          /></label>
          <button type="submit" :disabled="busy || !keyPassword || link.state !== 'open'">
            登记公钥
          </button>
        </form>
        <ul v-if="keys.length">
          <li v-for="key in keys" :key="key.keyId">
            {{ key.label }}
            <button
              type="button"
              class="secondary"
              :disabled="busy || !keyPassword"
              @click="revokeKey(key.keyId)"
            >
              撤销公钥
            </button>
          </li>
        </ul>
      </details>
      <p v-if="!files.length" class="empty-state">还没有文件，选择一个文件开始上传。</p>
      <div v-else class="table-scroll">
        <button
          type="button"
          :disabled="busy || !selectedFiles.length || transferBusy || link.state !== 'open'"
          @click="downloadSelection"
        >
          下载所选文件（{{ selectedFiles.length }}）
        </button>
        <table class="file-table">
          <thead>
            <tr>
              <th>选择</th>
              <th>文件名</th>
              <th>大小</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="file in files" :key="file.fileId">
              <td>
                <input
                  v-model="selectedFiles"
                  type="checkbox"
                  :value="file.fileId"
                  :aria-label="'选择文件 ' + file.name"
                />
              </td>
              <td>{{ file.name }}</td>
              <td>{{ file.size.toLocaleString() }} B</td>
              <td>
                <button
                  type="button"
                  :disabled="busy || transferBusy || link.state !== 'open'"
                  @click="downloadFile(file)"
                >
                  下载
                </button>
                <template v-if="confirming === file.fileId">
                  <button type="button" :disabled="busy" @click="remove(file.fileId)">
                    确认删除
                  </button>
                  <button type="button" class="secondary" @click="confirming = null">取消</button>
                </template>
                <button
                  v-else
                  type="button"
                  class="secondary"
                  :disabled="busy || transferBusy || link.state !== 'open'"
                  @click="confirming = file.fileId"
                >
                  删除
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <button
        v-if="nextAfter"
        type="button"
        :disabled="busy"
        @click="perform(() => loadFiles(true))"
      >
        加载更多
      </button>
    </template>
    <p v-if="error" class="error-message" role="alert">{{ error }}</p>
    <p v-if="notice" class="notice-message" role="status" aria-label="账户提示">{{ notice }}</p>
  </section>
</template>
