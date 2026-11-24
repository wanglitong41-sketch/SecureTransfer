<script setup lang="ts">
import { computed, onMounted, onBeforeUnmount, ref } from 'vue';
import { ConnectionManager } from './connection';
import type { LinkStatus } from './connection';
import AccountWorkspace from './components/AccountWorkspace.vue';
import type { UserProfile } from '@securetransfer/protocol';
import { PROTOCOL_VERSION } from '@securetransfer/protocol';

const state = ref<'checking' | 'ready' | 'error'>('checking');
const statusText = computed(
  () =>
    ({
      checking: '正在检查服务',
      ready: '服务已就绪',
      error: '暂时无法连接服务',
    })[state.value],
);

async function checkService() {
  state.value = 'checking';
  try {
    const response = await fetch('/api/health', { signal: AbortSignal.timeout(5000) });
    const data: unknown = await response.json();
    if (
      !response.ok ||
      typeof data !== 'object' ||
      data === null ||
      !('status' in data) ||
      data.status !== 'ok'
    ) {
      throw new Error('Health check failed');
    }
    state.value = 'ready';
  } catch {
    state.value = 'error';
  }
}

const user = ref<UserProfile | null>(null);
const link = ref<LinkStatus>({ state: 'idle', reason: '' });
const completed = ref(0);
const connectionId = ref('');
const probeError = ref('');
const probing = ref(false);
const manager = new ConnectionManager(
  'wss://localhost:8443/ws',
  (status) => {
    link.value = status;
  },
  (profile) => {
    user.value = profile;
  },
);
const linkText = computed(
  () =>
    ({
      idle: '尚未连接',
      connecting: '正在连接',
      open: '连接已建立',
      reconnecting: '正在重连',
      closed: '连接已关闭',
    })[link.value.state],
);
function connectLink() {
  probeError.value = '';
  completed.value = 0;
  connectionId.value = '';
  void manager.connect().catch(() => {
    probeError.value = '连接未完成，请稍后重试';
  });
}
async function runProbe() {
  probing.value = true;
  probeError.value = '';
  try {
    for (let sequence = 1; sequence <= 10; sequence++) {
      const result = await manager.probe(sequence);
      if (result['sequence'] !== sequence || typeof result['connectionId'] !== 'string') {
        throw new Error('诊断响应不匹配');
      }
      if (connectionId.value && connectionId.value !== result['connectionId'])
        throw new Error('连接发生变化，请重新验证');
      connectionId.value = result['connectionId'];
      completed.value = sequence;
    }
  } catch (error) {
    probeError.value = error instanceof Error ? error.message : '验证失败';
  } finally {
    probing.value = false;
  }
}
onMounted(() => {
  void checkService();
  window.addEventListener('pagehide', closeLink);
});
function closeLink() {
  manager.disconnect();
}
onBeforeUnmount(() => {
  closeLink();
  window.removeEventListener('pagehide', closeLink);
});
</script>

<template>
  <div class="page">
    <header class="topbar">
      <a class="brand" href="/" aria-label="SecureTransfer 首页">
        <span class="brand-icon" aria-hidden="true">S</span>
        SecureTransfer
      </a>
      <span class="edition">软件与系统安全 · 实验 1B</span>
    </header>
    <main>
      <p class="eyebrow">SECURE FILE TRANSFER</p>
      <h1>让文件传输，<br />安全而有序。</h1>
      <p class="intro">在个人文件空间中管理每一次传输。上传、下载与校验，在可信连接中完成。</p>
      <section class="status-card" aria-labelledby="status-heading">
        <div class="status-label">环境状态</div>
        <h2 id="status-heading" role="status" aria-live="polite">
          <span class="status-dot" :class="state" aria-hidden="true"></span>{{ statusText }}
        </h2>
        <p>第六阶段 · 扩展功能</p>
        <button type="button" :disabled="state === 'checking'" @click="checkService">
          重新检查
        </button>
      </section>
      <AccountWorkspace :manager="manager" :user="user" :link="link" />
      <section class="connection-panel" aria-labelledby="connection-heading">
        <div>
          <p class="eyebrow">连接验证</p>
          <h2 id="connection-heading">{{ linkText }}</h2>
          <p>验证同一连接的连续通信。已认证连接保持会话；未认证连接在 10 秒后关闭。</p>
          <p v-if="link.reason">{{ link.reason }}</p>
        </div>
        <div class="connection-actions">
          <button
            type="button"
            :disabled="['open', 'connecting', 'reconnecting'].includes(link.state)"
            @click="connectLink"
          >
            建立连接
          </button>
          <button
            type="button"
            :disabled="link.state !== 'open' || probing || completed === 10"
            @click="runProbe"
          >
            连续验证 10 次
          </button>
          <button
            type="button"
            :disabled="!['open', 'connecting', 'reconnecting'].includes(link.state)"
            @click="closeLink"
          >
            断开连接
          </button>
        </div>
        <p data-testid="probe-count">已确认 {{ completed }} / 10</p>
        <p v-if="connectionId" class="connection-id" data-testid="connection-id">
          连接标识：{{ connectionId }}
        </p>
        <p v-if="probeError" role="alert">{{ probeError }}</p>
      </section>
      <div class="facts" aria-label="项目基础配置">
        <div><span>通信方式</span><strong>HTTPS / WSS</strong></div>
        <div>
          <span>协议版本</span><strong>SFT1 · v{{ PROTOCOL_VERSION }}</strong>
        </div>
        <div><span>运行范围</span><strong>本机私有环境</strong></div>
      </div>
    </main>
    <footer>连接可信，传输可验。</footer>
  </div>
</template>
