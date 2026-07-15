import {
  getActiveProfileId,
  getEnabled,
  getLastError,
  getProfile,
  getSelectedProtocol,
  setEnabled,
  setLastError,
  setActiveProfileId,
  setSelectedProtocol,
  initializeDefaults,
} from './storage.js';
import {
  buildProxyConfig,
  buildSelectedProxyConfig,
  endpointToProxyServer,
  PROTOCOLS,
} from './config.js';

const attemptedAuthRequests = new Set();
const authCleanupTimers = new Map();
const AUTH_REQUEST_TTL_MS = 120000;
const CHECK_TIMEOUT_MS = 15000;
let endpointCheckInProgress = false;
let endpointTestAuth = null;
let pendingProfileAuth = null;
let ignoreProxyErrorsUntil = 0;

function normalizeProxyHost(host) {
  return String(host ?? '')
    .trim()
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '')
    .toLowerCase();
}

function proxyServersForProfile(profile, protocol = 'auto') {
  const endpoints = {
    http: profile?.proxyForHttp,
    https: profile?.proxyForHttps,
    socks: profile?.socks,
  };

  if (protocol !== 'auto') {
    const selectedServer = endpointToProxyServer(endpoints[protocol]);
    if (selectedServer) {
      return [selectedServer];
    }
  }

  return Object.values(endpoints).map(endpointToProxyServer).filter(Boolean);
}

function authScopeForProfile(profile, protocol = 'auto') {
  return {
    credentials: { username: profile?.username ?? '', password: profile?.password ?? '' },
    servers: proxyServersForProfile(profile, protocol),
  };
}

function isExpectedProxyChallenger(challenger, servers) {
  if (!challenger || !Array.isArray(servers)) {
    return false;
  }

  const host = normalizeProxyHost(challenger.host);
  const port = Number(challenger.port);
  return servers.some((server) => (
    normalizeProxyHost(server.host) === host && Number(server.port) === port
  ));
}

function clearAuthAttempt(requestId) {
  if (!requestId) {
    return;
  }

  attemptedAuthRequests.delete(requestId);
  const timerId = authCleanupTimers.get(requestId);
  if (timerId) {
    clearTimeout(timerId);
    authCleanupTimers.delete(requestId);
  }
}

function rememberAuthAttempt(requestId) {
  attemptedAuthRequests.add(requestId);
  const timerId = setTimeout(() => {
    clearAuthAttempt(requestId);
  }, AUTH_REQUEST_TTL_MS);
  authCleanupTimers.set(requestId, timerId);
}

function proxySet(value, scope) {
  return new Promise((resolve, reject) => {
    chrome.proxy.settings.set({ value, scope }, () => {
      const error = chrome.runtime.lastError;
      if (error) {
        reject(new Error(error.message));
        return;
      }
      resolve();
    });
  });
}

async function applyProfile(profile, protocol = 'auto') {
  if (!PROTOCOLS.includes(protocol)) {
    throw new Error('Неизвестный протокол прокси.');
  }
  let resolvedProtocol = protocol;
  if (protocol !== 'auto') {
    const endpoint = protocol === 'http'
      ? profile?.proxyForHttp
      : protocol === 'https'
        ? profile?.proxyForHttps
        : profile?.socks;
    if (!endpointToProxyServer(endpoint)) resolvedProtocol = 'auto';
  }
  const config = buildSelectedProxyConfig(profile, resolvedProtocol);
  if (config.mode === 'direct') {
    throw new Error('В профиле не настроен ни один прокси.');
  }
  await proxySet(config, 'regular');
  await setSelectedProtocol(resolvedProtocol);
  await setLastError(null);
  return config;
}

async function disableAll() {
  await proxySet({ mode: 'direct' }, 'regular');
  await setEnabled(false);
  await setLastError(null);
}

async function enableActiveProfile(protocol = null) {
  const activeProfileId = await getActiveProfileId();
  if (!activeProfileId) {
    throw new Error('Активный профиль не выбран');
  }

  const profile = await getProfile(activeProfileId);
  if (!profile) {
    throw new Error('Активный профиль не найден');
  }

  const selectedProtocol = protocol ?? await getSelectedProtocol();
  pendingProfileAuth = authScopeForProfile(profile, selectedProtocol);
  try {
    await applyProfile(profile, selectedProtocol);
    await setEnabled(true);
  } finally {
    pendingProfileAuth = null;
  }
  return profile;
}

async function getStatus() {
  const enabled = await getEnabled();
  const activeProfileId = await getActiveProfileId();
  const activeProfile = activeProfileId ? await getProfile(activeProfileId) : null;
  const lastError = await getLastError();
  const selectedProtocol = await getSelectedProtocol();
  return {
    enabled,
    activeProfileId,
    activeProfileName: activeProfile?.name ?? null,
    lastError,
    selectedProtocol,
  };
}

async function updateActionIcon() {
  const enabled = await getEnabled();
  const lastError = await getLastError();
  const color = !enabled ? 'gray' : lastError ? 'red' : 'green';
  try {
    await chrome.action.setIcon({
      path: {
        16: `icons/globe-${color}-16.png`,
        48: `icons/globe-${color}-48.png`,
        128: `icons/globe-${color}-128.png`,
      },
    });
  } catch (error) {
    console.error('Unable to update extension icon:', error);
  }
}

async function fetchExternalIp() {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), CHECK_TIMEOUT_MS);
  try {
    const response = await fetch('https://api.ipify.org?format=json', {
      cache: 'no-store',
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const data = await response.json();
    return data.ip ?? null;
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw new Error('Проверка превысила 15 секунд.');
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

chrome.proxy.onProxyError.addListener(async (details) => {
  if (endpointCheckInProgress || Date.now() < ignoreProxyErrorsUntil || !await getEnabled()) {
    return;
  }
  const message = details?.error || 'Неизвестная ошибка прокси';
  const suffix = details?.details ? `: ${details.details}` : '';
  await setLastError(`${message}${suffix}`);
  await updateActionIcon();
});

chrome.webRequest.onAuthRequired.addListener(
  (details, callback) => {
    if (!details.isProxy) {
      callback({});
      return;
    }

    if (attemptedAuthRequests.has(details.requestId)) {
      callback({ cancel: true });
      return;
    }

    (async () => {
      let authScope = endpointTestAuth || pendingProfileAuth;
      if (!authScope) {
        if (!await getEnabled()) {
          callback({});
          return;
        }
        const activeProfileId = await getActiveProfileId();
        const profile = activeProfileId ? await getProfile(activeProfileId) : null;
        const protocol = await getSelectedProtocol();
        authScope = authScopeForProfile(profile, protocol);
      }
      if (!authScope.credentials.username || !isExpectedProxyChallenger(details.challenger, authScope.servers)) {
        callback({});
        return;
      }

      rememberAuthAttempt(details.requestId);

      callback({
        authCredentials: {
          username: authScope.credentials.username,
          password: authScope.credentials.password || '',
        },
      });
    })().catch(() => callback({}));
  },
  { urls: ['<all_urls>'] },
  ['asyncBlocking']
);

chrome.webRequest.onCompleted.addListener(
  (details) => clearAuthAttempt(details.requestId),
  { urls: ['<all_urls>'] }
);

chrome.webRequest.onErrorOccurred.addListener(
  (details) => clearAuthAttempt(details.requestId),
  { urls: ['<all_urls>'] }
);

async function testProxyEndpoint(endpoint, credentials) {
  const server = endpointToProxyServer(endpoint);
  if (!server) {
    return { ok: false, error: 'Укажите корректные хост и порт прокси.' };
  }
  if (endpointCheckInProgress) {
    return { ok: false, error: 'Другая проверка прокси уже выполняется.' };
  }

  endpointCheckInProgress = true;
  endpointTestAuth = {
    credentials: {
      username: credentials?.username || '',
      password: credentials?.password || '',
    },
    servers: [server],
  };

  let previousConfig = { mode: 'direct' };
  let result;
  try {
    const enabled = await getEnabled();
    const activeProfileId = await getActiveProfileId();
    const activeProfile = activeProfileId ? await getProfile(activeProfileId) : null;
    const protocol = await getSelectedProtocol();
    if (enabled && activeProfile) {
      try {
        previousConfig = buildSelectedProxyConfig(activeProfile, protocol);
      } catch {
        previousConfig = buildProxyConfig(activeProfile);
      }
    }

    await proxySet({ mode: 'fixed_servers', rules: { singleProxy: server } }, 'regular');
    result = { ok: true, ip: await fetchExternalIp() };
  } catch (error) {
    result = { ok: false, error: error instanceof Error ? error.message : String(error) };
  } finally {
    try {
      await proxySet(previousConfig, 'regular');
    } catch (error) {
      result = {
        ok: false,
        error: `Не удалось восстановить настройки прокси: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
    endpointTestAuth = null;
    ignoreProxyErrorsUntil = Date.now() + 1500;
    endpointCheckInProgress = false;
  }

  return result;
}

async function restoreStoredState() {
  try {
    await initializeDefaults();
    if (await getEnabled()) {
      await enableActiveProfile();
    }
  } catch (error) {
    try {
      await proxySet({ mode: 'direct' }, 'regular');
    } catch (proxyError) {
      console.error('Unable to reset proxy settings:', proxyError);
    }
    await setLastError(error instanceof Error ? error.message : String(error));
    await setEnabled(false);
  } finally {
    await updateActionIcon();
  }
}

chrome.runtime.onStartup.addListener(async () => {
  await restoreStoredState();
});

chrome.runtime.onInstalled.addListener(async () => {
  await restoreStoredState();
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || !message.action) {
    return undefined;
  }

  (async () => {
    if (message.action === 'enable') {
      if (endpointCheckInProgress) throw new Error('Дождитесь завершения проверки прокси.');
      const targetProfileId = message.profileId || await getActiveProfileId();
      const profile = await getProfile(targetProfileId);
      if (!profile) throw new Error('Выбранный профиль не найден.');
      const selectedProtocol = message.protocol ?? await getSelectedProtocol();
      pendingProfileAuth = authScopeForProfile(profile, selectedProtocol);
      try {
        await applyProfile(profile, selectedProtocol);
        await setActiveProfileId(targetProfileId);
        await setEnabled(true);
      } finally {
        pendingProfileAuth = null;
      }
      await updateActionIcon();
      sendResponse({ ok: true, profile });
      return;
    }

    if (message.action === 'disable') {
      if (endpointCheckInProgress) throw new Error('Дождитесь завершения проверки прокси.');
      await disableAll();
      await updateActionIcon();
      sendResponse({ ok: true });
      return;
    }

    if (message.action === 'applyProfile') {
      if (endpointCheckInProgress) throw new Error('Дождитесь завершения проверки прокси.');
      if (Object.hasOwn(message, 'profileId') && !message.profileId) {
        if (await getEnabled()) await disableAll();
        await setActiveProfileId(null);
        await setSelectedProtocol('auto');
        await updateActionIcon();
        sendResponse({ ok: true, profile: null });
        return;
      }
      const protocol = message.protocol ?? await getSelectedProtocol();
      const enabled = await getEnabled();
      const targetProfileId = message.profileId || await getActiveProfileId();
      const profile = targetProfileId ? await getProfile(targetProfileId) : null;
      if (!profile) throw new Error('Выбранный профиль не найден.');
      if (enabled) {
        pendingProfileAuth = authScopeForProfile(profile, protocol);
        try {
          await applyProfile(profile, protocol);
          await setActiveProfileId(targetProfileId);
        } finally {
          pendingProfileAuth = null;
        }
        await updateActionIcon();
        sendResponse({ ok: true, profile });
        return;
      }

      await setActiveProfileId(targetProfileId);
      await setSelectedProtocol(protocol);
      sendResponse({ ok: true, profile });
      return;
    }

    if (message.action === 'getStatus') {
      sendResponse(await getStatus());
      return;
    }

    if (message.action === 'checkProxy') {
      if (endpointCheckInProgress) {
        sendResponse({
          ok: false,
          busy: true,
          error: 'Выполняется проверка другого прокси.',
          tips: [],
        });
        return;
      }
      try {
        const ip = await fetchExternalIp();
        if (await getEnabled()) await setLastError(null);
        await updateActionIcon();
        const status = await getStatus();
        sendResponse({
          ok: true,
          ip,
          status,
          tips: [],
        });
      } catch (error) {
        const messageText = error instanceof Error ? error.message : String(error);
        if (await getEnabled()) await setLastError(messageText);
        await updateActionIcon();
        sendResponse({
          ok: false,
          error: messageText,
          tips: [
            'Проверьте хост и порт прокси.',
            'Проверьте логин и пароль, если прокси требует авторизацию.',
            'Откройте chrome://net-internals/#proxy для низкоуровневой диагностики Chrome.',
          ],
        });
      }
      return;
    }

    if (message.action === 'checkProxyEndpoint') {
      sendResponse(await testProxyEndpoint(message.endpoint, {
        username: message.username,
        password: message.password,
      }));
      return;
    }

    sendResponse({ ok: false, error: 'Неизвестное действие' });
  })().catch(async (error) => {
    const messageText = error instanceof Error ? error.message : String(error);
    if (await getEnabled()) {
      await setLastError(messageText);
      await updateActionIcon();
    }
    sendResponse({ ok: false, error: messageText });
  });

  return true;
});
