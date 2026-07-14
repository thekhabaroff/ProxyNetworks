import {
  getActiveProfileId,
  getEnabled,
  getLastError,
  getProfile,
  setEnabled,
  setLastError,
  setActiveProfileId,
  initializeDefaults,
} from './storage.js';

const attemptedAuthRequests = new Set();
const authCleanupTimers = new Map();
const AUTH_REQUEST_TTL_MS = 120000;

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

function proxyClear(scope) {
  return new Promise((resolve, reject) => {
    chrome.proxy.settings.clear({ scope }, () => {
      const error = chrome.runtime.lastError;
      if (error) {
        reject(new Error(error.message));
        return;
      }
      resolve();
    });
  });
}

function endpointToProxyServer(endpoint) {
  if (!endpoint || !endpoint.host || !endpoint.port) {
    return null;
  }

  const port = Number(endpoint.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return null;
  }

  return {
    scheme: endpoint.scheme,
    host: endpoint.host,
    port,
  };
}

function extensionIsAllowedIncognitoAccess() {
  return new Promise((resolve) => {
    if (!chrome.extension?.isAllowedIncognitoAccess) {
      resolve(false);
      return;
    }

    chrome.extension.isAllowedIncognitoAccess((isAllowed) => {
      resolve(Boolean(isAllowed));
    });
  });
}

export function buildProxyConfig(profile) {
  if (!profile) {
    return { mode: 'direct' };
  }

  if (profile.mode === 'pac_script') {
    return {
      mode: 'pac_script',
      pacScript: {
        data: profile.pacScript || '',
        mandatory: true,
      },
    };
  }

  if (profile.mode === 'fixed_servers') {
    if (profile.useAdvanced) {
      const rules = {};
      const httpProxy = endpointToProxyServer(profile.proxyForHttp);
      const httpsProxy = endpointToProxyServer(profile.proxyForHttps);
      const socksProxy = endpointToProxyServer(profile.socks);

      if (httpProxy) {
        rules.proxyForHttp = httpProxy;
      }
      if (httpsProxy) {
        rules.proxyForHttps = httpsProxy;
      }
      if (socksProxy) {
        rules.fallbackProxy = socksProxy;
      }
      if (Array.isArray(profile.bypassList) && profile.bypassList.length > 0) {
        rules.bypassList = profile.bypassList;
      }

      return {
        mode: 'fixed_servers',
        rules,
      };
    }

    const singleProxy = endpointToProxyServer(profile);
    if (!singleProxy) {
      return { mode: 'direct' };
    }

    return {
      mode: 'fixed_servers',
      rules: {
        singleProxy,
        bypassList: Array.isArray(profile.bypassList) ? profile.bypassList : [],
      },
    };
  }

  return { mode: profile.mode };
}

async function applyProfile(profile) {
  if (profile.incognito && !(await extensionIsAllowedIncognitoAccess())) {
    throw new Error('Для профиля инкогнито разрешите расширению доступ в инкогнито в chrome://extensions');
  }

  const config = buildProxyConfig(profile);
  const scope = profile.incognito ? 'incognito_session_only' : 'regular';
  await proxySet(config, scope);
  await setLastError(null);
  return config;
}

async function disableAll() {
  await proxySet({ mode: 'direct' }, 'regular');
  await proxyClear('incognito_session_only');
  await setEnabled(false);
  await setLastError(null);
}

async function enableActiveProfile() {
  const activeProfileId = await getActiveProfileId();
  if (!activeProfileId) {
    throw new Error('Активный профиль не выбран');
  }

  const profile = await getProfile(activeProfileId);
  if (!profile) {
    throw new Error('Активный профиль не найден');
  }

  await applyProfile(profile);
  await setEnabled(true);
  return profile;
}

async function getStatus() {
  const enabled = await getEnabled();
  const activeProfileId = await getActiveProfileId();
  const activeProfile = activeProfileId ? await getProfile(activeProfileId) : null;
  const lastError = await getLastError();
  return {
    enabled,
    activeProfileId,
    activeProfileName: activeProfile?.name ?? null,
    lastError,
  };
}

chrome.proxy.onProxyError.addListener(async (details) => {
  const message = details?.error || 'Неизвестная ошибка прокси';
  const suffix = details?.details ? `: ${details.details}` : '';
  await setLastError(`${message}${suffix}`);
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

    rememberAuthAttempt(details.requestId);

    (async () => {
      const activeProfileId = await getActiveProfileId();
      const profile = activeProfileId ? await getProfile(activeProfileId) : null;
      if (!profile || !profile.username) {
        callback({});
        return;
      }

      callback({
        authCredentials: {
          username: profile.username,
          password: profile.password || '',
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

chrome.runtime.onStartup.addListener(async () => {
  try {
    if (await getEnabled()) {
      await enableActiveProfile();
    }
  } catch (error) {
    await setLastError(error instanceof Error ? error.message : String(error));
    await setEnabled(false);
  }
});

chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason !== 'install') {
    return;
  }

  await initializeDefaults();
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.action) {
    return undefined;
  }

  (async () => {
    if (message.action === 'enable') {
      if (message.profileId) {
        await setActiveProfileId(message.profileId);
      }
      const profile = await enableActiveProfile();
      sendResponse({ ok: true, profile });
      return;
    }

    if (message.action === 'disable') {
      await disableAll();
      sendResponse({ ok: true });
      return;
    }

    if (message.action === 'applyProfile') {
      if (message.profileId) {
        await setActiveProfileId(message.profileId);
      }

      const enabled = await getEnabled();
      if (enabled) {
        const profile = await enableActiveProfile();
        sendResponse({ ok: true, profile });
        return;
      }

      const activeProfileId = await getActiveProfileId();
      const profile = activeProfileId ? await getProfile(activeProfileId) : null;
      sendResponse({ ok: true, profile });
      return;
    }

    if (message.action === 'getStatus') {
      sendResponse(await getStatus());
      return;
    }

    if (message.action === 'checkProxy') {
      try {
        const response = await fetch('https://api.ipify.org?format=json', { cache: 'no-store' });
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        await setLastError(null);
        const status = await getStatus();
        sendResponse({
          ok: true,
          ip: data.ip ?? null,
          status,
          tips: [],
        });
      } catch (error) {
        const messageText = error instanceof Error ? error.message : String(error);
        await setLastError(messageText);
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

    sendResponse({ ok: false, error: 'Неизвестное действие' });
  })().catch(async (error) => {
    const messageText = error instanceof Error ? error.message : String(error);
    await setLastError(messageText);
    sendResponse({ ok: false, error: messageText });
  });

  return true;
});
