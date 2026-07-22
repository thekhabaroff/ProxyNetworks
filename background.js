import {
  getActiveProfileId,
  getContentBlockingSettings,
  getEnabled,
  getProfile,
  getProfileSummaries,
  getProxyState,
  getSelectedProtocol,
  initializeDefaults,
  setLastError,
  setProxyState,
} from './storage.js';
import {
  getGeositeCacheStatus,
  geositeNamesFromProfiles,
  refreshGeositeCaches,
  resolveGeositeDomainList,
} from './geosite.js';
import { updateBlockRules } from './blocker.js';
import { getProfileProxyGeo } from './geo.js';
import {
  buildSelectedProxyConfig,
  endpointToProxyServer,
  getConfiguredProtocols,
  getProfileEndpoint,
  PROTOCOLS,
} from './config.js';
import {
  errorMessage,
  normalizeProxyHost,
} from './utils.js';

const attemptedAuthRequests = new Set();
const authCleanupTimers = new Map();
const AUTH_REQUEST_TTL_MS = 120000;
const CHECK_TIMEOUT_MS = 15000;
const STATIC_RULESET_IDS = Object.freeze({
  tracking: ['trackers_rules'],
});
const CONTROLLABLE_SETTING_LEVELS = new Set([
  'controllable_by_this_extension',
  'controlled_by_this_extension',
]);
const PROXY_CONTROL_ERROR = 'Настройки прокси контролируются политикой Chrome или другим расширением.';
const WEBRTC_PROTECTION_VALUE = 'disable_non_proxied_udp';
const WEBRTC_CONTROL_ERROR = 'Защита WebRTC контролируется политикой Chrome или другим расширением.';
let endpointCheckInProgress = false;
let proxyHealthCheckInProgress = false;
let endpointTestAuth = null;
let pendingProfileAuth = null;
let ignoreProxyErrorsUntil = 0;
let russianBypassListPromise = null;
let localBypassListPromise = null;
let proxyOperationQueue = Promise.resolve();
let pendingProxyOperations = 0;
let proxyHealthCheckQueued = false;

function withProxyOperation(callback) {
  pendingProxyOperations += 1;
  const operation = proxyOperationQueue.then(callback);
  proxyOperationQueue = operation.catch(() => undefined);
  return operation.finally(() => {
    pendingProxyOperations = Math.max(0, pendingProxyOperations - 1);
  });
}

async function fetchPackagedJson(path) {
  const response = await fetch(chrome.runtime.getURL(path), { cache: 'no-store' });
  if (!response.ok) {
    throw new Error(`Не удалось загрузить ${path} (HTTP ${response.status}).`);
  }
  return response.json();
}

async function getRussianBypassList() {
  if (!russianBypassListPromise) {
    russianBypassListPromise = fetchPackagedJson('rules/ru.json')
      .then((rules) => [...new Set((Array.isArray(rules) ? rules : [])
        .map((rule) => rule?.condition?.urlFilter)
        .filter((filter) => typeof filter === 'string')
        .map((filter) => filter.match(/^\|\|([^|^]+)\^$/)?.[1])
        .filter(Boolean)
        .flatMap((domain) => [domain, `*.${domain}`]))]);
  }
  try {
    return await russianBypassListPromise;
  } catch (error) {
    russianBypassListPromise = null;
    throw error;
  }
}

async function getLocalBypassList() {
  if (!localBypassListPromise) {
    localBypassListPromise = fetchPackagedJson('rules/local.json')
      .then((rules) => [...new Set((Array.isArray(rules) ? rules : [])
        .filter((entry) => typeof entry === 'string' && entry.trim())
        .map((entry) => entry.trim()))]);
  }
  try {
    return await localBypassListPromise;
  } catch (error) {
    localBypassListPromise = null;
    throw error;
  }
}

async function profileWithResolvedRoutingLists(profile) {
  if (!profile) {
    return profile;
  }
  const selectedOnly = profile.routingMode === 'selected';
  const [resolvedBypassList, proxyList] = await Promise.all([
    selectedOnly ? [] : resolveGeositeDomainList(profile.bypassList ?? []),
    resolveGeositeDomainList(profile.proxyList ?? []),
  ]);
  const bypassList = [...resolvedBypassList];
  if (profile.bypassRussianResources) {
    bypassList.push(...await getRussianBypassList());
  }
  if (profile.bypassLocalNetworks) {
    bypassList.push(...await getLocalBypassList());
  }
  return {
    ...profile,
    bypassList: [...new Set(bypassList)],
    proxyList: [...new Set(proxyList)],
  };
}

async function syncContentBlockingRules(profileOverride = undefined, profileEnabledOverride = null) {
  const activeProfileId = await getActiveProfileId();
  const activeProfile = profileOverride === undefined
    ? (activeProfileId ? await getProfile(activeProfileId) : null)
    : profileOverride;
  const settings = await getContentBlockingSettings();
  const profileEnabled = profileEnabledOverride ?? await getEnabled();
  const enabledRulesets = await chrome.declarativeNetRequest.getEnabledRulesets();
  const desiredRulesets = Object.entries(STATIC_RULESET_IDS)
    .filter(([setting]) => settings[setting])
    .flatMap(([, rulesetIds]) => rulesetIds);
  const desiredSet = new Set(desiredRulesets);
  const enableRulesetIds = desiredRulesets.filter((id) => !enabledRulesets.includes(id));
  const disableRulesetIds = Object.values(STATIC_RULESET_IDS).flat()
    .filter((id) => enabledRulesets.includes(id) && !desiredSet.has(id));
  if (enableRulesetIds.length > 0 || disableRulesetIds.length > 0) {
    await chrome.declarativeNetRequest.updateEnabledRulesets({
      enableRulesetIds,
      disableRulesetIds,
    });
  }
  const blockList = profileEnabled && activeProfile?.routingMode !== 'selected'
    ? activeProfile?.blockList ?? []
    : [];
  return updateBlockRules(blockList);
}

function canonicalProxyHost(host) {
  return normalizeProxyHost(String(host ?? ''))
    .replace(/\.$/, '')
    .toLowerCase();
}

function proxyServersForProfile(profile, protocol = 'auto') {
  if (protocol !== 'auto') {
    const selectedServer = endpointToProxyServer(getProfileEndpoint(profile, protocol));
    if (selectedServer) {
      return [selectedServer];
    }
  }

  return getConfiguredProtocols(profile)
    .map((configuredProtocol) => endpointToProxyServer(getProfileEndpoint(profile, configuredProtocol)));
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

  const host = canonicalProxyHost(challenger.host);
  const port = Number(challenger.port);
  return servers.some((server) => (
    canonicalProxyHost(server.host) === host && Number(server.port) === port
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

function proxyGet() {
  return new Promise((resolve, reject) => {
    chrome.proxy.settings.get({}, (details) => {
      const error = chrome.runtime.lastError;
      if (error) {
        reject(new Error(error.message));
        return;
      }
      resolve({
        levelOfControl: details?.levelOfControl ?? 'not_controllable',
        value: details?.value ?? { mode: 'system' },
      });
    });
  });
}

function assertProxyControllable(proxySetting) {
  if (!CONTROLLABLE_SETTING_LEVELS.has(proxySetting?.levelOfControl)) {
    throw new Error(PROXY_CONTROL_ERROR);
  }
}

function webRtcPolicyGet() {
  return new Promise((resolve, reject) => {
    chrome.privacy.network.webRTCIPHandlingPolicy.get({}, (details) => {
      const error = chrome.runtime.lastError;
      if (error) {
        reject(new Error(error.message));
        return;
      }
      resolve(details ?? {});
    });
  });
}

function webRtcPolicySet(value) {
  return new Promise((resolve, reject) => {
    chrome.privacy.network.webRTCIPHandlingPolicy.set({ value }, () => {
      const error = chrome.runtime.lastError;
      if (error) {
        reject(new Error(error.message));
        return;
      }
      resolve();
    });
  });
}

function webRtcPolicyClear() {
  return new Promise((resolve, reject) => {
    chrome.privacy.network.webRTCIPHandlingPolicy.clear({}, () => {
      const error = chrome.runtime.lastError;
      if (error) {
        reject(new Error(error.message));
        return;
      }
      resolve();
    });
  });
}

function webRtcProtectionStatus(setting) {
  const levelOfControl = setting?.levelOfControl ?? 'not_controllable';
  const controllable = CONTROLLABLE_SETTING_LEVELS.has(levelOfControl);
  const enabled = levelOfControl === 'controlled_by_this_extension'
    && setting?.value === WEBRTC_PROTECTION_VALUE;
  return {
    enabled,
    controllable,
    message: controllable ? '' : WEBRTC_CONTROL_ERROR,
  };
}

async function getWebRtcProtectionStatus() {
  return webRtcProtectionStatus(await webRtcPolicyGet());
}

async function setWebRtcProtection(enabled) {
  const current = await webRtcPolicyGet();
  const levelOfControl = current?.levelOfControl;
  if (enabled) {
    if (!CONTROLLABLE_SETTING_LEVELS.has(levelOfControl)) {
      throw new Error(WEBRTC_CONTROL_ERROR);
    }
    await webRtcPolicySet(WEBRTC_PROTECTION_VALUE);
  } else if (levelOfControl === 'controlled_by_this_extension') {
    await webRtcPolicyClear();
  }
  return getWebRtcProtectionStatus();
}

async function restoreProxySetting(proxySetting) {
  if (proxySetting?.levelOfControl === 'controlled_by_this_extension') {
    await proxySet(proxySetting.value, 'regular');
    return;
  }
  await proxyClear('regular');
}

async function getEffectiveProxyState() {
  const state = await getProxyState();
  if (!state.enabled) {
    return { ...state, proxyControlled: true };
  }
  const proxySetting = await proxyGet();
  const proxyControlled = proxySetting.levelOfControl === 'controlled_by_this_extension';
  return {
    ...state,
    lastError: proxyControlled ? state.lastError : PROXY_CONTROL_ERROR,
    proxyControlled,
  };
}

async function applyProfile(profile, protocol = 'auto') {
  if (!PROTOCOLS.includes(protocol)) {
    throw new Error('Неизвестный протокол прокси.');
  }
  let resolvedProtocol = protocol;
  if (protocol !== 'auto') {
    const endpoint = getProfileEndpoint(profile, protocol);
    if (!endpointToProxyServer(endpoint)) resolvedProtocol = 'auto';
  }
  const resolvedProfile = await profileWithResolvedRoutingLists(profile);
  const config = buildSelectedProxyConfig(resolvedProfile, resolvedProtocol);
  if (config.mode === 'direct') {
    throw new Error('В профиле не настроен ни один прокси.');
  }
  await proxySet(config, 'regular');
  return { config, resolvedProtocol };
}

async function disableAll() {
  await proxyClear('regular');
  await setProxyState({ enabled: false, lastError: null });
  await syncContentBlockingRules(null, false);
}

async function rollbackFailedEnable() {
  const rollbackErrors = [];
  try {
    await proxyClear('regular');
  } catch (error) {
    rollbackErrors.push(error);
  }
  try {
    await setProxyState({ enabled: false, lastError: null });
  } catch (error) {
    rollbackErrors.push(error);
  }
  try {
    await syncContentBlockingRules(null, false);
  } catch (error) {
    rollbackErrors.push(error);
  }
  if (rollbackErrors.length > 0) {
    console.error('Unable to fully roll back failed proxy activation:', rollbackErrors);
  }
}

async function activateProfile(profile, profileId, protocol) {
  const previousState = await getProxyState();
  const previousProfile = previousState.activeProfileId
    ? await getProfile(previousState.activeProfileId)
    : null;
  const previousProxySetting = await proxyGet();
  assertProxyControllable(previousProxySetting);
  pendingProfileAuth = authScopeForProfile(profile, protocol);
  try {
    await syncContentBlockingRules(profile, true);
    const { resolvedProtocol } = await applyProfile(profile, protocol);
    await setProxyState({
      activeProfileId: profileId,
      enabled: true,
      lastError: null,
      selectedProtocol: resolvedProtocol,
    });
  } catch (error) {
    if (previousState.enabled
      && previousProfile
      && previousProxySetting.levelOfControl === 'controlled_by_this_extension') {
      const rollbackErrors = [];
      let proxyRestored = false;
      pendingProfileAuth = authScopeForProfile(previousProfile, previousState.selectedProtocol);
      try {
        await restoreProxySetting(previousProxySetting);
        proxyRestored = true;
      } catch (rollbackError) {
        rollbackErrors.push(rollbackError);
      }
      try {
        await syncContentBlockingRules(previousProfile, true);
      } catch (rollbackError) {
        rollbackErrors.push(rollbackError);
      }
      if (proxyRestored) {
        try {
          await setProxyState(previousState);
        } catch (rollbackError) {
          rollbackErrors.push(rollbackError);
        }
      } else {
        await rollbackFailedEnable();
      }
      if (rollbackErrors.length > 0) {
        console.error('Unable to fully restore the previous proxy profile:', rollbackErrors);
      }
    } else {
      await rollbackFailedEnable();
    }
    throw error;
  } finally {
    pendingProfileAuth = null;
  }
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
  await activateProfile(profile, activeProfileId, selectedProtocol);
  return profile;
}

async function getStatus() {
  const state = await getEffectiveProxyState();
  const { activeProfileId, enabled, lastError, selectedProtocol } = state;
  const activeProfile = activeProfileId
    ? (await getProfileSummaries()).find((profile) => profile.id === activeProfileId) ?? null
    : null;
  return {
    enabled,
    activeProfileId,
    activeProfileName: activeProfile?.name ?? null,
    lastError,
    selectedProtocol,
    routingMode: activeProfile?.routingMode ?? 'all',
    killSwitch: activeProfile?.killSwitch === true,
  };
}

async function updateActionIcon() {
  const { enabled, lastError } = await getEffectiveProxyState();
  const color = !enabled ? 'gray' : lastError ? 'red' : 'green';
  try {
    await chrome.action.setIcon({
      path: {
        16: `images/globe-${color}-16.png`,
        48: `images/globe-${color}-48.png`,
        128: `images/globe-${color}-128.png`,
      },
    });
  } catch (error) {
    console.error('Unable to update extension icon:', error);
  }
}

chrome.proxy.settings.onChange.addListener(() => {
  void updateActionIcon().catch((error) => {
    console.error('Unable to update the icon after a proxy ownership change:', error);
  });
});

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

async function fetchExternalIpWithLatency() {
  const startedAt = performance.now();
  const ip = await fetchExternalIp();
  return {
    ip,
    latencyMs: Math.max(1, Math.round(performance.now() - startedAt)),
  };
}

async function handleProxyError(details) {
  if (endpointCheckInProgress
    || proxyHealthCheckInProgress
    || Date.now() < ignoreProxyErrorsUntil
    || !await getEnabled()) {
    return;
  }

  const message = details?.error || 'Неизвестная ошибка прокси';
  const suffix = details?.details ? `: ${details.details}` : '';
  proxyHealthCheckInProgress = true;

  try {
    // One failed socket does not necessarily mean that the configured proxy
    // is unavailable. Confirm it with a separate request before showing red.
    await fetchExternalIp();
    await setLastError(null);
  } catch {
    await setLastError(`${message}${suffix}`);
  } finally {
    proxyHealthCheckInProgress = false;
    await updateActionIcon();
  }
}

chrome.proxy.onProxyError.addListener((details) => {
  if (proxyHealthCheckQueued) {
    return;
  }
  proxyHealthCheckQueued = true;
  void withProxyOperation(() => handleProxyError(details))
    .catch((error) => {
      console.error('Unable to process proxy error:', error);
    })
    .finally(() => {
      proxyHealthCheckQueued = false;
    });
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

  let previousProxySetting = null;
  let result;
  try {
    previousProxySetting = await proxyGet();
    assertProxyControllable(previousProxySetting);
    await proxySet({ mode: 'fixed_servers', rules: { singleProxy: server } }, 'regular');
    const measurement = await fetchExternalIpWithLatency();
    result = {
      ok: true,
      ip: measurement.ip,
      ping: measurement.latencyMs,
    };
  } catch (error) {
    result = { ok: false, error: errorMessage(error) };
  } finally {
    if (previousProxySetting) {
      try {
        await restoreProxySetting(previousProxySetting);
      } catch (error) {
        result = {
          ok: false,
          error: `Не удалось восстановить настройки прокси: ${errorMessage(error)}`,
        };
      }
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
    } else {
      await proxyClear('regular');
      await syncContentBlockingRules();
    }
  } catch (error) {
    try {
      await proxyClear('regular');
    } catch (proxyError) {
      console.error('Unable to reset proxy settings:', proxyError);
    }
    await setProxyState({
      enabled: false,
      lastError: errorMessage(error),
    });
    try {
      await syncContentBlockingRules(null, false);
    } catch (rulesError) {
      console.error('Unable to clear profile block rules:', rulesError);
    }
  } finally {
    await updateActionIcon();
  }
}

async function scheduleGeositeRefresh() {
  const now = new Date();
  const nextMidnight = new Date(now);
  nextMidnight.setDate(now.getDate() + 1);
  nextMidnight.setHours(0, 0, 0, 0);
  await chrome.alarms.create('geosite-daily-refresh', {
    when: nextMidnight.getTime(),
    periodInMinutes: 24 * 60,
  });
}

async function getProfileGeositeStatus(profileId) {
  const profile = profileId ? await getProfile(profileId) : null;
  if (!profile) {
    return { names: [], statuses: [] };
  }
  const names = geositeNamesFromProfiles([profile]);
  return {
    names,
    statuses: await getGeositeCacheStatus(names),
  };
}

async function refreshProfileGeosites(profileId) {
  const profile = profileId ? await getProfile(profileId) : null;
  if (!profile) {
    throw new Error('Сначала сохраните профиль.');
  }

  const names = geositeNamesFromProfiles([profile]);
  const result = await refreshGeositeCaches(names);
  const state = await getProxyState();
  if (state.enabled && state.activeProfileId === profileId && result.refreshed.length > 0) {
    await enableActiveProfile(state.selectedProtocol);
    await updateActionIcon();
  } else {
    await syncContentBlockingRules();
  }
  return {
    ...result,
    statuses: await getGeositeCacheStatus(names),
  };
}

async function handleGeositeAlarm(alarm) {
  if (alarm.name !== 'geosite-daily-refresh') {
    return;
  }

  const profiles = await getProfileSummaries();
  const result = await refreshGeositeCaches(geositeNamesFromProfiles(profiles));
  if (result.failed.length) {
    console.warn('Unable to refresh geosite bases:', result.failed);
  }
  if (result.refreshed.length && await getEnabled()) {
    try {
      await enableActiveProfile(await getSelectedProtocol());
      await updateActionIcon();
    } catch (error) {
      console.warn('Unable to reapply the active profile after geosite refresh:', error);
      await updateActionIcon();
    }
  } else {
    await syncContentBlockingRules();
  }
}

chrome.alarms.onAlarm.addListener((alarm) => {
  void withProxyOperation(() => handleGeositeAlarm(alarm)).catch((error) => {
    console.error('Unable to handle geosite refresh alarm:', error);
  });
});

async function initializeWorkerState() {
  await scheduleGeositeRefresh();
  await restoreStoredState();
}

chrome.runtime.onStartup.addListener(() => {
  void withProxyOperation(initializeWorkerState).catch((error) => {
    console.error('Unable to restore extension state on startup:', error);
  });
});

chrome.runtime.onInstalled.addListener(() => {
  void withProxyOperation(initializeWorkerState).catch((error) => {
    console.error('Unable to initialize extension state:', error);
  });
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || !message.action) {
    return undefined;
  }

  (async () => {
    if (message.action === 'enable') {
      const profile = await withProxyOperation(async () => {
        const targetProfileId = message.profileId || await getActiveProfileId();
        const selectedProfile = await getProfile(targetProfileId);
        if (!selectedProfile) throw new Error('Выбранный профиль не найден.');
        const selectedProtocol = message.protocol ?? await getSelectedProtocol();
        await activateProfile(selectedProfile, targetProfileId, selectedProtocol);
        return selectedProfile;
      });
      await updateActionIcon();
      sendResponse({ ok: true, profile });
      return;
    }

    if (message.action === 'disable') {
      await withProxyOperation(disableAll);
      await updateActionIcon();
      sendResponse({ ok: true });
      return;
    }

    if (message.action === 'applyProfile') {
      const profile = await withProxyOperation(async () => {
        if (Object.hasOwn(message, 'profileId') && !message.profileId) {
          if (await getEnabled()) await disableAll();
          await setProxyState({ activeProfileId: null, selectedProtocol: 'auto' });
          return null;
        }
        const protocol = message.protocol ?? await getSelectedProtocol();
        const enabled = await getEnabled();
        const targetProfileId = message.profileId || await getActiveProfileId();
        const selectedProfile = targetProfileId ? await getProfile(targetProfileId) : null;
        if (!selectedProfile) throw new Error('Выбранный профиль не найден.');
        if (enabled) {
          await activateProfile(selectedProfile, targetProfileId, protocol);
          return selectedProfile;
        }

        await setProxyState({
          activeProfileId: targetProfileId,
          selectedProtocol: protocol,
        });
        await syncContentBlockingRules(selectedProfile, false);
        return selectedProfile;
      });
      await updateActionIcon();
      sendResponse({ ok: true, profile });
      return;
    }

    if (message.action === 'getStatus') {
      sendResponse({ ok: true, ...await getStatus() });
      return;
    }

    if (message.action === 'getProxyGeo') {
      const profileId = message.profileId ?? await getActiveProfileId();
      const profile = profileId ? await getProfile(profileId) : null;
      if (!profile) {
        throw new Error('Выбранный профиль не найден.');
      }
      const state = await getProxyState();
      const protocol = message.protocol
        ?? (state.activeProfileId === profileId ? state.selectedProtocol : 'auto');
      sendResponse({
        ok: true,
        ...await getProfileProxyGeo(profile, protocol, message.forceRefresh === true),
      });
      return;
    }

    if (message.action === 'getWebRtcProtection') {
      sendResponse({ ok: true, ...await getWebRtcProtectionStatus() });
      return;
    }

    if (message.action === 'getGeositeStatus') {
      sendResponse({ ok: true, ...await getProfileGeositeStatus(message.profileId) });
      return;
    }

    if (message.action === 'refreshGeosite') {
      const result = await withProxyOperation(() => refreshProfileGeosites(message.profileId));
      sendResponse({ ok: true, ...result });
      return;
    }

    if (message.action === 'setWebRtcProtection') {
      sendResponse({ ok: true, ...await setWebRtcProtection(message.enabled === true) });
      return;
    }

    if (message.action === 'syncBlockRules') {
      const count = await withProxyOperation(syncContentBlockingRules);
      sendResponse({ ok: true, count });
      return;
    }

    if (message.action === 'checkProxy') {
      if (endpointCheckInProgress || pendingProxyOperations > 0) {
        sendResponse({
          ok: false,
          busy: true,
          error: 'Выполняется изменение настроек прокси.',
          tips: [],
        });
        return;
      }
      try {
        const state = await getEffectiveProxyState();
        if (state.enabled && !state.proxyControlled) {
          throw new Error(PROXY_CONTROL_ERROR);
        }
        const result = await fetchExternalIpWithLatency();
        if (await getEnabled()) {
          await setLastError(null);
        }
        await updateActionIcon();
        sendResponse({
          ok: true,
          ip: result.ip,
          ping: result.latencyMs,
          tips: [],
        });
      } catch (error) {
        const messageText = errorMessage(error);
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
      sendResponse(await withProxyOperation(() => testProxyEndpoint(message.endpoint, {
        username: message.username,
        password: message.password,
      })));
      return;
    }

    sendResponse({ ok: false, error: 'Неизвестное действие' });
  })().catch(async (error) => {
    const messageText = errorMessage(error);
    try {
      await updateActionIcon();
    } catch (reportError) {
      console.error('Unable to refresh the action icon after a command error:', reportError);
    }
    sendResponse({ ok: false, error: messageText });
  });

  return true;
});
