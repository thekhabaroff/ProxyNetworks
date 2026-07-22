import {
  getContentBlockingSettings,
  getProfileSummaries,
  setContentBlockingSettings,
} from './storage.js';
import {
  errorMessage,
  sendRuntimeCommand,
  sendRuntimeMessage,
} from './utils.js';
import { getConfiguredProtocols } from './config.js';

const enabledToggle = document.getElementById('enabledToggle');
const profileSelect = document.getElementById('profileSelect');
const protocolSelect = document.getElementById('protocolSelect');
const protocolField = document.getElementById('protocolField');
const proxyGeoInfo = document.getElementById('proxyGeoInfo');
const proxyGeoLocation = document.getElementById('proxyGeoLocation');
const proxyGeoProviderRow = document.getElementById('proxyGeoProviderRow');
const proxyGeoProvider = document.getElementById('proxyGeoProvider');
const ipLine = document.getElementById('ipLine');
const pingLine = document.getElementById('pingLine');
const pingValue = document.getElementById('pingValue');
const errorBanner = document.getElementById('errorBanner');
const toggleLabel = document.getElementById('toggleLabel');
const connectionHint = document.getElementById('connectionHint');
const refreshIpButton = document.getElementById('refreshIpButton');
const settingsButton = document.getElementById('settingsButton');
const versionBadge = document.getElementById('versionBadge');
const tipsList = document.getElementById('tipsList');
const webRtcProtectionInput = document.getElementById('webRtcProtection');
const webRtcInfoButton = document.getElementById('webRtcInfoButton');
const webRtcInfoTip = document.getElementById('webRtcInfoTip');
const blockTrackingInput = document.getElementById('blockTracking');
const blockTrackingInfoButton = document.getElementById('blockTrackingInfoButton');
const blockTrackingInfoTip = document.getElementById('blockTrackingInfoTip');
const webRtcProtectionStatus = document.getElementById('webRtcProtectionStatus');

let profilesCache = [];
let currentEnabled = false;
let currentActiveProfileId = null;
let currentProtocol = 'auto';
let refreshInProgress = false;
let refreshTimerId = null;
let webRtcProtectionState = null;
let proxyGeoRequestId = 0;
const LIVE_REFRESH_INTERVAL_MS = 3000;
const WEB_RTC_INFO_DEFAULT = 'Снижает риск раскрытия реального IP через WebRTC. Может повлиять на звонки и P2P-соединения.';
const infoControls = [
  { button: webRtcInfoButton, tooltip: webRtcInfoTip },
  { button: blockTrackingInfoButton, tooltip: blockTrackingInfoTip },
];

versionBadge.textContent = `v${chrome.runtime.getManifest().version}`;

async function loadStatus() {
  const [blockingSettings, response, webRtcStatus] = await Promise.all([
    getContentBlockingSettings(),
    sendRuntimeCommand({ action: 'getStatus' }),
    sendRuntimeCommand({ action: 'getWebRtcProtection' }),
  ]);
  blockTrackingInput.checked = blockingSettings.tracking;
  renderWebRtcProtection(webRtcStatus);
  currentEnabled = Boolean(response?.enabled);
  currentActiveProfileId = response?.activeProfileId ?? null;
  currentProtocol = response?.selectedProtocol ?? 'auto';
  renderProfiles();
  enabledToggle.checked = currentEnabled;
  pingLine.classList.toggle('hidden', !currentEnabled);
  protocolField.classList.toggle('hidden', !currentActiveProfileId);
  toggleLabel.textContent = currentEnabled ? 'Прокси включён' : 'Прокси выключен';
  connectionHint.textContent = currentEnabled
    ? response?.routingMode === 'selected'
      ? `Выборочно${response?.killSwitch ? ' · Kill Switch' : ''}`
      : `Весь трафик${response?.killSwitch ? ' · Kill Switch' : ''}`
    : 'Подключение без прокси';
  protocolSelect.value = currentProtocol;
  if (updateProtocolOptions()) {
    currentProtocol = protocolSelect.value;
    await sendRuntimeCommand({
      action: 'applyProfile',
      profileId: currentActiveProfileId,
      protocol: currentProtocol,
    });
  }

  const lastError = currentEnabled ? response?.lastError : null;
  if (lastError) {
    errorBanner.textContent = `Предупреждение: ${lastError}`;
    errorBanner.classList.remove('hidden');
  } else {
    errorBanner.textContent = '';
    errorBanner.classList.add('hidden');
  }
  void loadProxyGeo();
}

function renderProxyGeo(result) {
  if (!result?.endpoint) {
    proxyGeoInfo.classList.add('hidden');
    return;
  }

  proxyGeoInfo.classList.remove('hidden');
  if (result.geo) {
    const city = result.geo.city && result.geo.city !== 'Город не указан'
      ? ` · ${result.geo.city}`
      : '';
    proxyGeoLocation.textContent = `${result.geo.flag ?? '🌐'} ${result.geo.country ?? 'Страна не указана'}${city}`;
    proxyGeoProvider.textContent = result.geo.provider ?? 'Не указан';
    proxyGeoProviderRow.classList.remove('hidden');
    return;
  }

  proxyGeoLocation.textContent = result.error || 'Не удалось определить локацию прокси.';
  proxyGeoProvider.textContent = '';
  proxyGeoProviderRow.classList.add('hidden');
}

async function loadProxyGeo() {
  const profileId = currentActiveProfileId;
  const requestId = ++proxyGeoRequestId;
  if (!profileId) {
    proxyGeoInfo.classList.add('hidden');
    return;
  }

  proxyGeoInfo.classList.remove('hidden');
  proxyGeoLocation.textContent = 'Прокси: определяю локацию…';
  proxyGeoProvider.textContent = '';
  proxyGeoProviderRow.classList.add('hidden');
  try {
    const response = await sendRuntimeMessage({
      action: 'getProxyGeo',
      profileId,
      protocol: currentProtocol,
    });
    if (requestId !== proxyGeoRequestId || profileId !== currentActiveProfileId) return;
    if (!response?.ok) {
      throw new Error(response?.error || 'Не удалось определить локацию прокси.');
    }
    renderProxyGeo(response);
  } catch (error) {
    if (requestId !== proxyGeoRequestId || profileId !== currentActiveProfileId) return;
    renderProxyGeo({ error: errorMessage(error) });
  }
}

function renderWebRtcProtection(status) {
  webRtcProtectionState = status ?? null;
  webRtcProtectionInput.checked = Boolean(status?.enabled);
  webRtcProtectionInput.disabled = !status?.controllable;
  webRtcInfoTip.textContent = status?.message || WEB_RTC_INFO_DEFAULT;
  const statusText = status?.enabled
    ? 'WebRTC: защита активна'
    : status?.controllable
      ? 'WebRTC: защита выключена'
      : 'WebRTC: защита недоступна';
  webRtcProtectionStatus.textContent = statusText;
  webRtcProtectionStatus.classList.toggle('active', Boolean(status?.enabled));
  webRtcProtectionStatus.classList.toggle('unavailable', !status?.controllable);
}

function closeInfoTooltips(exceptButton = null) {
  for (const { button, tooltip } of infoControls) {
    if (button === exceptButton) continue;
    tooltip.classList.add('hidden');
    button.setAttribute('aria-expanded', 'false');
  }
}

function toggleInfoTooltip(button, tooltip) {
  const shouldOpen = tooltip.classList.contains('hidden');
  closeInfoTooltips();
  tooltip.classList.toggle('hidden', !shouldOpen);
  button.setAttribute('aria-expanded', String(shouldOpen));
}

async function saveWebRtcProtection() {
  const requestedEnabled = webRtcProtectionInput.checked;
  webRtcProtectionInput.disabled = true;
  try {
    const response = await sendRuntimeCommand({
      action: 'setWebRtcProtection',
      enabled: requestedEnabled,
    });
    renderWebRtcProtection(response);
    showPopupError('');
  } catch (error) {
    renderWebRtcProtection(webRtcProtectionState);
    showPopupError(errorMessage(error));
  }
}

async function saveContentBlockingSettings() {
  blockTrackingInput.disabled = true;
  let previousSettings = { tracking: !blockTrackingInput.checked };
  try {
    previousSettings = await getContentBlockingSettings();
    await setContentBlockingSettings({
      tracking: blockTrackingInput.checked,
    });
    await sendRuntimeCommand({ action: 'syncBlockRules' });
    showPopupError('');
  } catch (error) {
    blockTrackingInput.checked = previousSettings.tracking;
    try {
      await setContentBlockingSettings(previousSettings);
      await sendRuntimeCommand({ action: 'syncBlockRules' });
    } catch (rollbackError) {
      console.error('Unable to roll back content blocking settings:', rollbackError);
    }
    showPopupError(errorMessage(error));
  } finally {
    blockTrackingInput.disabled = false;
  }
}

function renderProfiles() {
  profileSelect.replaceChildren();

  const emptyOption = document.createElement('option');
  emptyOption.value = '';
  emptyOption.textContent = 'Без прокси';
  profileSelect.append(emptyOption);

  for (const profile of profilesCache) {
    const option = document.createElement('option');
    option.value = profile.id;
    option.textContent = profile.name || profile.id;
    profileSelect.append(option);
  }

  profileSelect.value = currentActiveProfileId ?? '';
  updateProfileSelectState();
}

function updateProfileSelectState() {
  const isLocked = profilesCache.length === 1 && currentActiveProfileId === profilesCache[0]?.id;
  profileSelect.disabled = isLocked;
  profileSelect.classList.toggle('select-locked', isLocked);
}

function updateProtocolOptions() {
  const activeProfile = profilesCache.find((profile) => profile.id === currentActiveProfileId);
  const availableProtocols = getConfiguredProtocols(activeProfile);
  const showAutoOption = availableProtocols.length !== 1;
  const allowedProtocols = showAutoOption
    ? ['auto', ...availableProtocols]
    : availableProtocols;

  [...protocolSelect.options].forEach((option) => {
    option.hidden = !allowedProtocols.includes(option.value);
  });
  if (!allowedProtocols.includes(protocolSelect.value)) {
    protocolSelect.value = allowedProtocols[0] ?? 'auto';
    updateProtocolSelectState(availableProtocols);
    return true;
  }
  updateProtocolSelectState(availableProtocols);
  return false;
}

function updateProtocolSelectState(availableProtocols) {
  const isLocked = Boolean(currentActiveProfileId) && availableProtocols.length <= 1;
  protocolSelect.disabled = isLocked;
  protocolSelect.classList.toggle('select-locked', isLocked);
}

async function loadProfiles() {
  profilesCache = await getProfileSummaries();
  renderProfiles();
  updateProtocolOptions();
}

function showPopupError(message) {
  errorBanner.textContent = message ? `Предупреждение: ${message}` : '';
  errorBanner.classList.toggle('hidden', !message);
}

function updateLiveText(element, text, animate = true) {
  if (element.textContent === text) {
    return;
  }
  element.textContent = text;
  if (animate && typeof element.animate === 'function') {
    element.animate([
      { opacity: 0.62, transform: 'translateY(1px)' },
      { opacity: 1, transform: 'translateY(0)' },
    ], {
      duration: 260,
      easing: 'ease-out',
    });
  }
}

async function refreshIp() {
  if (refreshInProgress) return;
  refreshInProgress = true;
  try {
    const response = await sendRuntimeMessage({ action: 'checkProxy' });
    if (!response?.ok) {
      if (response?.busy) {
        updateLiveText(ipLine, 'Выполняется проверка…');
        return;
      }
      updateLiveText(ipLine, `Ошибка: ${response?.error ?? 'Не удалось проверить IP'}`);
      updateLiveText(pingValue, '—', false);
      if (currentEnabled) showPopupError(response?.error ?? 'Не удалось проверить IP');
      renderTips(response?.tips);
      return;
    }
    updateLiveText(ipLine, response.ip ?? 'Неизвестен');
    updateLiveText(pingValue, currentEnabled && Number.isFinite(response.ping)
      ? `${response.ping} мс`
      : '—', false);
    showPopupError('');
    renderTips([]);
  } catch (error) {
    const message = errorMessage(error);
    updateLiveText(ipLine, `Ошибка: ${message}`);
    updateLiveText(pingValue, '—', false);
    if (currentEnabled) showPopupError(message);
    renderTips();
  } finally {
    refreshInProgress = false;
  }
}

function renderTips(items = [
  'Проверьте хост и порт прокси.',
  'Проверьте логин и пароль, если прокси требует авторизацию.',
  'Откройте chrome://net-internals/#proxy для диагностики Chrome.',
]) {
  const tips = Array.isArray(items) ? items : [];
  tipsList.replaceChildren();
  for (const tip of tips) {
    const item = document.createElement('li');
    item.textContent = tip;
    tipsList.append(item);
  }
  tipsList.classList.toggle('hidden', tips.length === 0);
}

async function updateFromBackground() {
  await loadProfiles();
  await loadStatus();
  await refreshIp();
}

async function restoreUiAfterError(error, reloadProfiles = false) {
  try {
    if (reloadProfiles) {
      await loadProfiles();
    }
    await loadStatus();
  } catch (reloadError) {
    console.error('Unable to restore popup state:', reloadError);
  }
  showPopupError(errorMessage(error));
}

enabledToggle.addEventListener('change', async () => {
  enabledToggle.disabled = true;
  try {
    if (enabledToggle.checked) {
      const selectedProfileId = profileSelect.value;
      if (!selectedProfileId) {
        throw new Error('Сначала выберите профиль.');
      }

      await sendRuntimeCommand({
        action: 'enable',
        profileId: selectedProfileId,
        protocol: protocolSelect.value,
      });
    } else {
      await sendRuntimeCommand({ action: 'disable' });
    }
    await updateFromBackground();
  } catch (error) {
    await restoreUiAfterError(error);
  } finally {
    enabledToggle.disabled = false;
  }
});

profileSelect.addEventListener('change', async () => {
  profileSelect.disabled = true;
  try {
    const selectedProfileId = profileSelect.value || null;
    currentActiveProfileId = selectedProfileId;
    if (!selectedProfileId) {
      await sendRuntimeCommand({ action: 'applyProfile', profileId: null, protocol: 'auto' });
    } else {
      updateProtocolOptions();
      await sendRuntimeCommand({
        action: 'applyProfile',
        profileId: selectedProfileId,
        protocol: protocolSelect.value,
      });
    }
    await loadProfiles();
    await loadStatus();
    await refreshIp();
  } catch (error) {
    await restoreUiAfterError(error, true);
  } finally {
    updateProfileSelectState();
  }
});

protocolSelect.addEventListener('change', async () => {
  protocolSelect.disabled = true;
  try {
    if (currentActiveProfileId) {
      await sendRuntimeCommand({ action: 'applyProfile', profileId: currentActiveProfileId, protocol: protocolSelect.value });
      await loadStatus();
      await refreshIp();
    }
  } catch (error) {
    await restoreUiAfterError(error);
  } finally {
    updateProtocolOptions();
  }
});

refreshIpButton.addEventListener('click', refreshIp);
webRtcProtectionInput.addEventListener('change', saveWebRtcProtection);
blockTrackingInput.addEventListener('change', saveContentBlockingSettings);

for (const { button, tooltip } of infoControls) {
  button.addEventListener('click', (event) => {
    event.stopPropagation();
    toggleInfoTooltip(button, tooltip);
  });
}

document.addEventListener('click', (event) => {
  if (!event.target.closest('.content-setting')) {
    closeInfoTooltips();
  }
});

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') {
    closeInfoTooltips();
  }
});

settingsButton.addEventListener('click', async () => {
  try {
    await chrome.runtime.openOptionsPage();
  } catch (error) {
    showPopupError(errorMessage(error));
  }
});

try {
  await updateFromBackground();
} catch (error) {
  showPopupError(errorMessage(error));
}

refreshTimerId = setInterval(() => {
  void refreshIp();
}, LIVE_REFRESH_INTERVAL_MS);

window.addEventListener('pagehide', () => {
  if (refreshTimerId) {
    clearInterval(refreshTimerId);
    refreshTimerId = null;
  }
}, { once: true });
