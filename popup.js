import {
  getProfiles,
  getActiveProfileId,
} from './storage.js';

const enabledToggle = document.getElementById('enabledToggle');
const profileSelect = document.getElementById('profileSelect');
const protocolSelect = document.getElementById('protocolSelect');
const protocolField = document.getElementById('protocolField');
const statusLine = document.getElementById('statusLine');
const ipLine = document.getElementById('ipLine');
const errorBanner = document.getElementById('errorBanner');
const toggleLabel = document.getElementById('toggleLabel');
const refreshIpButton = document.getElementById('refreshIpButton');
const settingsButton = document.getElementById('settingsButton');
const tipsList = document.getElementById('tipsList');

let profilesCache = [];
let currentEnabled = false;
let currentActiveProfileId = null;
let currentProtocol = 'auto';

function sendMessage(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      const error = chrome.runtime.lastError;
      if (error) {
        reject(new Error(error.message));
        return;
      }
      resolve(response);
    });
  });
}

async function sendCommand(message) {
  const response = await sendMessage(message);
  if (!response?.ok) {
    throw new Error(response?.error || 'Команда расширения завершилась с ошибкой.');
  }
  return response;
}

async function loadStatus() {
  const response = await sendMessage({ action: 'getStatus' });
  currentEnabled = Boolean(response?.enabled);
  currentActiveProfileId = response?.activeProfileId ?? null;
  currentProtocol = response?.selectedProtocol ?? 'auto';
  enabledToggle.checked = currentEnabled;
  protocolField.classList.toggle('hidden', !currentActiveProfileId);
  toggleLabel.textContent = currentEnabled ? 'Прокси включён' : 'Прокси выключен';
  statusLine.textContent = currentEnabled ? `Активен: ${response?.activeProfileName ?? 'без названия'}` : '';
  statusLine.classList.toggle('hidden', !currentEnabled);

  protocolSelect.value = currentProtocol;
  if (updateProtocolOptions()) {
    currentProtocol = 'auto';
    await sendCommand({
      action: 'applyProfile',
      profileId: currentActiveProfileId,
      protocol: 'auto',
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
}

function renderProfiles() {
  profileSelect.innerHTML = '';

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
}

function updateProtocolOptions() {
  const activeProfile = profilesCache.find((profile) => profile.id === currentActiveProfileId);
  const availableProtocols = [
    ['http', activeProfile?.proxyForHttp],
    ['https', activeProfile?.proxyForHttps],
    ['socks', activeProfile?.socks],
  ].filter(([, endpoint]) => endpoint?.host && endpoint?.port)
    .map(([protocol]) => protocol);

  [...protocolSelect.options].forEach((option) => {
    option.hidden = option.value !== 'auto' && !availableProtocols.includes(option.value);
  });
  if (protocolSelect.value !== 'auto' && protocolSelect.selectedOptions[0]?.hidden) {
    protocolSelect.value = 'auto';
    return true;
  }
  return false;
}

async function loadProfiles() {
  profilesCache = await getProfiles();
  currentActiveProfileId = await getActiveProfileId();
  renderProfiles();
  updateProtocolOptions();
}

function showPopupError(message) {
  errorBanner.textContent = message ? `Предупреждение: ${message}` : '';
  errorBanner.classList.toggle('hidden', !message);
}

async function refreshIp() {
  if (refreshIpButton.disabled) return;
  refreshIpButton.disabled = true;
  ipLine.textContent = 'Текущий IP: ...';
  tipsList.innerHTML = '';
  tipsList.classList.add('hidden');
  try {
    const response = await sendMessage({ action: 'checkProxy' });
    if (!response?.ok) {
      if (response?.busy) {
        ipLine.textContent = 'Текущий IP: выполняется проверка прокси';
        return;
      }
      ipLine.textContent = `Текущий IP: ошибка (${response?.error ?? 'Не удалось проверить IP'})`;
      if (currentEnabled) showPopupError(response?.error ?? 'Не удалось проверить IP');
      renderTips(response?.tips);
      return;
    }
    ipLine.textContent = `Текущий IP: ${response.ip ?? 'неизвестен'}`;
    showPopupError('');
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    ipLine.textContent = `Текущий IP: ошибка (${message})`;
    if (currentEnabled) showPopupError(message);
    renderTips();
  } finally {
    refreshIpButton.disabled = false;
  }
}

function renderTips(items = [
  'Проверьте хост и порт прокси.',
  'Проверьте логин и пароль, если прокси требует авторизацию.',
  'Откройте chrome://net-internals/#proxy для диагностики Chrome.',
]) {
  const tips = Array.isArray(items) ? items : [];
  tipsList.innerHTML = '';
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

enabledToggle.addEventListener('change', async () => {
  enabledToggle.disabled = true;
  try {
    if (enabledToggle.checked) {
      const selectedProfileId = profileSelect.value;
      if (!selectedProfileId) {
        throw new Error('Сначала выберите профиль.');
      }

      await sendCommand({
        action: 'enable',
        profileId: selectedProfileId,
        protocol: protocolSelect.value,
      });
    } else {
      await sendCommand({ action: 'disable' });
    }
    await updateFromBackground();
  } catch (error) {
    await loadStatus();
    showPopupError(error instanceof Error ? error.message : String(error));
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
      await sendCommand({ action: 'applyProfile', profileId: null, protocol: 'auto' });
    } else {
      updateProtocolOptions();
      await sendCommand({
        action: 'applyProfile',
        profileId: selectedProfileId,
        protocol: protocolSelect.value,
      });
    }
    await loadProfiles();
    await loadStatus();
  } catch (error) {
    await loadProfiles();
    await loadStatus();
    showPopupError(error instanceof Error ? error.message : String(error));
  } finally {
    profileSelect.disabled = false;
  }
});

protocolSelect.addEventListener('change', async () => {
  protocolSelect.disabled = true;
  try {
    if (currentActiveProfileId) {
      await sendCommand({ action: 'applyProfile', profileId: currentActiveProfileId, protocol: protocolSelect.value });
      await loadStatus();
    }
  } catch (error) {
    await loadStatus();
    showPopupError(error instanceof Error ? error.message : String(error));
  } finally {
    protocolSelect.disabled = false;
  }
});

refreshIpButton.addEventListener('click', refreshIp);

settingsButton.addEventListener('click', async () => {
  try {
    await chrome.runtime.openOptionsPage();
  } catch (error) {
    showPopupError(error instanceof Error ? error.message : String(error));
  }
});

try {
  await updateFromBackground();
} catch (error) {
  showPopupError(error instanceof Error ? error.message : String(error));
}
