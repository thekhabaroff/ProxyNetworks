import {
  getLastError,
  getProfiles,
  getActiveProfileId,
  setActiveProfileId,
} from './storage.js';

const enabledToggle = document.getElementById('enabledToggle');
const profileSelect = document.getElementById('profileSelect');
const statusLine = document.getElementById('statusLine');
const ipLine = document.getElementById('ipLine');
const errorBanner = document.getElementById('errorBanner');
const toggleLabel = document.getElementById('toggleLabel');
const refreshIpButton = document.getElementById('refreshIpButton');
const settingsButton = document.getElementById('settingsButton');

let profilesCache = [];
let currentEnabled = false;
let currentActiveProfileId = null;

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

async function loadStatus() {
  const response = await sendMessage({ action: 'getStatus' });
  currentEnabled = Boolean(response?.enabled);
  currentActiveProfileId = response?.activeProfileId ?? null;
  enabledToggle.checked = currentEnabled;
  toggleLabel.textContent = currentEnabled ? 'Прокси включён' : 'Прокси выключен';
  statusLine.textContent = currentEnabled
    ? `Активен: ${response?.activeProfileName ?? 'без названия'}`
    : 'Прокси выключен';

  const lastError = response?.lastError ?? (await getLastError());
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
  emptyOption.textContent = '— выберите профиль —';
  profileSelect.append(emptyOption);

  for (const profile of profilesCache) {
    const option = document.createElement('option');
    option.value = profile.id;
    option.textContent = profile.name || profile.id;
    profileSelect.append(option);
  }

  profileSelect.value = currentActiveProfileId ?? '';
}

async function loadProfiles() {
  profilesCache = await getProfiles();
  currentActiveProfileId = await getActiveProfileId();
  renderProfiles();
}

async function refreshIp() {
  ipLine.textContent = 'Текущий IP: ...';
  try {
    const response = await fetch('https://api.ipify.org?format=json', { cache: 'no-store' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const data = await response.json();
    ipLine.textContent = `Текущий IP: ${data.ip ?? 'неизвестен'}`;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    ipLine.textContent = `Текущий IP: ошибка (${message})`;
  }
}

async function updateFromBackground() {
  await loadProfiles();
  await loadStatus();
  await refreshIp();
}

enabledToggle.addEventListener('change', async () => {
  if (enabledToggle.checked) {
    const selectedProfileId = profileSelect.value;
    if (!selectedProfileId) {
      enabledToggle.checked = false;
      toggleLabel.textContent = 'Прокси выключен';
      statusLine.textContent = 'Выберите профиль';
      return;
    }

    await setActiveProfileId(selectedProfileId);
    await sendMessage({ action: 'enable', profileId: selectedProfileId });
  } else {
    await sendMessage({ action: 'disable' });
  }

  await updateFromBackground();
});

profileSelect.addEventListener('change', async () => {
  const selectedProfileId = profileSelect.value || null;
  await setActiveProfileId(selectedProfileId);
  if (currentEnabled && selectedProfileId) {
    await sendMessage({ action: 'applyProfile', profileId: selectedProfileId });
  }
  await loadStatus();
});

refreshIpButton.addEventListener('click', refreshIp);

settingsButton.addEventListener('click', () => {
  chrome.runtime.openOptionsPage();
});

await updateFromBackground();
