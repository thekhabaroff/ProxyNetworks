import {
  deleteProfile,
  getActiveProfileId,
  getEnabled,
  getProfiles,
  saveProfile,
  setActiveProfileId,
} from './storage.js';

const profilesList = document.getElementById('profilesList');
const newProfileButton = document.getElementById('newProfileButton');
const formTitle = document.getElementById('formTitle');
const profileForm = document.getElementById('profileForm');
const profileIdInput = document.getElementById('profileId');
const nameInput = document.getElementById('name');
const modeInput = document.getElementById('mode');
const schemeInput = document.getElementById('scheme');
const hostInput = document.getElementById('host');
const portInput = document.getElementById('port');
const useAdvancedInput = document.getElementById('useAdvanced');
const httpSchemeInput = document.getElementById('httpScheme');
const httpHostInput = document.getElementById('httpHost');
const httpPortInput = document.getElementById('httpPort');
const httpsSchemeInput = document.getElementById('httpsScheme');
const httpsHostInput = document.getElementById('httpsHost');
const httpsPortInput = document.getElementById('httpsPort');
const socksSchemeInput = document.getElementById('socksScheme');
const socksHostInput = document.getElementById('socksHost');
const socksPortInput = document.getElementById('socksPort');
const bypassListInput = document.getElementById('bypassList');
const pacScriptInput = document.getElementById('pacScript');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const incognitoInput = document.getElementById('incognito');
const fixedServersSection = document.getElementById('fixedServersSection');
const advancedSection = document.getElementById('advancedSection');
const pacSection = document.getElementById('pacSection');
const formError = document.getElementById('formError');
const deleteButton = document.getElementById('deleteButton');
const activateButton = document.getElementById('activateButton');

let profiles = [];
let selectedProfileId = null;

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

function showError(message) {
  if (!message) {
    formError.classList.add('hidden');
    formError.textContent = '';
    return;
  }

  formError.textContent = message;
  formError.classList.remove('hidden');
}

function parseBypassList(text) {
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
}

function formatBypassList(items) {
  return Array.isArray(items) ? items.join('\n') : '';
}

function endpointFromInputs(schemeInputEl, hostInputEl, portInputEl) {
  const host = hostInputEl.value.trim();
  const port = Number(portInputEl.value);
  if (!host && !portInputEl.value.trim()) {
    return null;
  }
  return {
    scheme: schemeInputEl.value,
    host,
    port,
  };
}

function setFieldVisibility() {
  const mode = modeInput.value;
  const isFixed = mode === 'fixed_servers';
  const isPac = mode === 'pac_script';
  fixedServersSection.classList.toggle('hidden', !isFixed);
  pacSection.classList.toggle('hidden', !isPac);
  advancedSection.classList.toggle('hidden', !useAdvancedInput.checked || !isFixed);
}

function renderProfileList() {
  profilesList.innerHTML = '';

  for (const profile of profiles) {
    const item = document.createElement('button');
    item.type = 'button';
    item.className = `profile-item${profile.id === selectedProfileId ? ' active' : ''}`;
    item.textContent = profile.name || profile.id;
    item.addEventListener('click', () => {
      loadProfile(profile.id);
    });
    profilesList.append(item);
  }
}

function fillForm(profile) {
  profileIdInput.value = profile?.id ?? '';
  nameInput.value = profile?.name ?? '';
  modeInput.value = profile?.mode ?? 'direct';
  schemeInput.value = profile?.scheme ?? 'http';
  hostInput.value = profile?.host ?? '';
  portInput.value = profile?.port ? String(profile.port) : '';
  useAdvancedInput.checked = Boolean(profile?.useAdvanced);
  httpSchemeInput.value = profile?.proxyForHttp?.scheme ?? 'http';
  httpHostInput.value = profile?.proxyForHttp?.host ?? '';
  httpPortInput.value = profile?.proxyForHttp?.port ? String(profile.proxyForHttp.port) : '';
  httpsSchemeInput.value = profile?.proxyForHttps?.scheme ?? 'https';
  httpsHostInput.value = profile?.proxyForHttps?.host ?? '';
  httpsPortInput.value = profile?.proxyForHttps?.port ? String(profile.proxyForHttps.port) : '';
  socksSchemeInput.value = profile?.socks?.scheme ?? 'socks5';
  socksHostInput.value = profile?.socks?.host ?? '';
  socksPortInput.value = profile?.socks?.port ? String(profile.socks.port) : '';
  bypassListInput.value = formatBypassList(profile?.bypassList ?? []);
  pacScriptInput.value = profile?.pacScript ?? '';
  usernameInput.value = profile?.username ?? '';
  passwordInput.value = profile?.password ?? '';
  incognitoInput.checked = Boolean(profile?.incognito);
  formTitle.textContent = profile?.id ? `Профиль: ${profile.name || profile.id}` : 'Новый профиль';
  setFieldVisibility();
  deleteButton.disabled = !profile?.id;
  activateButton.disabled = !profile?.id;
}

async function loadProfile(id) {
  const profile = profiles.find((item) => item.id === id) ?? null;
  selectedProfileId = id;
  renderProfileList();
  fillForm(profile);
  showError('');
}

async function loadProfiles() {
  profiles = await getProfiles();
  const activeProfileId = await getActiveProfileId();
  selectedProfileId = selectedProfileId && profiles.some((item) => item.id === selectedProfileId)
    ? selectedProfileId
    : activeProfileId ?? profiles[0]?.id ?? null;
  renderProfileList();
  fillForm(profiles.find((item) => item.id === selectedProfileId) ?? null);
}

function validateProfile(data) {
  if (!data.name.trim()) {
    return 'Введите название профиля.';
  }

  if (data.mode === 'fixed_servers' && !data.useAdvanced) {
    if (!data.host.trim()) {
      return 'Укажите хост прокси.';
    }
    if (!data.port || data.port < 1 || data.port > 65535) {
      return 'Порт должен быть числом от 1 до 65535.';
    }
  }

  if (data.mode === 'pac_script' && !data.pacScript.trim()) {
    return 'Укажите PAC-скрипт.';
  }

  const endpoints = [data.proxyForHttp, data.proxyForHttps, data.socks].filter(Boolean);
  for (const endpoint of endpoints) {
    if (!endpoint.host.trim()) {
      return 'Укажите хост для всех заполненных прокси-эндпоинтов.';
    }
    if (!endpoint.port || endpoint.port < 1 || endpoint.port > 65535) {
      return 'Порт должен быть числом от 1 до 65535.';
    }
  }

  return '';
}

function collectProfile() {
  const useAdvanced = useAdvancedInput.checked;
  const profile = {
    id: profileIdInput.value || undefined,
    name: nameInput.value.trim(),
    mode: modeInput.value,
    scheme: schemeInput.value,
    host: hostInput.value.trim(),
    port: Number(portInput.value),
    useAdvanced,
    proxyForHttp: useAdvanced ? endpointFromInputs(httpSchemeInput, httpHostInput, httpPortInput) : null,
    proxyForHttps: useAdvanced ? endpointFromInputs(httpsSchemeInput, httpsHostInput, httpsPortInput) : null,
    socks: useAdvanced ? endpointFromInputs(socksSchemeInput, socksHostInput, socksPortInput) : null,
    bypassList: parseBypassList(bypassListInput.value),
    pacScript: pacScriptInput.value,
    username: usernameInput.value.trim(),
    password: passwordInput.value,
    incognito: incognitoInput.checked,
  };

  if (Number.isNaN(profile.port)) {
    profile.port = 0;
  }
  return profile;
}

async function refreshAfterSave(savedProfile) {
  await loadProfiles();
  await loadProfile(savedProfile.id);
  const enabled = await getEnabled();
  if (enabled && savedProfile.id === (await getActiveProfileId())) {
    await sendMessage({ action: 'applyProfile', profileId: savedProfile.id });
  }
}

profileForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const profile = collectProfile();
  const validationError = validateProfile(profile);
  if (validationError) {
    showError(validationError);
    return;
  }

  showError('');
  const savedProfile = await saveProfile(profile);
  await refreshAfterSave(savedProfile);
});

newProfileButton.addEventListener('click', () => {
  selectedProfileId = null;
  renderProfileList();
  fillForm(null);
  showError('');
});

deleteButton.addEventListener('click', async () => {
  const id = profileIdInput.value;
  if (!id) {
    return;
  }

  await deleteProfile(id);
  await loadProfiles();
});

activateButton.addEventListener('click', async () => {
  const id = profileIdInput.value;
  if (!id) {
    return;
  }

  await setActiveProfileId(id);
  await sendMessage({ action: 'applyProfile', profileId: id });
  await loadProfiles();
});

modeInput.addEventListener('change', setFieldVisibility);
useAdvancedInput.addEventListener('change', setFieldVisibility);

await loadProfiles();
