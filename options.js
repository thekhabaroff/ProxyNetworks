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
const httpHostInput = document.getElementById('httpHost');
const httpPortInput = document.getElementById('httpPort');
const httpsHostInput = document.getElementById('httpsHost');
const httpsPortInput = document.getElementById('httpsPort');
const socksHostInput = document.getElementById('socksHost');
const socksPortInput = document.getElementById('socksPort');
const bypassListInput = document.getElementById('bypassList');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const formError = document.getElementById('formError');
const formSuccess = document.getElementById('formSuccess');
const deleteButton = document.getElementById('deleteButton');
const activateButton = document.getElementById('activateButton');
const testProfileButton = document.getElementById('testProfileButton');
const exportProfilesButton = document.getElementById('exportProfilesButton');
const importProfilesButton = document.getElementById('importProfilesButton');
const importProfilesInput = document.getElementById('importProfilesInput');
const togglePasswordButton = document.getElementById('togglePasswordButton');
const clearPasswordButton = document.getElementById('clearPasswordButton');

const FIXED_SERVERS_MODE = 'fixed_servers';
const ALLOWED_SCHEMES = ['http', 'https', 'socks4', 'socks5'];

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

function showSuccess(message) {
  if (!message) {
    formSuccess.classList.add('hidden');
    formSuccess.textContent = '';
    return;
  }

  formSuccess.textContent = message;
  formSuccess.classList.remove('hidden');
}

function parseBypassList(text) {
  return [...new Set(text
    .split(/[\n,]+/)
    .map((line) => line.trim())
    .filter(Boolean))];
}

function formatBypassList(items) {
  return Array.isArray(items) ? items.join('\n') : '';
}

function parseProxyUrl(value) {
  const trimmed = value.trim();
  if (!trimmed.includes('://')) {
    return null;
  }

  try {
    const url = new URL(trimmed);
    return {
      scheme: url.protocol.replace(':', ''),
      host: url.hostname,
      port: url.port ? Number(url.port) : 0,
    };
  } catch (error) {
    console.warn('Unable to parse proxy URL:', error);
    return null;
  }
}

function endpointFromInputs(scheme, hostInputEl, portInputEl) {
  const parsed = parseProxyUrl(hostInputEl.value);
  const host = parsed?.host ?? hostInputEl.value.trim();
  const port = parsed?.port || Number(portInputEl.value);

  if (!host && !portInputEl.value.trim()) {
    return null;
  }

  return {
    scheme,
    host,
    port,
  };
}

function endpointsFromLegacySingleProxy(profile) {
  if (profile.proxyForHttp || profile.proxyForHttps || profile.socks) {
    return {
      proxyForHttp: profile.proxyForHttp ? { ...profile.proxyForHttp, scheme: 'http' } : null,
      proxyForHttps: profile.proxyForHttps ? { ...profile.proxyForHttps, scheme: 'https' } : null,
      socks: profile.socks ? { ...profile.socks, scheme: 'socks5' } : null,
    };
  }

  const host = typeof profile.host === 'string' ? profile.host.trim() : '';
  const port = Number(profile.port);
  if (!host || !port) {
    return {
      proxyForHttp: null,
      proxyForHttps: null,
      socks: null,
    };
  }

  const scheme = ALLOWED_SCHEMES.includes(profile.scheme) ? profile.scheme : 'http';
  const endpoint = { scheme, host, port };
  if (scheme === 'socks4' || scheme === 'socks5') {
    return {
      proxyForHttp: null,
      proxyForHttps: null,
      socks: { ...endpoint, scheme: 'socks5' },
    };
  }

  return {
    proxyForHttp: endpoint,
    proxyForHttps: { ...endpoint, scheme: scheme === 'https' ? 'https' : 'http' },
    socks: null,
  };
}

function isValidHost(host) {
  return Boolean(host) && !/\s|\/|:\/\//.test(host);
}

function isValidPort(port) {
  return Number.isInteger(Number(port)) && Number(port) >= 1 && Number(port) <= 65535;
}

function profileWithoutIncognito(profile) {
  const { incognito, ...rest } = profile;
  return rest;
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
  httpHostInput.value = profile?.proxyForHttp?.host ?? '';
  httpPortInput.value = profile?.proxyForHttp?.port ? String(profile.proxyForHttp.port) : '';
  httpsHostInput.value = profile?.proxyForHttps?.host ?? '';
  httpsPortInput.value = profile?.proxyForHttps?.port ? String(profile.proxyForHttps.port) : '';
  socksHostInput.value = profile?.socks?.host ?? '';
  socksPortInput.value = profile?.socks?.port ? String(profile.socks.port) : '';
  bypassListInput.value = formatBypassList(profile?.bypassList ?? []);
  usernameInput.value = profile?.username ?? '';
  passwordInput.value = profile?.password ?? '';
  passwordInput.type = 'password';
  togglePasswordButton.textContent = 'Показать пароль';
  formTitle.textContent = profile?.id ? `Профиль: ${profile.name || profile.id}` : 'Новый профиль';
  deleteButton.disabled = !profile?.id;
  activateButton.disabled = !profile?.id;
}

async function loadProfile(id) {
  const profile = profiles.find((item) => item.id === id) ?? null;
  selectedProfileId = id;
  renderProfileList();
  fillForm(profile);
  showError('');
  showSuccess('');
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

  const endpoints = [data.proxyForHttp, data.proxyForHttps, data.socks].filter(Boolean);
  if (endpoints.length === 0) {
    return 'Заполните хотя бы один прокси-эндпоинт.';
  }

  for (const endpoint of endpoints) {
    if (!ALLOWED_SCHEMES.includes(endpoint.scheme)) {
      return 'Выбрана неизвестная схема прокси-эндпоинта.';
    }
    if (!isValidHost(endpoint.host)) {
      return 'Укажите корректный хост для всех заполненных прокси-эндпоинтов без http://, путей и пробелов.';
    }
    if (!isValidPort(endpoint.port)) {
      return 'Порт должен быть числом от 1 до 65535.';
    }
  }

  if (data.proxyForHttp && data.proxyForHttp.scheme !== 'http') {
    return 'HTTP прокси должен использовать протокол http.';
  }

  if (data.proxyForHttps && data.proxyForHttps.scheme !== 'https') {
    return 'HTTPS прокси должен использовать протокол https.';
  }

  if (data.socks && data.socks.scheme !== 'socks5') {
    return 'SOCKS прокси должен использовать только socks5.';
  }

  return '';
}

function collectProfile() {
  return {
    id: profileIdInput.value || undefined,
    name: nameInput.value.trim(),
    mode: FIXED_SERVERS_MODE,
    scheme: 'http',
    host: '',
    port: 0,
    useAdvanced: true,
    proxyForHttp: endpointFromInputs('http', httpHostInput, httpPortInput),
    proxyForHttps: endpointFromInputs('https', httpsHostInput, httpsPortInput),
    socks: endpointFromInputs('socks5', socksHostInput, socksPortInput),
    bypassList: parseBypassList(bypassListInput.value),
    pacScript: '',
    username: usernameInput.value.trim(),
    password: passwordInput.value,
  };
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
    showSuccess('');
    showError(validationError);
    return;
  }

  showError('');
  const savedProfile = await saveProfile(profile);
  await refreshAfterSave(savedProfile);
  showSuccess('Профиль сохранён.');
});

newProfileButton.addEventListener('click', () => {
  selectedProfileId = null;
  renderProfileList();
  fillForm(null);
  showError('');
  showSuccess('');
});

deleteButton.addEventListener('click', async () => {
  const id = profileIdInput.value;
  if (!id) {
    return;
  }

  if (!confirm('Удалить этот профиль?')) {
    return;
  }

  await deleteProfile(id);
  await loadProfiles();
  showSuccess('Профиль удалён.');
});

activateButton.addEventListener('click', async () => {
  const id = profileIdInput.value;
  if (!id) {
    return;
  }

  await setActiveProfileId(id);
  await sendMessage({ action: 'applyProfile', profileId: id });
  await loadProfiles();
  showSuccess('Профиль сделан активным.');
});

testProfileButton.addEventListener('click', async () => {
  showError('');
  showSuccess('Проверяю прокси...');
  const response = await sendMessage({ action: 'checkProxy' });
  if (response?.ok) {
    showSuccess(`Прокси отвечает. Текущий IP: ${response.ip ?? 'неизвестен'}.`);
    return;
  }

  showSuccess('');
  showError(`Проверка не прошла: ${response?.error ?? 'неизвестная ошибка'}`);
});

exportProfilesButton.addEventListener('click', async () => {
  const includePasswords = confirm('Экспортировать профили вместе с паролями? Нажмите “Отмена”, чтобы экспортировать без паролей.');
  const exportedProfiles = (await getProfiles()).map((profile) => profileWithoutIncognito({
    ...profile,
    mode: FIXED_SERVERS_MODE,
    useAdvanced: true,
    password: includePasswords ? profile.password : '',
  }));
  const blob = new Blob([JSON.stringify({ version: 1, profiles: exportedProfiles }, null, 2)], {
    type: 'application/json',
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'proxy-networks-profiles.json';
  link.click();
  URL.revokeObjectURL(url);
  showSuccess(includePasswords ? 'Профили экспортированы с паролями.' : 'Профили экспортированы без паролей.');
});

importProfilesButton.addEventListener('click', () => {
  importProfilesInput.click();
});

importProfilesInput.addEventListener('change', async () => {
  const file = importProfilesInput.files?.[0];
  if (!file) {
    return;
  }

  try {
    const payload = JSON.parse(await file.text());
    const importedProfiles = Array.isArray(payload?.profiles) ? payload.profiles : null;
    if (!importedProfiles) {
      throw new Error('Файл должен содержать массив profiles.');
    }

    for (const profile of importedProfiles) {
      const preparedProfile = {
        ...profile,
        ...endpointsFromLegacySingleProxy(profile),
        id: undefined,
        name: profile.name ? `${profile.name} (import)` : 'Imported profile',
        mode: FIXED_SERVERS_MODE,
        useAdvanced: true,
      };
      const validationError = validateProfile(preparedProfile);
      if (validationError) {
        throw new Error(validationError);
      }
      await saveProfile(preparedProfile);
    }

    await loadProfiles();
    showError('');
    showSuccess(`Импортировано профилей: ${importedProfiles.length}.`);
  } catch (error) {
    showSuccess('');
    showError(error instanceof Error ? error.message : String(error));
  } finally {
    importProfilesInput.value = '';
  }
});

togglePasswordButton.addEventListener('click', () => {
  const nextType = passwordInput.type === 'password' ? 'text' : 'password';
  passwordInput.type = nextType;
  togglePasswordButton.textContent = nextType === 'password' ? 'Показать пароль' : 'Скрыть пароль';
});

clearPasswordButton.addEventListener('click', () => {
  passwordInput.value = '';
  showError('');
  showSuccess('Пароль очищен в форме. Нажмите “Сохранить”, чтобы применить изменение.');
});

await loadProfiles();
