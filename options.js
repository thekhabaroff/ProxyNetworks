import {
  deleteProfile,
  getActiveProfileId,
  getEnabled,
  getProfiles,
  saveProfile,
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
const saveButton = document.getElementById('saveButton');
const checkProxyButtons = [...document.querySelectorAll('.check-proxy-button')];
const exportProfilesButton = document.getElementById('exportProfilesButton');
const importProfilesButton = document.getElementById('importProfilesButton');
const importProfilesInput = document.getElementById('importProfilesInput');
const togglePasswordButton = document.getElementById('togglePasswordButton');
const clearPasswordButton = document.getElementById('clearPasswordButton');

const ALLOWED_SCHEMES = ['http', 'https', 'socks5'];

let profiles = [];
let selectedProfileId = null;
let successTimer = null;

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
  clearTimeout(successTimer);
  if (!message) {
    formSuccess.classList.add('hidden');
    formSuccess.textContent = '';
    return;
  }

  formSuccess.textContent = message;
  formSuccess.classList.remove('hidden');
  successTimer = setTimeout(() => showSuccess(''), 2200);
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

  const scheme = profile.scheme === 'socks4' ? 'socks5'
    : ALLOWED_SCHEMES.includes(profile.scheme) ? profile.scheme : 'http';
  const endpoint = { scheme, host, port };
  if (scheme === 'socks5') {
    return {
      proxyForHttp: null,
      proxyForHttps: null,
      socks: { ...endpoint, scheme: 'socks5' },
    };
  }

  return {
    proxyForHttp: { ...endpoint, scheme: 'http' },
    proxyForHttps: { ...endpoint, scheme: 'https' },
    socks: null,
  };
}

function isValidHost(host) {
  return typeof host === 'string' && Boolean(host.trim()) && !/\s|\/|:\/\//.test(host);
}

function isValidPort(port) {
  return Number.isInteger(Number(port)) && Number(port) >= 1 && Number(port) <= 65535;
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

function resetProtocolStatuses() {
  for (const status of document.querySelectorAll('.proxy-status')) {
    status.className = 'proxy-status';
    status.title = '';
  }
}

function fillForm(profile) {
  resetProtocolStatuses();
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
}

function loadProfile(id) {
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
  if (!data || typeof data.name !== 'string' || !data.name.trim()) {
    return 'Введите название профиля.';
  }

  const endpoints = [data.proxyForHttp, data.proxyForHttps, data.socks].filter(Boolean);
  if (endpoints.length === 0) {
    return 'Заполните хотя бы один прокси-эндпоинт.';
  }

  for (const endpoint of endpoints) {
    if (typeof endpoint !== 'object') {
      return 'Прокси-эндпоинт имеет некорректный формат.';
    }
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
    proxyForHttp: endpointFromInputs('http', httpHostInput, httpPortInput),
    proxyForHttps: endpointFromInputs('https', httpsHostInput, httpsPortInput),
    socks: endpointFromInputs('socks5', socksHostInput, socksPortInput),
    bypassList: parseBypassList(bypassListInput.value),
    username: usernameInput.value.trim(),
    password: passwordInput.value,
  };
}

async function refreshAfterSave(savedProfile) {
  await loadProfiles();
  await loadProfile(savedProfile.id);
  const enabled = await getEnabled();
  if (enabled && savedProfile.id === (await getActiveProfileId())) {
    await sendCommand({ action: 'applyProfile', profileId: savedProfile.id });
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
  saveButton.disabled = true;
  try {
    const savedProfile = await saveProfile(profile);
    await refreshAfterSave(savedProfile);
    showSuccess('Профиль сохранён.');
  } catch (error) {
    showError(error instanceof Error ? error.message : String(error));
  } finally {
    saveButton.disabled = false;
  }
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

  deleteButton.disabled = true;
  try {
    const activeProfileId = await getActiveProfileId();
    if (id === activeProfileId && await getEnabled()) {
      await sendCommand({ action: 'disable' });
    }
    await deleteProfile(id);
    await loadProfiles();
    showSuccess('Профиль удалён.');
  } catch (error) {
    showError(error instanceof Error ? error.message : String(error));
  } finally {
    deleteButton.disabled = !profileIdInput.value;
  }
});

for (const button of checkProxyButtons) {
  button.addEventListener('click', async () => {
    const protocol = button.dataset.protocol;
    const status = document.querySelector(`.proxy-status[data-protocol="${protocol}"]`);
    const endpoint = protocol === 'http'
      ? endpointFromInputs('http', httpHostInput, httpPortInput)
      : protocol === 'https'
        ? endpointFromInputs('https', httpsHostInput, httpsPortInput)
        : endpointFromInputs('socks5', socksHostInput, socksPortInput);
    if (!endpoint || !isValidHost(endpoint.host) || !isValidPort(endpoint.port)) {
      status.className = 'proxy-status invalid';
      status.title = 'Укажите корректные хост и порт.';
      return;
    }
    for (const checkButton of checkProxyButtons) checkButton.disabled = true;
    status.className = 'proxy-status checking';
    status.title = 'Проверка...';
    try {
      const response = await sendMessage({
        action: 'checkProxyEndpoint',
        endpoint,
        username: usernameInput.value.trim(),
        password: passwordInput.value,
      });
      status.className = `proxy-status ${response?.ok ? 'online' : 'offline'}`;
      status.title = response?.error || (response?.ip ? `IP: ${response.ip}` : '');
    } catch (error) {
      status.className = 'proxy-status offline';
      status.title = error instanceof Error ? error.message : String(error);
    } finally {
      for (const checkButton of checkProxyButtons) checkButton.disabled = false;
    }
  });
}

for (const [protocol, inputs] of [
  ['http', [httpHostInput, httpPortInput]],
  ['https', [httpsHostInput, httpsPortInput]],
  ['socks', [socksHostInput, socksPortInput]],
]) {
  for (const input of inputs) {
    input.addEventListener('input', () => {
      const status = document.querySelector(`.proxy-status[data-protocol="${protocol}"]`);
      status.className = 'proxy-status';
      status.title = '';
    });
  }
}

profileForm.addEventListener('input', () => {
  showSuccess('');
});

usernameInput.addEventListener('input', resetProtocolStatuses);
passwordInput.addEventListener('input', resetProtocolStatuses);

exportProfilesButton.addEventListener('click', async () => {
  const includePasswords = confirm('Экспортировать профили вместе с паролями? Нажмите “Отмена”, чтобы экспортировать без паролей.');
  exportProfilesButton.disabled = true;
  try {
    const exportedProfiles = (await getProfiles()).map((profile) => ({
      name: profile.name,
      proxyForHttp: profile.proxyForHttp,
      proxyForHttps: profile.proxyForHttps,
      socks: profile.socks,
      bypassList: profile.bypassList,
      username: profile.username,
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
    setTimeout(() => URL.revokeObjectURL(url), 0);
    showSuccess(includePasswords ? 'Профили экспортированы с паролями.' : 'Профили экспортированы без паролей.');
  } catch (error) {
    showError(error instanceof Error ? error.message : String(error));
  } finally {
    exportProfilesButton.disabled = false;
  }
});

importProfilesButton.addEventListener('click', () => {
  importProfilesInput.click();
});

importProfilesInput.addEventListener('change', async () => {
  const file = importProfilesInput.files?.[0];
  if (!file) {
    return;
  }

  importProfilesButton.disabled = true;
  try {
    if (file.size > 1024 * 1024) {
      throw new Error('Файл импорта не должен превышать 1 МБ.');
    }
    const payload = JSON.parse(await file.text());
    const importedProfiles = Array.isArray(payload?.profiles) ? payload.profiles : null;
    if (!importedProfiles) {
      throw new Error('Файл должен содержать массив profiles.');
    }
    if (importedProfiles.length > 500) {
      throw new Error('За один раз можно импортировать не более 500 профилей.');
    }

    const preparedProfiles = importedProfiles.map((profile) => {
      if (!profile || typeof profile !== 'object' || Array.isArray(profile)) {
        throw new Error('Каждый профиль должен быть объектом.');
      }
      const prepared = {
        ...profile,
        ...endpointsFromLegacySingleProxy(profile),
        id: undefined,
        name: profile.name ? `${profile.name} (import)` : 'Imported profile',
      };
      const validationError = validateProfile(prepared);
      if (validationError) {
        throw new Error(validationError);
      }
      return prepared;
    });

    for (const profile of preparedProfiles) {
      await saveProfile(profile);
    }

    await loadProfiles();
    showError('');
    showSuccess(`Импортировано профилей: ${importedProfiles.length}.`);
  } catch (error) {
    showSuccess('');
    showError(error instanceof Error ? error.message : String(error));
  } finally {
    importProfilesInput.value = '';
    importProfilesButton.disabled = false;
  }
});

togglePasswordButton.addEventListener('click', () => {
  const nextType = passwordInput.type === 'password' ? 'text' : 'password';
  passwordInput.type = nextType;
  togglePasswordButton.textContent = nextType === 'password' ? 'Показать пароль' : 'Скрыть пароль';
});

clearPasswordButton.addEventListener('click', () => {
  passwordInput.value = '';
  resetProtocolStatuses();
  showError('');
  showSuccess('Пароль очищен в форме. Нажмите “Сохранить”, чтобы применить изменение.');
});

try {
  await loadProfiles();
} catch (error) {
  showError(error instanceof Error ? error.message : String(error));
}
