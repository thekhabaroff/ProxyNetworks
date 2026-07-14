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
const formSuccess = document.getElementById('formSuccess');
const deleteButton = document.getElementById('deleteButton');
const activateButton = document.getElementById('activateButton');
const testProfileButton = document.getElementById('testProfileButton');
const exportProfilesButton = document.getElementById('exportProfilesButton');
const importProfilesButton = document.getElementById('importProfilesButton');
const importProfilesInput = document.getElementById('importProfilesInput');
const togglePasswordButton = document.getElementById('togglePasswordButton');
const clearPasswordButton = document.getElementById('clearPasswordButton');

const ALLOWED_MODES = ['direct', 'auto_detect', 'system', 'fixed_servers', 'pac_script'];
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
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean))];
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
    return null;
  }
}

function normalizeProxyUrlInput(profile) {
  const parsed = parseProxyUrl(profile.host);
  if (!parsed) {
    return profile;
  }

  return {
    ...profile,
    scheme: parsed.scheme || profile.scheme,
    host: parsed.host,
    port: parsed.port || profile.port,
  };
}

function isValidHost(host) {
  return Boolean(host) && !/\s|\/|:\/\//.test(host);
}

function isValidPort(port) {
  return Number.isInteger(Number(port)) && Number(port) >= 1 && Number(port) <= 65535;
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
  passwordInput.type = 'password';
  togglePasswordButton.textContent = 'Показать пароль';
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

  if (!ALLOWED_MODES.includes(data.mode)) {
    return 'Выбран неизвестный режим прокси.';
  }

  if (data.mode === 'fixed_servers' && !data.useAdvanced) {
    if (!ALLOWED_SCHEMES.includes(data.scheme)) {
      return 'Выбрана неизвестная схема прокси.';
    }
    if (!isValidHost(data.host)) {
      return 'Укажите корректный хост прокси без http://, путей и пробелов.';
    }
    if (!isValidPort(data.port)) {
      return 'Порт должен быть числом от 1 до 65535.';
    }
  }

  if (data.mode === 'pac_script' && !data.pacScript.trim()) {
    return 'Укажите PAC-скрипт.';
  }

  const endpoints = [data.proxyForHttp, data.proxyForHttps, data.socks].filter(Boolean);
  if (data.mode === 'fixed_servers' && data.useAdvanced && endpoints.length === 0) {
    return 'Заполните хотя бы один прокси-эндпоинт в расширенном режиме.';
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

  return '';
}

function collectProfile() {
  const useAdvanced = useAdvancedInput.checked;
  let profile = {
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

  profile = normalizeProxyUrlInput(profile);
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
  const exportedProfiles = (await getProfiles()).map((profile) => ({
    ...profile,
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
        id: undefined,
        name: profile.name ? `${profile.name} (import)` : 'Imported profile',
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

modeInput.addEventListener('change', setFieldVisibility);
useAdvancedInput.addEventListener('change', setFieldVisibility);

await loadProfiles();
