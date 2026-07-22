import {
  deleteProfile,
  getActiveProfileId,
  getEnabled,
  getProfiles,
  normalizeProfile,
  reorderProfiles,
  saveProfile,
  saveProfiles,
} from './storage.js';
import { geositeNameFromEntry } from './geosite.js';
import { getConfiguredProtocols } from './config.js';
import {
  errorMessage,
  isValidProxyHost,
  normalizeDomain,
  normalizePort,
  parseProxyClipboardEntry,
  normalizeStringList,
  sendRuntimeCommand,
  sendRuntimeMessage,
} from './utils.js';

const profilesList = document.getElementById('profilesList');
const newProfileButton = document.getElementById('newProfileButton');
const formTitle = document.getElementById('formTitle');
const profileForm = document.getElementById('profileForm');
const profileIdInput = document.getElementById('profileId');
const nameInput = document.getElementById('name');
const profileTagsInput = document.getElementById('profileTags');
const profileNoteInput = document.getElementById('profileNote');
const httpHostInput = document.getElementById('httpHost');
const httpPortInput = document.getElementById('httpPort');
const httpsHostInput = document.getElementById('httpsHost');
const httpsPortInput = document.getElementById('httpsPort');
const socksHostInput = document.getElementById('socksHost');
const socksPortInput = document.getElementById('socksPort');
const routingModeInput = document.getElementById('routingMode');
const proxyListField = document.getElementById('proxyListField');
const proxyListInput = document.getElementById('proxyList');
const killSwitchInput = document.getElementById('killSwitch');
const manualBypassField = document.getElementById('manualBypassField');
const bypassListInput = document.getElementById('bypassList');
const bypassRussianResourcesInput = document.getElementById('bypassRussianResources');
const bypassLocalNetworksInput = document.getElementById('bypassLocalNetworks');
const builtinBypassOptions = document.getElementById('builtinBypassOptions');
const blockListField = document.getElementById('blockListField');
const blockListInput = document.getElementById('blockList');
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
const pasteProxyButton = document.getElementById('pasteProxyButton');
const diagnosticsState = document.getElementById('diagnosticsState');
const diagnosticsProfileName = document.getElementById('diagnosticsProfileName');
const diagnosticsRouting = document.getElementById('diagnosticsRouting');
const diagnosticsEndpoints = document.getElementById('diagnosticsEndpoints');
const diagnosticsBypass = document.getElementById('diagnosticsBypass');
const diagnosticsBlock = document.getElementById('diagnosticsBlock');
const diagnosticsCheckButton = document.getElementById('diagnosticsCheckButton');
const diagnosticsResults = document.getElementById('diagnosticsResults');
const refreshGeositeButton = document.getElementById('refreshGeositeButton');
const geositeStatusList = document.getElementById('geositeStatusList');

const ALLOWED_SCHEMES = new Set(['http', 'https', 'socks5']);
const PROXY_URL_PROTOCOLS = new Set(['http:', 'https:', 'socks:', 'socks5:']);
const PROTOCOL_NAMES = Object.freeze({
  http: 'HTTP',
  https: 'HTTPS',
  socks: 'SOCKS5',
});
const PROXY_FIELDS = Object.freeze({
  http: { scheme: 'http', hostInput: httpHostInput, portInput: httpPortInput },
  https: { scheme: 'https', hostInput: httpsHostInput, portInput: httpsPortInput },
  socks: { scheme: 'socks5', hostInput: socksHostInput, portInput: socksPortInput },
});

let profiles = [];
let selectedProfileId = null;
let successTimer = null;
let draggedProfileId = null;
let diagnosticsRefreshTimer = null;
let proxyGeoRequestId = 0;
const profileGeoById = new Map();
const proxyStatusTimers = new Map();
const PROXY_RESULT_TIMEOUT_MS = 10000;
const EXPORT_FORMAT = 'proxy-networks-export';
const EXPORT_VERSION = 2;
const EXPORT_KDF_ITERATIONS = 250000;

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

function formatStringList(items) {
  return Array.isArray(items) ? items.join('\n') : '';
}

function bytesToBase64(bytes) {
  let binary = '';
  const chunkSize = 0x8000;
  for (let index = 0; index < bytes.length; index += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize));
  }
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

async function deriveExportKey(passphrase, salt, iterations, usages) {
  const material = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    usages,
  );
}

async function encryptExportPayload(payload, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveExportKey(passphrase, salt, EXPORT_KDF_ITERATIONS, ['encrypt']);
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(JSON.stringify(payload)),
  );
  return {
    format: EXPORT_FORMAT,
    version: EXPORT_VERSION,
    encrypted: true,
    kdf: {
      name: 'PBKDF2',
      hash: 'SHA-256',
      iterations: EXPORT_KDF_ITERATIONS,
      salt: bytesToBase64(salt),
    },
    cipher: {
      name: 'AES-GCM',
      iv: bytesToBase64(iv),
      data: bytesToBase64(new Uint8Array(encrypted)),
    },
  };
}

async function decryptExportPayload(envelope) {
  const iterations = Number(envelope?.kdf?.iterations);
  if (envelope?.format !== EXPORT_FORMAT
    || envelope?.kdf?.name !== 'PBKDF2'
    || envelope?.kdf?.hash !== 'SHA-256'
    || envelope?.cipher?.name !== 'AES-GCM'
    || !Number.isInteger(iterations)
    || iterations < 100000
    || iterations > 1000000) {
    throw new Error('Формат защищённого экспорта не поддерживается.');
  }

  const passphrase = prompt('Введите пароль защищённого экспорта:');
  if (passphrase === null) {
    throw new Error('Импорт отменён.');
  }
  if (!passphrase) {
    throw new Error('Пароль экспорта не может быть пустым.');
  }

  try {
    const salt = base64ToBytes(envelope.kdf.salt);
    const iv = base64ToBytes(envelope.cipher.iv);
    const ciphertext = base64ToBytes(envelope.cipher.data);
    if (salt.length < 16 || iv.length !== 12 || ciphertext.length < 16) {
      throw new Error('Повреждённые параметры шифрования.');
    }
    const key = await deriveExportKey(passphrase, salt, iterations, ['decrypt']);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return JSON.parse(new TextDecoder().decode(decrypted));
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new Error('Расшифрованный файл повреждён.');
    }
    throw new Error('Неверный пароль или повреждённый файл экспорта.');
  }
}

function profileForExport(profile, includePasswords) {
  return {
    name: profile.name,
    tags: profile.tags,
    note: profile.note,
    proxyForHttp: profile.proxyForHttp,
    proxyForHttps: profile.proxyForHttps,
    socks: profile.socks,
    routingMode: profile.routingMode,
    proxyList: profile.proxyList,
    killSwitch: profile.killSwitch === true,
    bypassList: profile.bypassList,
    bypassRussianResources: profile.bypassRussianResources === true,
    bypassLocalNetworks: profile.bypassLocalNetworks === true,
    blockList: profile.blockList,
    username: profile.username,
    password: includePasswords ? profile.password : '',
  };
}

function parseProxyUrl(value) {
  const trimmed = value.trim();
  if (!trimmed.includes('://')) {
    return null;
  }

  try {
    const url = new URL(trimmed);
    if (!PROXY_URL_PROTOCOLS.has(url.protocol)
      || url.username
      || url.password
      || (url.pathname && url.pathname !== '/')
      || url.search
      || url.hash) {
      return null;
    }
    return {
      host: url.hostname,
      port: url.port ? Number(url.port) : 0,
    };
  } catch {
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

function renderProfileList() {
  profilesList.replaceChildren();

  for (const profile of profiles) {
    const item = document.createElement('button');
    item.type = 'button';
    item.className = `profile-item${profile.id === selectedProfileId ? ' active' : ''}`;
    item.draggable = true;
    item.title = 'Перетащите профиль, чтобы изменить порядок.';
    item.setAttribute('aria-pressed', String(profile.id === selectedProfileId));
    const summary = document.createElement('span');
    summary.className = 'profile-summary';
    const name = document.createElement('span');
    name.className = 'profile-name';
    name.textContent = profile.name || profile.id;
    summary.append(name);
    item.append(summary);
    if (profile.tags?.length) {
      const tags = document.createElement('span');
      tags.className = 'profile-tags';
      for (const tagText of profile.tags) {
        const tag = document.createElement('span');
        tag.className = 'profile-tag';
        tag.textContent = tagText;
        tags.append(tag);
      }
      item.append(tags);
    }
    const geoResults = profileGeoById.get(profile.id) ?? [];
    const uniqueLocations = new Map();
    for (const result of geoResults) {
      if (!result?.geo) continue;
      const geo = result.geo;
      const key = `${geo.countryCode ?? geo.country ?? ''}|${geo.city ?? ''}|${geo.provider ?? ''}`;
      uniqueLocations.set(key, geo);
    }
    if (uniqueLocations.size > 0) {
      const locations = document.createElement('span');
      locations.className = 'profile-geo-list';
      for (const geo of uniqueLocations.values()) {
        const location = document.createElement('span');
        location.className = 'profile-geo';
        const flag = document.createElement('span');
        flag.className = 'profile-geo-flag';
        flag.textContent = geo.flag ?? '🌐';
        const country = document.createElement('span');
        country.className = 'profile-geo-country';
        country.textContent = `${geo.country ?? 'Страна не указана'}${geo.city && geo.city !== 'Город не указан' ? ` · ${geo.city}` : ''}`;
        const provider = document.createElement('span');
        provider.className = 'profile-geo-provider';
        provider.textContent = geo.provider ?? 'Провайдер не указан';
        location.title = `${country.textContent} · ${provider.textContent}`;
        location.append(flag, country, provider);
        locations.append(location);
      }
      item.append(locations);
    }
    item.addEventListener('click', () => {
      loadProfile(profile.id);
    });
    item.addEventListener('dragstart', (event) => {
      draggedProfileId = profile.id;
      item.classList.add('dragging');
      event.dataTransfer.effectAllowed = 'move';
      event.dataTransfer.setData('text/plain', profile.id);
    });
    item.addEventListener('dragend', () => {
      draggedProfileId = null;
      item.classList.remove('dragging');
      profilesList.querySelectorAll('.drop-target').forEach((element) => {
        element.classList.remove('drop-target');
      });
    });
    item.addEventListener('dragover', (event) => {
      if (!draggedProfileId || draggedProfileId === profile.id) return;
      event.preventDefault();
      event.dataTransfer.dropEffect = 'move';
    });
    item.addEventListener('dragenter', () => {
      if (draggedProfileId && draggedProfileId !== profile.id) {
        item.classList.add('drop-target');
      }
    });
    item.addEventListener('dragleave', () => {
      item.classList.remove('drop-target');
    });
    item.addEventListener('drop', (event) => {
      event.preventDefault();
      item.classList.remove('drop-target');
      const sourceId = draggedProfileId || event.dataTransfer.getData('text/plain');
      void moveProfile(sourceId, profile.id);
    });
    profilesList.append(item);
  }
}

async function moveProfile(sourceId, targetId) {
  if (!sourceId || sourceId === targetId) {
    return;
  }

  const sourceIndex = profiles.findIndex((profile) => profile.id === sourceId);
  const targetIndex = profiles.findIndex((profile) => profile.id === targetId);
  if (sourceIndex < 0 || targetIndex < 0) {
    return;
  }

  const nextProfiles = [...profiles];
  const [movedProfile] = nextProfiles.splice(sourceIndex, 1);
  const insertionIndex = sourceIndex < targetIndex ? targetIndex - 1 : targetIndex;
  nextProfiles.splice(insertionIndex, 0, movedProfile);
  profiles = nextProfiles;
  renderProfileList();

  try {
    await reorderProfiles(profiles.map((profile) => profile.id));
    showSuccess('Порядок профилей сохранён.');
  } catch (error) {
    await loadProfiles();
    showError(errorMessage(error));
  }
}

function setProxyStatus(status, state = '', details = '') {
  if (!status) {
    return;
  }
  const statusText = {
    online: 'доступен',
    offline: 'недоступен',
    invalid: 'некорректные параметры',
    checking: 'проверяется',
  }[state] ?? 'не проверен';
  const protocolName = PROTOCOL_NAMES[status.dataset.protocol] ?? 'прокси';
  status.className = `proxy-status${state ? ` ${state}` : ''}`;
  status.title = details;
  status.setAttribute('aria-label', `Статус ${protocolName}: ${statusText}${details ? `. ${details}` : ''}`);
}

function setProxyPing(protocol, ping = null) {
  const pingElement = document.querySelector(`.proxy-ping[data-protocol="${protocol}"]`);
  if (!pingElement) {
    return;
  }
  pingElement.textContent = Number.isFinite(ping) ? `Пинг: ${ping} мс` : '';
}

function clearProxyStatusTimer(protocol) {
  const timerId = proxyStatusTimers.get(protocol);
  if (timerId) {
    clearTimeout(timerId);
    proxyStatusTimers.delete(protocol);
  }
}

function clearProxyCheckResult(protocol) {
  const status = document.querySelector(`.proxy-status[data-protocol="${protocol}"]`);
  setProxyStatus(status);
  setProxyPing(protocol);
}

function scheduleProxyCheckResultClear(protocol) {
  clearProxyStatusTimer(protocol);
  const timerId = setTimeout(() => {
    clearProxyCheckResult(protocol);
    proxyStatusTimers.delete(protocol);
  }, PROXY_RESULT_TIMEOUT_MS);
  proxyStatusTimers.set(protocol, timerId);
}

function resetProtocolStatuses() {
  for (const status of document.querySelectorAll('.proxy-status')) {
    const protocol = status.dataset.protocol;
    clearProxyStatusTimer(protocol);
    clearProxyCheckResult(protocol);
  }
}

function updateRoutingVisibility() {
  const selectedOnly = routingModeInput.value === 'selected';
  proxyListField.classList.toggle('hidden', !selectedOnly);
  manualBypassField.classList.toggle('hidden', selectedOnly);
  blockListField.classList.toggle('hidden', selectedOnly);
  if (selectedOnly) {
    proxyListField.append(builtinBypassOptions);
  } else {
    manualBypassField.after(builtinBypassOptions);
  }
  diagnosticsRouting.textContent = selectedOnly
    ? `Только выбранные сайты${killSwitchInput.checked ? ' · Kill Switch' : ''}`
    : `Весь трафик${killSwitchInput.checked ? ' · Kill Switch' : ''}`;
}

async function loadProxyGeo() {
  const profileId = profileIdInput.value;
  const requestId = ++proxyGeoRequestId;
  const profile = profiles.find((item) => item.id === profileId);
  if (!profile) {
    return;
  }

  try {
    const protocols = getConfiguredProtocols(profile);
    const responses = await Promise.all(protocols.map((protocol) => sendRuntimeCommand({
      action: 'getProxyGeo',
      profileId,
      protocol,
    })));
    if (requestId !== proxyGeoRequestId || profileId !== profileIdInput.value) return;
    profileGeoById.set(profileId, responses);
    renderProfileList();
  } catch (error) {
    if (requestId !== proxyGeoRequestId || profileId !== profileIdInput.value) return;
    console.warn('Unable to determine proxy location:', error);
  }
}

function renderGeositeStatuses(statuses) {
  geositeStatusList.replaceChildren();
  if (!Array.isArray(statuses) || statuses.length === 0) {
    geositeStatusList.textContent = profileIdInput.value
      ? 'В профиле нет geosite-баз.'
      : 'Сохраните профиль, чтобы управлять geosite-базами.';
    refreshGeositeButton.disabled = true;
    return;
  }

  refreshGeositeButton.disabled = false;
  for (const status of statuses) {
    const item = document.createElement('div');
    item.className = 'geosite-status-item';
    const name = document.createElement('span');
    name.className = 'geosite-status-name';
    name.textContent = `geosite:${status.name}`;
    const state = document.createElement('span');
    state.className = `geosite-status-state ${status.fresh ? 'fresh' : 'stale'}`;
    state.textContent = status.fresh ? 'Актуальна' : status.cached ? 'Устарела' : 'Не загружена';
    const meta = document.createElement('span');
    meta.className = 'geosite-status-meta';
    const updatedAt = status.updatedAt
      ? new Date(status.updatedAt).toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' })
      : '—';
    meta.textContent = `${status.domains.toLocaleString('ru-RU')} доменов · ${updatedAt}`;
    item.append(name, state, meta);
    geositeStatusList.append(item);
  }
}

async function loadGeositeStatuses() {
  const profileId = profileIdInput.value;
  if (!profileId) {
    renderGeositeStatuses([]);
    return;
  }
  try {
    const response = await sendRuntimeCommand({ action: 'getGeositeStatus', profileId });
    renderGeositeStatuses(response.statuses);
  } catch (error) {
    geositeStatusList.textContent = `Не удалось прочитать кэш: ${errorMessage(error)}`;
    refreshGeositeButton.disabled = true;
  }
}

async function refreshDiagnostics() {
  const draft = collectProfile();
  const endpoints = [draft.proxyForHttp, draft.proxyForHttps, draft.socks].filter(Boolean).length;
  diagnosticsProfileName.textContent = draft.name || 'Новый профиль';
  diagnosticsEndpoints.textContent = `${endpoints} из 3`;
  diagnosticsBypass.textContent = String(
    (draft.routingMode === 'selected' ? 0 : draft.bypassList.length)
      + (draft.bypassRussianResources ? 1 : 0)
      + (draft.bypassLocalNetworks ? 1 : 0),
  );
  diagnosticsBlock.textContent = String(draft.routingMode === 'selected' ? 0 : draft.blockList.length);
  diagnosticsCheckButton.disabled = endpoints === 0;
  updateRoutingVisibility();

  diagnosticsState.className = 'state-badge';
  if (!draft.id) {
    diagnosticsState.textContent = 'Не сохранён';
    return;
  }
  try {
    const status = await sendRuntimeCommand({ action: 'getStatus' });
    if (status.activeProfileId === draft.id && status.enabled) {
      diagnosticsState.textContent = 'Активен';
      diagnosticsState.classList.add('active');
    } else if (status.activeProfileId === draft.id) {
      diagnosticsState.textContent = 'Выбран';
      diagnosticsState.classList.add('selected');
    } else {
      diagnosticsState.textContent = 'Сохранён';
    }
  } catch {
    diagnosticsState.textContent = 'Состояние неизвестно';
  }
}

function scheduleDiagnosticsRefresh() {
  clearTimeout(diagnosticsRefreshTimer);
  diagnosticsRefreshTimer = setTimeout(() => {
    void refreshDiagnostics();
  }, 100);
}

function fillForm(profile) {
  resetProtocolStatuses();
  profileIdInput.value = profile?.id ?? '';
  nameInput.value = profile?.name ?? '';
  profileTagsInput.value = Array.isArray(profile?.tags) ? profile.tags.join(', ') : '';
  profileNoteInput.value = profile?.note ?? '';
  httpHostInput.value = profile?.proxyForHttp?.host ?? '';
  httpPortInput.value = profile?.proxyForHttp?.port ? String(profile.proxyForHttp.port) : '';
  httpsHostInput.value = profile?.proxyForHttps?.host ?? '';
  httpsPortInput.value = profile?.proxyForHttps?.port ? String(profile.proxyForHttps.port) : '';
  socksHostInput.value = profile?.socks?.host ?? '';
  socksPortInput.value = profile?.socks?.port ? String(profile.socks.port) : '';
  routingModeInput.value = profile?.routingMode === 'selected' ? 'selected' : 'all';
  proxyListInput.value = formatStringList(profile?.proxyList ?? []);
  killSwitchInput.checked = profile?.killSwitch === true;
  bypassListInput.value = formatStringList(profile?.bypassList ?? []);
  bypassRussianResourcesInput.checked = profile?.bypassRussianResources === true;
  bypassLocalNetworksInput.checked = profile?.bypassLocalNetworks === true;
  blockListInput.value = formatStringList(profile?.blockList ?? []);
  usernameInput.value = profile?.username ?? '';
  passwordInput.value = profile?.password ?? '';
  passwordInput.type = 'password';
  togglePasswordButton.textContent = 'Показать пароль';
  formTitle.textContent = profile?.id ? `Профиль: ${profile.name || profile.id}` : 'Новый профиль';
  deleteButton.disabled = !profile?.id;
  diagnosticsResults.className = 'diagnostics-results';
  diagnosticsResults.textContent = 'Проверка ещё не запускалась.';
  updateRoutingVisibility();
  void refreshDiagnostics();
  void loadGeositeStatuses();
  void loadProxyGeo();
}

function loadProfile(id) {
  const profile = profiles.find((item) => item.id === id) ?? null;
  selectedProfileId = profile?.id ?? null;
  renderProfileList();
  fillForm(profile);
  showError('');
  showSuccess('');
}

async function loadProfiles() {
  const [loadedProfiles, activeProfileId] = await Promise.all([
    getProfiles(),
    getActiveProfileId(),
  ]);
  profiles = loadedProfiles;
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
  if (data.name.length > 120) {
    return 'Название профиля не должно превышать 120 символов.';
  }

  const endpoints = [data.proxyForHttp, data.proxyForHttps, data.socks].filter(Boolean);
  if (endpoints.length === 0) {
    return 'Заполните хотя бы один прокси-эндпоинт.';
  }

  for (const endpoint of endpoints) {
    if (typeof endpoint !== 'object') {
      return 'Прокси-эндпоинт имеет некорректный формат.';
    }
    if (!ALLOWED_SCHEMES.has(endpoint.scheme)) {
      return 'Выбрана неизвестная схема прокси-эндпоинта.';
    }
    if (!isValidProxyHost(endpoint.host)) {
      return 'Укажите корректный хост для всех заполненных прокси-эндпоинтов без http://, путей и пробелов.';
    }
    if (!normalizePort(endpoint.port)) {
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

  if (!['all', 'selected'].includes(data.routingMode)) {
    return 'Выбран неизвестный режим маршрутизации.';
  }
  if (data.routingMode === 'selected' && data.proxyList.length === 0) {
    return 'Для выборочной маршрутизации добавьте хотя бы один сайт.';
  }

  const listsToValidate = [[data.proxyList, 'списке маршрутизации']];
  if (data.routingMode !== 'selected') {
    listsToValidate.push(
      [data.bypassList, 'исключениях'],
      [data.blockList, 'списке блокировки'],
    );
  }
  for (const [entries, label] of listsToValidate) {
    for (const entry of entries) {
      if (/^geosite:/i.test(entry) && !geositeNameFromEntry(entry)) {
        return `Некорректная geosite-запись в ${label}: ${entry}`;
      }
    }
  }
  for (const entry of data.proxyList) {
    if (!geositeNameFromEntry(entry) && !normalizeDomain(entry)) {
      return `Некорректный домен в списке маршрутизации: ${entry}`;
    }
  }
  if (data.routingMode !== 'selected') {
    for (const entry of data.blockList) {
      if (!geositeNameFromEntry(entry) && !normalizeDomain(entry)) {
        return `Некорректный домен в списке блокировки: ${entry}`;
      }
    }
  }
  if (data.username.length > 256) {
    return 'Логин не должен превышать 256 символов.';
  }
  if (data.password.length > 1024) {
    return 'Пароль не должен превышать 1024 символа.';
  }
  if (data.note.length > 2000) {
    return 'Заметка не должна превышать 2000 символов.';
  }
  if (data.tags.length > 12 || data.tags.some((tag) => tag.length > 32)) {
    return 'Используйте не более 12 тегов длиной до 32 символов каждый.';
  }
  return '';
}

function collectProfile() {
  return {
    id: profileIdInput.value || undefined,
    name: nameInput.value.trim(),
    tags: normalizeStringList(profileTagsInput.value),
    note: profileNoteInput.value.trim(),
    proxyForHttp: endpointFromInputs('http', httpHostInput, httpPortInput),
    proxyForHttps: endpointFromInputs('https', httpsHostInput, httpsPortInput),
    socks: endpointFromInputs('socks5', socksHostInput, socksPortInput),
    routingMode: routingModeInput.value,
    proxyList: normalizeStringList(proxyListInput.value),
    killSwitch: killSwitchInput.checked,
    bypassList: normalizeStringList(bypassListInput.value),
    bypassRussianResources: bypassRussianResourcesInput.checked,
    bypassLocalNetworks: bypassLocalNetworksInput.checked,
    blockList: normalizeStringList(blockListInput.value),
    username: usernameInput.value.trim(),
    password: passwordInput.value,
  };
}

function applyClipboardProxy(proxy) {
  const fields = PROXY_FIELDS[proxy.protocol];
  if (!fields) {
    throw new Error('Не удалось определить тип прокси.');
  }

  fields.hostInput.value = proxy.host;
  fields.portInput.value = String(proxy.port);
  if (proxy.username !== null) {
    usernameInput.value = proxy.username;
    passwordInput.value = proxy.password ?? '';
  }
  resetProtocolStatuses();
  showError('');

  const protocolName = PROTOCOL_NAMES[proxy.protocol] ?? 'прокси';
  const authNote = proxy.username === null
    ? ' Данные авторизации не изменены.'
    : '';
  showSuccess(`${protocolName} прокси вставлен в форму.${authNote} Нажмите «Сохранить», чтобы применить изменения.`);
}

async function refreshAfterSave(savedProfile) {
  await loadProfiles();
  loadProfile(savedProfile.id);
  const enabled = await getEnabled();
  if (enabled && savedProfile.id === (await getActiveProfileId())) {
    await sendRuntimeCommand({ action: 'applyProfile', profileId: savedProfile.id });
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
    showError(errorMessage(error));
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
      await sendRuntimeCommand({ action: 'disable' });
    }
    await deleteProfile(id);
    await loadProfiles();
    showSuccess('Профиль удалён.');
  } catch (error) {
    showError(errorMessage(error));
  } finally {
    deleteButton.disabled = !profileIdInput.value;
  }
});

async function checkProxyProtocol(protocol) {
  const status = document.querySelector(`.proxy-status[data-protocol="${protocol}"]`);
  const fields = PROXY_FIELDS[protocol];
  const endpoint = fields
    ? endpointFromInputs(fields.scheme, fields.hostInput, fields.portInput)
    : null;
  clearProxyStatusTimer(protocol);
  if (!endpoint || !isValidProxyHost(endpoint.host) || !normalizePort(endpoint.port)) {
    const result = { ok: false, skipped: !endpoint, error: 'Укажите корректные хост и порт.' };
    if (endpoint) setProxyStatus(status, 'invalid', result.error);
    setProxyPing(protocol);
    if (endpoint) scheduleProxyCheckResultClear(protocol);
    return result;
  }

  for (const checkButton of checkProxyButtons) checkButton.disabled = true;
  setProxyStatus(status, 'checking', 'Проверка…');
  setProxyPing(protocol);
  let response;
  try {
    response = await sendRuntimeMessage({
      action: 'checkProxyEndpoint',
      endpoint,
      username: usernameInput.value.trim(),
      password: passwordInput.value,
    });
    setProxyStatus(
      status,
      response?.ok ? 'online' : 'offline',
      response?.error || (response?.ip ? `IP: ${response.ip}` : ''),
    );
    setProxyPing(protocol, response?.ok ? response.ping : null);
    return response ?? { ok: false, error: 'Проверка не вернула результат.' };
  } catch (error) {
    response = { ok: false, error: errorMessage(error) };
    setProxyStatus(status, 'offline', response.error);
    setProxyPing(protocol);
    return response;
  } finally {
    for (const checkButton of checkProxyButtons) checkButton.disabled = false;
    scheduleProxyCheckResultClear(protocol);
  }
}

for (const button of checkProxyButtons) {
  button.addEventListener('click', () => {
    void checkProxyProtocol(button.dataset.protocol);
  });
}

diagnosticsCheckButton.addEventListener('click', async () => {
  diagnosticsCheckButton.disabled = true;
  diagnosticsResults.className = 'diagnostics-results';
  diagnosticsResults.textContent = 'Проверяю настроенные соединения…';
  const lines = [];
  let failures = 0;
  try {
    for (const protocol of Object.keys(PROXY_FIELDS)) {
      const result = await checkProxyProtocol(protocol);
      if (result.skipped) continue;
      if (result.ok) {
        lines.push(`${PROTOCOL_NAMES[protocol]}: ${result.ping} мс · IP ${result.ip ?? 'неизвестен'}`);
      } else {
        failures += 1;
        lines.push(`${PROTOCOL_NAMES[protocol]}: ошибка — ${result.error}`);
      }
    }
    diagnosticsResults.textContent = lines.join('\n') || 'Нет настроенных соединений.';
    diagnosticsResults.classList.add(failures > 0 ? 'failed' : 'successful');
  } finally {
    diagnosticsCheckButton.disabled = false;
  }
});

for (const [protocol, fields] of Object.entries(PROXY_FIELDS)) {
  for (const input of [fields.hostInput, fields.portInput]) {
    input.addEventListener('input', () => {
      const status = document.querySelector(`.proxy-status[data-protocol="${protocol}"]`);
      clearProxyStatusTimer(protocol);
      clearProxyCheckResult(protocol);
    });
  }
}

profileForm.addEventListener('input', () => {
  showSuccess('');
  scheduleDiagnosticsRefresh();
});

routingModeInput.addEventListener('change', updateRoutingVisibility);
killSwitchInput.addEventListener('change', updateRoutingVisibility);

usernameInput.addEventListener('input', resetProtocolStatuses);
passwordInput.addEventListener('input', resetProtocolStatuses);

refreshGeositeButton.addEventListener('click', async () => {
  const profileId = profileIdInput.value;
  if (!profileId) {
    showError('Сначала сохраните профиль.');
    return;
  }
  refreshGeositeButton.disabled = true;
  geositeStatusList.textContent = 'Обновляю geosite-базы…';
  try {
    const response = await sendRuntimeCommand({ action: 'refreshGeosite', profileId });
    renderGeositeStatuses(response.statuses);
    if (response.failed?.length) {
      showError(response.failed.map((item) => `${item.name}: ${item.error}`).join('\n'));
    } else {
      showError('');
      showSuccess(`Обновлено geosite-баз: ${response.refreshed.length}.`);
    }
  } catch (error) {
    showError(errorMessage(error));
    await loadGeositeStatuses();
  }
});

window.addEventListener('pagehide', () => {
  for (const timerId of proxyStatusTimers.values()) {
    clearTimeout(timerId);
  }
  proxyStatusTimers.clear();
}, { once: true });

exportProfilesButton.addEventListener('click', async () => {
  const includePasswords = confirm('Экспортировать профили вместе с паролями? Нажмите “Отмена”, чтобы экспортировать без паролей.');
  exportProfilesButton.disabled = true;
  try {
    let passphrase = null;
    if (includePasswords) {
      passphrase = prompt('Придумайте пароль для файла экспорта (минимум 8 символов):');
      if (passphrase === null) return;
      if (passphrase.length < 8) {
        throw new Error('Пароль экспорта должен содержать минимум 8 символов.');
      }
      const confirmation = prompt('Повторите пароль экспорта:');
      if (confirmation === null) return;
      if (confirmation !== passphrase) {
        throw new Error('Пароли экспорта не совпадают.');
      }
    }

    const exportedProfiles = (await getProfiles())
      .map((profile) => profileForExport(profile, includePasswords));
    const payload = {
      format: EXPORT_FORMAT,
      version: EXPORT_VERSION,
      profiles: exportedProfiles,
    };
    const exportDocument = includePasswords
      ? await encryptExportPayload(payload, passphrase)
      : { ...payload, encrypted: false };
    const blob = new Blob([JSON.stringify(exportDocument, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = includePasswords
      ? 'proxy-networks-profiles.encrypted.json'
      : 'proxy-networks-profiles.json';
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 0);
    showSuccess(includePasswords
      ? 'Профили экспортированы с паролями в зашифрованном файле.'
      : 'Профили экспортированы без паролей.');
  } catch (error) {
    showError(errorMessage(error));
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
    if (file.size > 4 * 1024 * 1024) {
      throw new Error('Файл импорта не должен превышать 4 МБ.');
    }
    const documentPayload = JSON.parse(await file.text());
    const payload = documentPayload?.encrypted === true
      ? await decryptExportPayload(documentPayload)
      : documentPayload;
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
      const prepared = normalizeProfile({
        ...profile,
        id: '',
        name: profile.name ? `${profile.name} (import)` : 'Imported profile',
      });
      const validationError = validateProfile(prepared);
      if (validationError) {
        throw new Error(validationError);
      }
      return prepared;
    });

    await saveProfiles(preparedProfiles);

    await loadProfiles();
    showError('');
    showSuccess(`Импортировано профилей: ${importedProfiles.length}.`);
  } catch (error) {
    showSuccess('');
    showError(errorMessage(error));
  } finally {
    importProfilesInput.value = '';
    importProfilesButton.disabled = false;
  }
});

pasteProxyButton.addEventListener('click', async () => {
  if (!navigator.clipboard?.readText) {
    showError('Браузер не поддерживает чтение буфера обмена.');
    return;
  }

  pasteProxyButton.disabled = true;
  try {
    const proxy = parseProxyClipboardEntry(await navigator.clipboard.readText());
    applyClipboardProxy(proxy);
  } catch (error) {
    showSuccess('');
    showError(errorMessage(error));
  } finally {
    pasteProxyButton.disabled = false;
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
  showError(errorMessage(error));
}

window.addEventListener('pagehide', () => {
  clearTimeout(successTimer);
}, { once: true });
