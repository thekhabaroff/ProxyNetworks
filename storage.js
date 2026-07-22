import {
  normalizePort,
  normalizeProxyHost,
  normalizeStringList,
  storageGet,
  storageSet,
} from './utils.js';

const STORAGE_KEYS = {
  profiles: 'profiles',
  activeProfileId: 'activeProfileId',
  enabled: 'enabled',
  cryptoKey: 'cryptoKey',
  lastError: 'lastError',
  selectedProtocol: 'selectedProtocol',
  contentBlocking: 'contentBlocking',
};

const PROTOCOLS = new Set(['auto', 'http', 'https', 'socks']);
const ROUTING_MODES = new Set(['all', 'selected']);
const STATE_LOCK_NAME = 'state';
const CRYPTO_KEY_LOCK_NAME = 'crypto-key';
const fallbackLockQueues = new Map();
let cryptoKeyPromise = null;

function restrictLocalStorageAccess() {
  return chrome.storage.local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
}

function withStorageLock(name, callback) {
  if (globalThis.navigator?.locks?.request) {
    return globalThis.navigator.locks.request(`proxy-networks:${name}`, { mode: 'exclusive' }, callback);
  }

  const previous = fallbackLockQueues.get(name) ?? Promise.resolve();
  const current = previous.catch(() => undefined).then(callback);
  fallbackLockQueues.set(name, current);
  return current.finally(() => {
    if (fallbackLockQueues.get(name) === current) {
      fallbackLockQueues.delete(name);
    }
  });
}

function base64Encode(bytes) {
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function base64Decode(text) {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function getDefaults() {
  return {
    [STORAGE_KEYS.profiles]: [],
    [STORAGE_KEYS.activeProfileId]: null,
    [STORAGE_KEYS.enabled]: false,
    [STORAGE_KEYS.cryptoKey]: null,
    [STORAGE_KEYS.lastError]: null,
    [STORAGE_KEYS.selectedProtocol]: 'auto',
    [STORAGE_KEYS.contentBlocking]: {
      tracking: false,
    },
  };
}

function normalizeScheme(scheme, fallback = 'http') {
  if (scheme === 'socks4') {
    return 'socks5';
  }
  return ['http', 'https', 'socks5'].includes(scheme) ? scheme : fallback;
}

function normalizeEndpoint(endpoint, fallbackScheme = 'http') {
  if (!endpoint || typeof endpoint !== 'object') {
    return null;
  }

  const host = normalizeProxyHost(endpoint.host);
  const port = normalizePort(endpoint.port);
  if (!host || !port) {
    return null;
  }

  return {
    scheme: normalizeScheme(endpoint.scheme, fallbackScheme),
    host,
    port,
  };
}

function buildAdvancedEndpoints(profile) {
  const proxyForHttp = normalizeEndpoint(profile.proxyForHttp, 'http');
  const proxyForHttps = normalizeEndpoint(profile.proxyForHttps, 'https');
  const socks = normalizeEndpoint(profile.socks, 'socks5');

  if (proxyForHttp || proxyForHttps || socks) {
    return {
      proxyForHttp: proxyForHttp ? { ...proxyForHttp, scheme: 'http' } : null,
      proxyForHttps: proxyForHttps ? { ...proxyForHttps, scheme: 'https' } : null,
      socks: socks ? { ...socks, scheme: 'socks5' } : null,
    };
  }

  const host = normalizeProxyHost(profile.host);
  const port = normalizePort(profile.port);
  if (!host || !port) {
    return { proxyForHttp: null, proxyForHttps: null, socks: null };
  }

  const scheme = normalizeScheme(profile.scheme);
  const endpoint = { scheme, host, port };
  if (scheme === 'socks5') {
    return { proxyForHttp: null, proxyForHttps: null, socks: { ...endpoint, scheme: 'socks5' } };
  }

  return {
    proxyForHttp: { ...endpoint, scheme: 'http' },
    proxyForHttps: { ...endpoint, scheme: 'https' },
    socks: null,
  };
}

export function normalizeProfile(profile) {
  const source = profile && typeof profile === 'object' && !Array.isArray(profile) ? profile : {};
  const advancedEndpoints = buildAdvancedEndpoints(source);

  return {
    id: typeof source.id === 'string' ? source.id : '',
    name: typeof source.name === 'string' ? source.name.trim() : '',
    proxyForHttp: advancedEndpoints.proxyForHttp,
    proxyForHttps: advancedEndpoints.proxyForHttps,
    socks: advancedEndpoints.socks,
    routingMode: ROUTING_MODES.has(source.routingMode) ? source.routingMode : 'all',
    proxyList: normalizeStringList(source.proxyList),
    killSwitch: source.killSwitch === true,
    bypassList: normalizeStringList(source.bypassList),
    bypassRussianResources: source.bypassRussianResources === true,
    bypassLocalNetworks: source.bypassLocalNetworks === true,
    blockList: normalizeStringList(source.blockList),
    note: typeof source.note === 'string' ? source.note.trim() : '',
    tags: normalizeStringList(source.tags),
    username: typeof source.username === 'string' ? source.username.trim() : '',
    password: typeof source.password === 'string' ? source.password : '',
  };
}

async function getStoredProfiles() {
  const data = await storageGet([STORAGE_KEYS.profiles]);
  return Array.isArray(data[STORAGE_KEYS.profiles])
    ? data[STORAGE_KEYS.profiles]
      .filter((profile) => profile && typeof profile === 'object' && !Array.isArray(profile))
    : [];
}

async function loadOrCreateCryptoKey() {
  return withStorageLock(CRYPTO_KEY_LOCK_NAME, async () => {
    const data = await storageGet([STORAGE_KEYS.cryptoKey]);
    if (data[STORAGE_KEYS.cryptoKey]) {
      const raw = base64Decode(data[STORAGE_KEYS.cryptoKey]);
      return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    }

    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    const raw = await crypto.subtle.exportKey('raw', key);
    await storageSet({
      [STORAGE_KEYS.cryptoKey]: base64Encode(new Uint8Array(raw)),
    });
    return key;
  });
}

function getCryptoKey() {
  if (!cryptoKeyPromise) {
    cryptoKeyPromise = loadOrCreateCryptoKey().catch((error) => {
      cryptoKeyPromise = null;
      throw error;
    });
  }
  return cryptoKeyPromise;
}

async function encryptPassword(plaintext) {
  if (!plaintext) {
    return '';
  }

  const key = await getCryptoKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(plaintext)
  );
  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encrypted), iv.length);
  return base64Encode(combined);
}

async function decryptPassword(b64) {
  if (!b64) {
    return '';
  }

  try {
    const key = await getCryptoKey();
    const bytes = base64Decode(b64);
    if (bytes.length <= 12) {
      throw new Error('Зашифрованный пароль повреждён.');
    }
    const iv = bytes.slice(0, 12);
    const ciphertext = bytes.slice(12);
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      ciphertext
    );
    return new TextDecoder().decode(decrypted);
  } catch (error) {
    console.warn('Unable to decrypt stored proxy password:', error);
    return '';
  }
}

async function decryptStoredProfile(profile) {
  const decryptedPassword = await decryptPassword(profile.password ?? '');
  return normalizeProfile({
    ...profile,
    password: decryptedPassword,
  });
}

async function encryptProfileForStorage(profile) {
  const password = await encryptPassword(profile.password ?? '');
  return normalizeProfile({
    ...profile,
    password,
  });
}

export async function getProfiles() {
  const profiles = await getStoredProfiles();
  return Promise.all(profiles.map((profile) => decryptStoredProfile(profile)));
}

export async function getProfileSummaries() {
  const profiles = await getStoredProfiles();
  return profiles.map((profile) => normalizeProfile({
    ...profile,
    password: '',
  }));
}

export async function getProfile(id) {
  if (!id) {
    return null;
  }

  const profiles = await getStoredProfiles();
  const profile = profiles.find((item) => item.id === id);
  return profile ? decryptStoredProfile(profile) : null;
}

export async function saveProfiles(profiles) {
  if (!Array.isArray(profiles)) {
    throw new TypeError('Профили должны быть массивом.');
  }
  if (profiles.length === 0) {
    return [];
  }

  const preparedProfiles = await Promise.all(profiles.map(async (profile) => {
    if (!profile || typeof profile !== 'object' || Array.isArray(profile)) {
      throw new TypeError('Каждый профиль должен быть объектом.');
    }
    const prepared = await encryptProfileForStorage(profile);
    return prepared.id
      ? prepared
      : {
          ...prepared,
          id: crypto.randomUUID(),
        };
  }));

  await withStorageLock(STATE_LOCK_NAME, async () => {
    const storedProfiles = await getStoredProfiles();
    const nextProfiles = [...storedProfiles];
    const indexById = new Map(nextProfiles.map((item, index) => [item.id, index]));
    for (const prepared of preparedProfiles) {
      const existingIndex = indexById.get(prepared.id);
      if (existingIndex === undefined) {
        indexById.set(prepared.id, nextProfiles.length);
        nextProfiles.push(prepared);
      } else {
        nextProfiles[existingIndex] = prepared;
      }
    }
    await storageSet({ [STORAGE_KEYS.profiles]: nextProfiles });
  });

  return preparedProfiles.map((prepared, index) => normalizeProfile({
    ...prepared,
    password: profiles[index].password,
  }));
}

export async function saveProfile(profile) {
  const [saved] = await saveProfiles([profile]);
  return saved;
}

export async function reorderProfiles(profileIds) {
  if (!Array.isArray(profileIds)) {
    throw new TypeError('Порядок профилей должен быть массивом идентификаторов.');
  }

  await withStorageLock(STATE_LOCK_NAME, async () => {
    const profiles = await getStoredProfiles();
    const uniqueIds = new Set(profileIds);
    if (uniqueIds.size !== profiles.length || uniqueIds.size !== profileIds.length) {
      throw new Error('Некорректный порядок профилей.');
    }

    const profilesById = new Map(profiles.map((profile) => [profile.id, profile]));
    const reorderedProfiles = profileIds.map((profileId) => profilesById.get(profileId));
    if (reorderedProfiles.some((profile) => !profile)) {
      throw new Error('Не удалось найти один из профилей.');
    }

    await storageSet({ [STORAGE_KEYS.profiles]: reorderedProfiles });
  });
}

export async function deleteProfile(id) {
  if (!id) {
    return;
  }

  await withStorageLock(STATE_LOCK_NAME, async () => {
    const data = await storageGet([STORAGE_KEYS.profiles, STORAGE_KEYS.activeProfileId]);
    const profiles = Array.isArray(data[STORAGE_KEYS.profiles]) ? data[STORAGE_KEYS.profiles] : [];
    const updates = {
      [STORAGE_KEYS.profiles]: profiles.filter((item) => item?.id !== id),
    };

    if (data[STORAGE_KEYS.activeProfileId] === id) {
      updates[STORAGE_KEYS.activeProfileId] = null;
    }

    await storageSet(updates);
  });
}

export async function getActiveProfileId() {
  const data = await storageGet([STORAGE_KEYS.activeProfileId]);
  return data[STORAGE_KEYS.activeProfileId] ?? null;
}

export async function getProxyState() {
  const data = await storageGet([
    STORAGE_KEYS.activeProfileId,
    STORAGE_KEYS.enabled,
    STORAGE_KEYS.lastError,
    STORAGE_KEYS.selectedProtocol,
  ]);
  const selectedProtocol = data[STORAGE_KEYS.selectedProtocol];
  return {
    activeProfileId: data[STORAGE_KEYS.activeProfileId] ?? null,
    enabled: Boolean(data[STORAGE_KEYS.enabled]),
    lastError: data[STORAGE_KEYS.lastError] ?? null,
    selectedProtocol: PROTOCOLS.has(selectedProtocol) ? selectedProtocol : 'auto',
  };
}

export async function setProxyState(state) {
  if (!state || typeof state !== 'object' || Array.isArray(state)) {
    throw new TypeError('Состояние прокси должно быть объектом.');
  }

  const updates = {};
  if (Object.hasOwn(state, 'activeProfileId')) {
    updates[STORAGE_KEYS.activeProfileId] = state.activeProfileId ?? null;
  }
  if (Object.hasOwn(state, 'enabled')) {
    updates[STORAGE_KEYS.enabled] = Boolean(state.enabled);
  }
  if (Object.hasOwn(state, 'lastError')) {
    updates[STORAGE_KEYS.lastError] = state.lastError ?? null;
  }
  if (Object.hasOwn(state, 'selectedProtocol')) {
    updates[STORAGE_KEYS.selectedProtocol] = PROTOCOLS.has(state.selectedProtocol)
      ? state.selectedProtocol
      : 'auto';
  }

  if (Object.keys(updates).length === 0) {
    return;
  }
  await withStorageLock(STATE_LOCK_NAME, () => storageSet(updates));
}

export async function getEnabled() {
  const data = await storageGet([STORAGE_KEYS.enabled]);
  return Boolean(data[STORAGE_KEYS.enabled]);
}

export async function setLastError(msg) {
  await setProxyState({ lastError: msg });
}

export async function getSelectedProtocol() {
  const data = await storageGet([STORAGE_KEYS.selectedProtocol]);
  const protocol = data[STORAGE_KEYS.selectedProtocol];
  return PROTOCOLS.has(protocol) ? protocol : 'auto';
}

export async function getContentBlockingSettings() {
  const data = await storageGet([STORAGE_KEYS.contentBlocking]);
  const settings = data[STORAGE_KEYS.contentBlocking];
  return {
    tracking: Boolean(settings?.tracking),
  };
}

export async function setContentBlockingSettings(settings) {
  await withStorageLock(STATE_LOCK_NAME, () => storageSet({
    [STORAGE_KEYS.contentBlocking]: {
      tracking: Boolean(settings?.tracking),
    },
  }));
}

export async function initializeDefaults() {
  await restrictLocalStorageAccess();
  await withStorageLock(STATE_LOCK_NAME, async () => {
    const data = await storageGet(Object.values(STORAGE_KEYS));
    const defaults = getDefaults();
    const updates = {};

    for (const key of Object.values(STORAGE_KEYS)) {
      if (!(key in data)) {
        updates[key] = defaults[key];
      }
    }

    const storedProfiles = Array.isArray(data[STORAGE_KEYS.profiles]) ? data[STORAGE_KEYS.profiles] : [];
    if (storedProfiles.some((profile) => profile && typeof profile === 'object' && Object.hasOwn(profile, 'color'))) {
      updates[STORAGE_KEYS.profiles] = storedProfiles.map((profile) => {
        if (!profile || typeof profile !== 'object') {
          return profile;
        }
        const { color: _removedColor, ...profileWithoutColor } = profile;
        return profileWithoutColor;
      });
    }

    if (Object.keys(updates).length > 0) {
      await storageSet(updates);
    }
  });
}
