const STORAGE_KEYS = {
  profiles: 'profiles',
  activeProfileId: 'activeProfileId',
  enabled: 'enabled',
  cryptoKey: 'cryptoKey',
  lastError: 'lastError',
};

function storageGet(keys) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get(keys, (items) => {
      const error = chrome.runtime.lastError;
      if (error) {
        reject(new Error(error.message));
        return;
      }
      resolve(items);
    });
  });
}

function storageSet(items) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.set(items, () => {
      const error = chrome.runtime.lastError;
      if (error) {
        reject(new Error(error.message));
        return;
      }
      resolve();
    });
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
  };
}

function normalizeMode(mode) {
  return 'fixed_servers';
}

function normalizeScheme(scheme, fallback = 'http') {
  const allowedSchemes = ['http', 'https', 'socks4', 'socks5'];
  return allowedSchemes.includes(scheme) ? scheme : fallback;
}

function normalizePort(port) {
  const numericPort = Number(port);
  if (!Number.isInteger(numericPort) || numericPort < 1 || numericPort > 65535) {
    return 0;
  }
  return numericPort;
}

function normalizeHost(host) {
  return typeof host === 'string' ? host.trim() : '';
}

function normalizeBypassList(items) {
  if (typeof items === 'string') {
    return [...new Set(items.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean))];
  }

  if (!Array.isArray(items)) {
    return [];
  }

  return [...new Set(items.map((item) => String(item).trim()).filter(Boolean))];
}

function normalizeEndpoint(endpoint, fallbackScheme = 'http') {
  if (!endpoint || typeof endpoint !== 'object') {
    return null;
  }

  const host = normalizeHost(endpoint.host);
  const port = normalizePort(endpoint.port);
  if (!host && !port) {
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

  const host = normalizeHost(profile.host);
  const port = normalizePort(profile.port);
  if (!host || !port) {
    return { proxyForHttp: null, proxyForHttps: null, socks: null };
  }

  const scheme = normalizeScheme(profile.scheme);
  const endpoint = { scheme, host, port };
  if (scheme === 'socks4' || scheme === 'socks5') {
    return { proxyForHttp: null, proxyForHttps: null, socks: { ...endpoint, scheme: 'socks5' } };
  }

  return {
    proxyForHttp: { ...endpoint, scheme: 'http' },
    proxyForHttps: { ...endpoint, scheme: 'https' },
    socks: null,
  };
}

function normalizeStoredProfile(profile) {
  const advancedEndpoints = buildAdvancedEndpoints(profile);

  return {
    id: profile.id || '',
    name: profile.name ?? '',
    mode: normalizeMode(profile.mode),
    scheme: normalizeScheme(profile.scheme),
    host: normalizeHost(profile.host),
    port: normalizePort(profile.port),
    useAdvanced: true,
    proxyForHttp: advancedEndpoints.proxyForHttp,
    proxyForHttps: advancedEndpoints.proxyForHttps,
    socks: advancedEndpoints.socks,
    bypassList: normalizeBypassList(profile.bypassList),
    pacScript: profile.pacScript ?? '',
    username: profile.username ?? '',
    password: profile.password ?? '',
    incognito: false,
  };
}

function normalizeProfileForCaller(profile) {
  return normalizeStoredProfile(profile);
}

async function getStoredProfiles() {
  const data = await storageGet([STORAGE_KEYS.profiles]);
  return Array.isArray(data[STORAGE_KEYS.profiles]) ? data[STORAGE_KEYS.profiles] : [];
}

export async function getCryptoKey() {
  const data = await storageGet([STORAGE_KEYS.cryptoKey]);
  if (data[STORAGE_KEYS.cryptoKey]) {
    const raw = base64Decode(data[STORAGE_KEYS.cryptoKey]);
    return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  }

  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  const raw = await crypto.subtle.exportKey('raw', key);
  const base64 = base64Encode(new Uint8Array(raw));
  await storageSet({ [STORAGE_KEYS.cryptoKey]: base64 });
  return key;
}

export async function encryptPassword(plaintext) {
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

export async function decryptPassword(b64) {
  if (!b64) {
    return '';
  }

  try {
    const key = await getCryptoKey();
    const bytes = base64Decode(b64);
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
  return normalizeProfileForCaller({
    ...profile,
    password: decryptedPassword,
  });
}

async function encryptProfileForStorage(profile) {
  const password = await encryptPassword(profile.password ?? '');
  return normalizeStoredProfile({
    ...profile,
    password,
  });
}

export async function getProfiles() {
  const profiles = await getStoredProfiles();
  return Promise.all(profiles.map((profile) => decryptStoredProfile(profile)));
}

export async function getProfile(id) {
  if (!id) {
    return null;
  }

  const profiles = await getStoredProfiles();
  const profile = profiles.find((item) => item.id === id);
  return profile ? decryptStoredProfile(profile) : null;
}

export async function saveProfile(profile) {
  const profiles = await getStoredProfiles();
  const prepared = await encryptProfileForStorage(profile);
  const saved = prepared.id
    ? prepared
    : {
        ...prepared,
        id: crypto.randomUUID(),
      };

  const nextProfiles = profiles.filter((item) => item.id !== saved.id);
  nextProfiles.push(saved);
  await storageSet({ [STORAGE_KEYS.profiles]: nextProfiles });
  return decryptStoredProfile(saved);
}

export async function deleteProfile(id) {
  if (!id) {
    return;
  }

  const data = await storageGet([STORAGE_KEYS.profiles, STORAGE_KEYS.activeProfileId]);
  const profiles = Array.isArray(data[STORAGE_KEYS.profiles]) ? data[STORAGE_KEYS.profiles] : [];
  const nextProfiles = profiles.filter((item) => item.id !== id);
  const updates = { [STORAGE_KEYS.profiles]: nextProfiles };

  if (data[STORAGE_KEYS.activeProfileId] === id) {
    updates[STORAGE_KEYS.activeProfileId] = null;
  }

  await storageSet(updates);
}

export async function getActiveProfileId() {
  const data = await storageGet([STORAGE_KEYS.activeProfileId]);
  return data[STORAGE_KEYS.activeProfileId] ?? null;
}

export async function setActiveProfileId(id) {
  await storageSet({ [STORAGE_KEYS.activeProfileId]: id ?? null });
}

export async function getEnabled() {
  const data = await storageGet([STORAGE_KEYS.enabled]);
  return Boolean(data[STORAGE_KEYS.enabled]);
}

export async function setEnabled(value) {
  await storageSet({ [STORAGE_KEYS.enabled]: Boolean(value) });
}

export async function getLastError() {
  const data = await storageGet([STORAGE_KEYS.lastError]);
  return data[STORAGE_KEYS.lastError] ?? null;
}

export async function setLastError(msg) {
  await storageSet({ [STORAGE_KEYS.lastError]: msg ?? null });
}

export async function initializeDefaults() {
  const data = await storageGet(Object.values(STORAGE_KEYS));
  const defaults = getDefaults();
  const updates = {};

  for (const key of Object.values(STORAGE_KEYS)) {
    if (!(key in data)) {
      updates[key] = defaults[key];
    }
  }

  if (Object.keys(updates).length > 0) {
    await storageSet(updates);
  }
}
