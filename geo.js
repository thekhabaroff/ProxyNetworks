import {
  errorMessage,
  normalizeProxyHost,
  storageGet,
  storageSet,
} from './utils.js';
import {
  endpointToProxyServer,
  getProfileEndpoint,
} from './config.js';

const GEO_CACHE_KEY = 'proxyGeoCache';
const GEO_CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const GEO_CACHE_LIMIT = 200;
const LOOKUP_TIMEOUT_MS = 12000;
const inFlightLookups = new Map();
let cachePromise = null;
let cacheWriteQueue = Promise.resolve();

const PROTOCOL_LABELS = Object.freeze({
  http: 'HTTP',
  https: 'HTTPS',
  socks: 'SOCKS5',
});

function countryFlag(countryCode) {
  if (!/^[A-Z]{2}$/.test(countryCode)) {
    return '🌐';
  }
  return String.fromCodePoint(...[...countryCode].map((letter) => 127397 + letter.codePointAt(0)));
}

function isIpv4(value) {
  const parts = value.split('.');
  return parts.length === 4
    && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

function isIpv6(value) {
  return value.includes(':') && !/[\s/?#@\\]/.test(value);
}

function isPrivateOrLocalHost(host) {
  const value = host.toLowerCase();
  if (value === 'localhost' || value.endsWith('.localhost') || value.endsWith('.local')) {
    return true;
  }
  if (!isIpv4(value)) {
    return value === '::1'
      || value.startsWith('fc')
      || value.startsWith('fd')
      || /^fe[89ab]/.test(value);
  }
  const [first, second] = value.split('.').map(Number);
  return first === 10
    || first === 127
    || (first === 169 && second === 254)
    || (first === 172 && second >= 16 && second <= 31)
    || (first === 192 && second === 168);
}

function resolveProfileEndpoint(profile, protocol = 'auto') {
  let resolvedProtocol = protocol;
  if (protocol === 'auto') {
    resolvedProtocol = ['https', 'http', 'socks']
      .find((candidate) => endpointToProxyServer(getProfileEndpoint(profile, candidate))) ?? 'auto';
  }
  const endpoint = endpointToProxyServer(getProfileEndpoint(profile, resolvedProtocol));
  return endpoint
    ? { endpoint, protocol: resolvedProtocol, label: PROTOCOL_LABELS[resolvedProtocol] ?? 'Прокси' }
    : null;
}

function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), LOOKUP_TIMEOUT_MS);
  return fetch(url, { ...options, cache: 'no-store', signal: controller.signal })
    .finally(() => clearTimeout(timeoutId));
}

async function resolveDns(host, type) {
  const response = await fetchWithTimeout(
    `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=${type}`,
    { headers: { accept: 'application/dns-json' } },
  );
  if (!response.ok) {
    throw new Error(`DNS-запрос вернул HTTP ${response.status}.`);
  }
  const payload = await response.json();
  const answer = Array.isArray(payload?.Answer)
    ? payload.Answer.find((item) => item?.type === type && typeof item.data === 'string')
    : null;
  return answer?.data ?? null;
}

async function resolveHostToIp(host) {
  if (isIpv4(host) || isIpv6(host)) {
    return host;
  }

  try {
    const ipv4 = await resolveDns(host, 1);
    if (ipv4 && isIpv4(ipv4)) {
      return ipv4;
    }
  } catch (error) {
    console.warn('Unable to resolve proxy hostname via IPv4 DNS:', error);
  }

  const ipv6 = await resolveDns(host, 28);
  if (ipv6 && isIpv6(ipv6)) {
    return ipv6;
  }
  throw new Error('Не удалось получить IP-адрес прокси-сервера.');
}

async function getCache() {
  if (!cachePromise) {
    cachePromise = storageGet([GEO_CACHE_KEY])
      .then((data) => (data[GEO_CACHE_KEY] && typeof data[GEO_CACHE_KEY] === 'object'
        ? data[GEO_CACHE_KEY]
        : {}))
      .catch((error) => {
        cachePromise = null;
        throw error;
      });
  }
  return cachePromise;
}

async function saveCache(cache) {
  const task = cacheWriteQueue.then(async () => {
    const entries = Object.entries(cache)
      .filter(([, value]) => value && typeof value === 'object')
      .sort(([, left], [, right]) => Number(right.updatedAt ?? 0) - Number(left.updatedAt ?? 0))
      .slice(0, GEO_CACHE_LIMIT);
    const nextCache = Object.fromEntries(entries);
    await storageSet({ [GEO_CACHE_KEY]: nextCache });
    cachePromise = Promise.resolve(nextCache);
  });
  cacheWriteQueue = task.catch(() => undefined);
  return task;
}

function isFresh(entry) {
  return Boolean(entry?.updatedAt) && Date.now() - entry.updatedAt < GEO_CACHE_TTL_MS;
}

function normalizeGeoResponse(payload, host, ip) {
  if (!payload?.success) {
    throw new Error(payload?.message || 'Сервис геолокации не вернул данные.');
  }
  const countryCode = typeof payload.country_code === 'string'
    ? payload.country_code.toUpperCase()
    : '';
  const provider = payload.connection?.isp || payload.connection?.org || payload.connection?.domain || '';
  return {
    host,
    ip,
    country: typeof payload.country === 'string' ? payload.country : 'Неизвестная страна',
    countryCode,
    flag: typeof payload.flag?.emoji === 'string' && payload.flag.emoji ? payload.flag.emoji : countryFlag(countryCode),
    city: typeof payload.city === 'string' && payload.city ? payload.city : 'Город не указан',
    provider: typeof provider === 'string' && provider ? provider : 'Провайдер не указан',
    updatedAt: Date.now(),
  };
}

async function lookupGeo(host, forceRefresh) {
  const cache = await getCache();
  const cached = cache[host];
  if (!forceRefresh && isFresh(cached)) {
    return cached;
  }

  if (inFlightLookups.has(host)) {
    return inFlightLookups.get(host);
  }

  const task = (async () => {
    const ip = await resolveHostToIp(host);
    const response = await fetchWithTimeout(`https://ipwho.is/${encodeURIComponent(ip)}?lang=ru`);
    if (!response.ok) {
      throw new Error(`Сервис геолокации вернул HTTP ${response.status}.`);
    }
    const geo = normalizeGeoResponse(await response.json(), host, ip);
    cache[host] = geo;
    await saveCache(cache);
    return geo;
  })();
  inFlightLookups.set(host, task);
  try {
    return await task;
  } finally {
    inFlightLookups.delete(host);
  }
}

export async function getProfileProxyGeo(profile, protocol = 'auto', forceRefresh = false) {
  const resolved = resolveProfileEndpoint(profile, protocol);
  if (!resolved) {
    return { geo: null, error: 'В профиле нет прокси для выбранного протокола.' };
  }

  const host = normalizeProxyHost(resolved.endpoint.host).toLowerCase();
  if (isPrivateOrLocalHost(host)) {
    return {
      ...resolved,
      geo: null,
      error: 'Для локального адреса геолокация недоступна.',
    };
  }

  try {
    return {
      ...resolved,
      geo: await lookupGeo(host, forceRefresh),
      error: null,
    };
  } catch (error) {
    return {
      ...resolved,
      geo: null,
      error: errorMessage(error),
    };
  }
}
