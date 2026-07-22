import {
  errorMessage,
  normalizeDomain,
  storageGet,
  storageSet,
} from './utils.js';

const GEOSITE_SOURCE = 'https://raw.githubusercontent.com/v2fly/domain-list-community/master/data';
const GEOSITE_CACHE_KEY = 'geositeCache';
const GEOSITE_CACHE_VERSION = 2;
const GEOSITE_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const GEOSITE_NAME_PATTERN = /^[a-z0-9][a-z0-9.!_-]*$/i;
const FETCH_TIMEOUT_MS = 15000;
const MAX_SOURCE_LENGTH = 10 * 1024 * 1024;
// Chrome 108–113 allow roughly 5 MB in storage.local. Keep the cache below
// that limit so profiles and encrypted credentials always have room.
const MAX_CACHE_BYTES = 4 * 1024 * 1024;
const inFlightLoads = new Map();
let cachePromise = null;

function isFresh(cacheEntry) {
  return cacheEntry?.version === GEOSITE_CACHE_VERSION
    && Boolean(cacheEntry?.updatedAt)
    && Date.now() - cacheEntry.updatedAt < GEOSITE_CACHE_TTL_MS;
}

function parseRuleLine(line) {
  const content = line.replace(/#.*$/, '').trim();
  if (!content) {
    return [];
  }

  const rules = [];
  for (const token of content.split(/\s+/)) {
    if (!token) continue;
    if (token.startsWith('@') || token.startsWith('&')) {
      if (rules.length && token.startsWith('@')) {
        rules[rules.length - 1].attributes.push(token);
      }
      continue;
    }
    if (token.startsWith('include:')) {
      rules.push({ type: 'include', name: token.slice('include:'.length), attributes: [] });
      continue;
    }
    if (token.startsWith('keyword:') || token.startsWith('regexp:')) {
      rules.push({ type: 'unsupported', attributes: [] });
      continue;
    }

    const type = token.startsWith('full:') ? 'full' : 'domain';
    rules.push({
      type,
      domain: token.replace(/^(?:full:|domain:)/, ''),
      attributes: [],
    });
  }
  return rules;
}

function matchesAttributes(attributes, filters) {
  if (!Array.isArray(filters) || filters.length === 0) {
    return true;
  }

  const available = new Set(Array.isArray(attributes) ? attributes : []);
  return filters.every((filter) => {
    const name = filter.replace(/^@/, '');
    if (name.startsWith('!') || name.startsWith('-')) {
      return !available.has(`@${name.slice(1)}`);
    }
    return available.has(`@${name}`);
  });
}

async function fetchListText(name) {
  if (!GEOSITE_NAME_PATTERN.test(name)) {
    throw new Error(`Некорректное имя geosite-базы: ${name}`);
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const response = await fetch(`${GEOSITE_SOURCE}/${encodeURIComponent(name)}`, {
      cache: 'no-store',
      signal: controller.signal,
    });
    if (!response.ok) {
      const error = new Error(`Geosite-база «${name}» не найдена (HTTP ${response.status}).`);
      error.status = response.status;
      throw error;
    }
    const contentLength = Number(response.headers.get('content-length'));
    if (Number.isFinite(contentLength) && contentLength > MAX_SOURCE_LENGTH) {
      throw new Error(`Geosite-база «${name}» превышает допустимый размер.`);
    }
    const text = await response.text();
    if (text.length > MAX_SOURCE_LENGTH) {
      throw new Error(`Geosite-база «${name}» превышает допустимый размер.`);
    }
    return text;
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw new Error(`Загрузка geosite-базы «${name}» превысила 15 секунд.`);
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function getCache() {
  if (!cachePromise) {
    cachePromise = storageGet([GEOSITE_CACHE_KEY])
      .then((data) => (
        data[GEOSITE_CACHE_KEY] && typeof data[GEOSITE_CACHE_KEY] === 'object'
          ? data[GEOSITE_CACHE_KEY]
          : {}
      ))
      .catch((error) => {
        cachePromise = null;
        throw error;
      });
  }
  return cachePromise;
}

async function setCache(cache) {
  const encoder = new TextEncoder();
  const entries = Object.entries(cache && typeof cache === 'object' ? cache : {})
    .filter(([, entry]) => entry && typeof entry === 'object')
    .sort(([, left], [, right]) => Number(right.updatedAt ?? 0) - Number(left.updatedAt ?? 0));
  const prunedCache = {};
  let estimatedBytes = 2;
  for (const [name, entry] of entries) {
    const entryBytes = encoder.encode(`${JSON.stringify(name)}:${JSON.stringify(entry)},`).byteLength;
    if (estimatedBytes + entryBytes > MAX_CACHE_BYTES) {
      continue;
    }
    prunedCache[name] = entry;
    estimatedBytes += entryBytes;
  }

  await storageSet({ [GEOSITE_CACHE_KEY]: prunedCache });
  cachePromise = Promise.resolve(prunedCache);
}

async function loadGeosite(name, options = {}) {
  const {
    forceRefresh = false,
    cache = null,
    stack = new Set(),
    filters = [],
  } = options;
  if (stack.has(name)) {
    throw new Error(`Обнаружено циклическое включение geosite-базы «${name}».`);
  }

  const key = `${name}|${forceRefresh ? 'refresh' : 'cache'}|${filters.join(',')}`;
  if (inFlightLoads.has(key)) {
    return inFlightLoads.get(key);
  }

  const promise = loadGeositeInternal(name, options);
  inFlightLoads.set(key, promise);
  try {
    return await promise;
  } finally {
    inFlightLoads.delete(key);
  }
}

async function loadGeositeInternal(name, {
  forceRefresh = false,
  cache = null,
  stack = new Set(),
  filters = [],
} = {}) {
  if (!GEOSITE_NAME_PATTERN.test(name)) {
    throw new Error(`Некорректное имя geosite-базы: ${name}`);
  }
  const currentCache = cache || await getCache();
  const cached = currentCache[name];
  if (filters.length === 0 && !forceRefresh && cached?.domains?.length && isFresh(cached)) {
    return cached.domains;
  }

  let text;
  try {
    text = await fetchListText(name);
  } catch (error) {
    if (!forceRefresh && filters.length === 0 && cached?.domains?.length) {
      return cached.domains;
    }
    throw error;
  }

  const domains = new Set();
  const nextStack = new Set(stack).add(name);
  const includeTasks = [];
  for (const line of text.split(/\r?\n/)) {
    for (const rule of parseRuleLine(line)) {
      if (rule.type === 'include' && rule.name) {
        includeTasks.push((async () => {
          try {
            return await loadGeosite(rule.name, {
              forceRefresh,
              cache: currentCache,
              stack: nextStack,
              filters: rule.attributes.length > 0 ? rule.attributes : filters,
            });
          } catch (error) {
            // Some upstream lists contain selector-style includes such as
            // "name-!cn". They are meaningful to the geosite generator but
            // may not exist as standalone files in the data directory.
            if (error?.status === 404) {
              console.warn(`Вложенная geosite-база «${rule.name}» отсутствует и будет пропущена.`);
              return [];
            }
            throw error;
          }
        })());
        continue;
      }
      if (rule.type !== 'domain' && rule.type !== 'full') {
        continue;
      }
      if (!matchesAttributes(rule.attributes, filters)) {
        continue;
      }

      const domain = normalizeDomain(rule.domain);
      if (!domain) {
        continue;
      }
      domains.add(domain);
      if (rule.type === 'domain') {
        domains.add(`*.${domain}`);
      }
    }
  }
  let includedLists;
  try {
    includedLists = await Promise.all(includeTasks);
  } catch (error) {
    if (!forceRefresh && filters.length === 0 && cached?.domains?.length) {
      return cached.domains;
    }
    throw error;
  }
  for (const included of includedLists) {
    included.forEach((domain) => domains.add(domain));
  }

  const result = [...domains];
  if (filters.length === 0) {
    currentCache[name] = {
      version: GEOSITE_CACHE_VERSION,
      domains: result,
      updatedAt: Date.now(),
    };
  }
  return result;
}

export function geositeNameFromEntry(entry) {
  if (typeof entry !== 'string') {
    return null;
  }
  const match = entry.trim().match(/^geosite:([a-z0-9][a-z0-9.!_-]*)$/i);
  return match?.[1] ?? null;
}

export async function resolveGeositeDomainList(entries) {
  if (!Array.isArray(entries)) {
    return [];
  }

  for (const entry of entries) {
    const value = typeof entry === 'string' ? entry.trim() : '';
    if (/^geosite:/i.test(value) && !geositeNameFromEntry(value)) {
      throw new Error(`Некорректное имя geosite-базы: ${value.slice('geosite:'.length) || 'пустое имя'}`);
    }
  }

  const geositeEntries = entries.filter((entry) => geositeNameFromEntry(entry));
  if (geositeEntries.length === 0) {
    return [...new Set(entries)];
  }

  const cache = await getCache();
  const resolvedLists = await Promise.all(entries.map(async (entry) => {
    const name = geositeNameFromEntry(entry);
    if (!name) {
      return [entry];
    }
    return loadGeosite(name, { cache });
  }));
  await setCache(cache);
  return [...new Set(resolvedLists.flat())];
}

export function geositeNamesFromProfiles(profiles) {
  const names = new Set();
  for (const profile of Array.isArray(profiles) ? profiles : []) {
    for (const list of [profile?.proxyList, profile?.bypassList, profile?.blockList]) {
      for (const entry of Array.isArray(list) ? list : []) {
        const name = geositeNameFromEntry(entry);
        if (name) names.add(name);
      }
    }
  }
  return [...names];
}

export async function getGeositeCacheStatus(names) {
  const cache = await getCache();
  return [...new Set(Array.isArray(names) ? names : [])]
    .filter((name) => GEOSITE_NAME_PATTERN.test(name))
    .map((name) => {
      const entry = cache[name];
      return {
        name,
        cached: Array.isArray(entry?.domains) && entry.domains.length > 0,
        domains: Array.isArray(entry?.domains) ? entry.domains.length : 0,
        updatedAt: Number(entry?.updatedAt) || null,
        fresh: isFresh(entry),
      };
    });
}

export async function refreshGeositeCaches(names) {
  const cache = await getCache();
  const uniqueNames = [...new Set(Array.isArray(names) ? names : [])];
  const results = await Promise.all(uniqueNames.map(async (name) => {
    try {
      await loadGeosite(name, { forceRefresh: true, cache });
      return { name, error: null };
    } catch (error) {
      return { name, error: errorMessage(error) };
    }
  }));
  const refreshed = [];
  const failed = [];
  for (const result of results) {
    if (result.error === null) {
      const { name } = result;
      refreshed.push(name);
    } else {
      failed.push(result);
    }
  }
  if (refreshed.length > 0) {
    await setCache(cache);
  }
  return { refreshed, failed };
}
