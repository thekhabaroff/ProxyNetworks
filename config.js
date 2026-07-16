export const PROTOCOLS = Object.freeze(['auto', 'http', 'https', 'socks']);

const PROXY_SCHEMES = new Set(['http', 'https', 'socks5']);

function bypassEntryToAscii(entry) {
  if (typeof entry !== 'string') {
    return '';
  }

  const value = entry.trim();
  if (!value || !/[^\x00-\x7F]/.test(value)) {
    return value;
  }

  // Chrome accepts only ASCII URL patterns in proxy bypassList. Keep its
  // special tokens, wildcards and IP/CIDR entries intact while converting
  // internationalized domain names to their ASCII/Punycode form.
  const wildcard = value.startsWith('*.');
  const hostname = wildcard ? value.slice(2) : value;

  try {
    const asciiHostname = new URL(`http://${hostname}`).hostname;
    return wildcard ? `*.${asciiHostname}` : asciiHostname;
  } catch {
    // Leave malformed entries untouched so validation/error reporting can
    // still identify the value supplied by the user.
    return value;
  }
}

function normalizeBypassListForChrome(bypassList) {
  if (!Array.isArray(bypassList)) {
    return [];
  }

  return [...new Set(bypassList.map(bypassEntryToAscii).filter(Boolean))];
}

export function endpointToProxyServer(endpoint) {
  if (!endpoint || typeof endpoint.host !== 'string') {
    return null;
  }

  const host = endpoint.host.trim();
  const port = Number(endpoint.port);
  if (!host || /\s|\/|:\/\//.test(host) || !PROXY_SCHEMES.has(endpoint.scheme)
    || !Number.isInteger(port) || port < 1 || port > 65535) {
    return null;
  }

  return { scheme: endpoint.scheme, host, port };
}

export function buildProxyConfig(profile) {
  if (!profile) {
    return { mode: 'direct' };
  }

  const rules = {};
  const httpProxy = endpointToProxyServer(profile.proxyForHttp);
  const httpsProxy = endpointToProxyServer(profile.proxyForHttps);
  const socksProxy = endpointToProxyServer(profile.socks);

  if (httpProxy) rules.proxyForHttp = httpProxy;
  if (httpsProxy) rules.proxyForHttps = httpsProxy;
  if (socksProxy) rules.fallbackProxy = socksProxy;
  if (Array.isArray(profile.bypassList) && profile.bypassList.length > 0) {
    const bypassList = normalizeBypassListForChrome(profile.bypassList);
    if (bypassList.length > 0) rules.bypassList = bypassList;
  }

  return httpProxy || httpsProxy || socksProxy
    ? { mode: 'fixed_servers', rules }
    : { mode: 'direct' };
}

export function buildSelectedProxyConfig(profile, protocol = 'auto') {
  if (protocol === 'auto') {
    return buildProxyConfig(profile);
  }
  if (!PROTOCOLS.includes(protocol)) {
    throw new Error('Неизвестный протокол прокси.');
  }

  const endpoint = protocol === 'http'
    ? profile?.proxyForHttp
    : protocol === 'https'
      ? profile?.proxyForHttps
      : profile?.socks;
  const server = endpointToProxyServer(endpoint);
  if (!server) {
    throw new Error('Для выбранного протокола не настроен прокси.');
  }

  return {
    mode: 'fixed_servers',
    rules: {
      singleProxy: server,
      bypassList: normalizeBypassListForChrome(profile?.bypassList),
    },
  };
}
