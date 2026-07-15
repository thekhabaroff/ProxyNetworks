export const PROTOCOLS = Object.freeze(['auto', 'http', 'https', 'socks']);

const PROXY_SCHEMES = new Set(['http', 'https', 'socks5']);

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
    rules.bypassList = profile.bypassList;
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
      bypassList: Array.isArray(profile.bypassList) ? profile.bypassList : [],
    },
  };
}
