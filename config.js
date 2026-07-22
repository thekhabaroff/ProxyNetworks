import {
  isValidProxyHost,
  normalizePort,
  normalizeProxyHost,
} from './utils.js';

export const PROTOCOLS = Object.freeze(['auto', 'http', 'https', 'socks']);

const PROXY_SCHEMES = new Set(['http', 'https', 'socks5']);
const MAX_PAC_SCRIPT_LENGTH = 4 * 1024 * 1024;
const INTERNAL_PROXY_PROBE_HOSTS = Object.freeze(['api.ipify.org']);
const PROFILE_ENDPOINT_KEYS = Object.freeze({
  http: 'proxyForHttp',
  https: 'proxyForHttps',
  socks: 'socks',
});

export function getProfileEndpoint(profile, protocol) {
  const key = PROFILE_ENDPOINT_KEYS[protocol];
  return key ? profile?.[key] ?? null : null;
}

export function getConfiguredProtocols(profile) {
  return Object.keys(PROFILE_ENDPOINT_KEYS)
    .filter((protocol) => Boolean(endpointToProxyServer(getProfileEndpoint(profile, protocol))));
}

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

function proxyServerToPacDirective(server) {
  if (!server) {
    return '';
  }

  const directive = {
    http: 'PROXY',
    https: 'HTTPS',
    socks5: 'SOCKS5',
  }[server.scheme];
  const host = server.host.includes(':') ? `[${server.host}]` : server.host;
  return directive ? `${directive} ${host}:${server.port}` : '';
}

function buildPacProxyPlan(profile, protocol) {
  if (protocol !== 'auto') {
    const directive = proxyServerToPacDirective(
      endpointToProxyServer(getProfileEndpoint(profile, protocol)),
    );
    return { http: directive, https: directive, other: directive };
  }

  const http = proxyServerToPacDirective(endpointToProxyServer(profile?.proxyForHttp));
  const https = proxyServerToPacDirective(endpointToProxyServer(profile?.proxyForHttps));
  const socks = proxyServerToPacDirective(endpointToProxyServer(profile?.socks));
  return {
    http: http || https || socks,
    https: https || http || socks,
    other: socks || https || http,
  };
}

function compilePacRuleSet(entries) {
  const domains = new Set();
  const patterns = new Set();
  const cidrs = new Set();
  let local = false;

  for (const entry of entries) {
    const value = String(entry ?? '').trim().toLowerCase();
    if (!value) continue;
    if (value === '<local>') {
      local = true;
    } else if (value.includes('/')) {
      cidrs.add(value);
    } else if (value.startsWith('*.')) {
      domains.add(value.slice(2));
    } else if (value.includes('*')) {
      patterns.add(value);
    } else {
      domains.add(value);
    }
  }

  return {
    domains: [...domains],
    patterns: [...patterns],
    cidrs: [...cidrs],
    local,
  };
}

function buildPacScript(profile, protocol) {
  const selectedOnly = profile?.routingMode === 'selected';
  const routeList = normalizeBypassListForChrome(profile?.proxyList);
  const bypassList = normalizeBypassListForChrome(profile?.bypassList);
  if (selectedOnly && routeList.length === 0) {
    throw new Error('Добавьте хотя бы один сайт для выборочной маршрутизации.');
  }
  if (selectedOnly) {
    routeList.push(...INTERNAL_PROXY_PROBE_HOSTS.filter((host) => !routeList.includes(host)));
  }
  const routeRules = compilePacRuleSet(routeList);
  const bypassRules = compilePacRuleSet(bypassList);

  const plan = buildPacProxyPlan(profile, protocol);
  if (!plan.http && !plan.https && !plan.other) {
    throw new Error('В профиле не настроен ни один прокси.');
  }
  const directFallback = selectedOnly && !profile?.killSwitch ? '; DIRECT' : '';
  const directives = {
    http: `${plan.http}${directFallback}`,
    https: `${plan.https}${directFallback}`,
    other: `${plan.other}${directFallback}`,
  };

  const script = `
var ROUTE_DOMAINS = ${JSON.stringify(routeRules.domains)};
var ROUTE_PATTERNS = ${JSON.stringify(routeRules.patterns)};
var ROUTE_CIDRS = ${JSON.stringify(routeRules.cidrs)};
var ROUTE_LOCAL = ${routeRules.local ? 'true' : 'false'};
var BYPASS_DOMAINS = ${JSON.stringify(bypassRules.domains)};
var BYPASS_PATTERNS = ${JSON.stringify(bypassRules.patterns)};
var BYPASS_CIDRS = ${JSON.stringify(bypassRules.cidrs)};
var BYPASS_LOCAL = ${bypassRules.local ? 'true' : 'false'};
var SELECTED_ONLY = ${selectedOnly ? 'true' : 'false'};
var PROXY_HTTP = ${JSON.stringify(directives.http)};
var PROXY_HTTPS = ${JSON.stringify(directives.https)};
var PROXY_OTHER = ${JSON.stringify(directives.other)};

function ipv4Mask(prefix) {
  var bits = Number(prefix);
  if (bits < 0 || bits > 32) return '';
  var octets = [];
  for (var i = 0; i < 4; i += 1) {
    var remaining = Math.max(0, Math.min(8, bits - i * 8));
    octets.push(remaining === 0 ? 0 : 256 - Math.pow(2, 8 - remaining));
  }
  return octets.join('.');
}

function matchesCidr(host, rule) {
  var parts = rule.split('/');
  if (parts.length !== 2) return false;
  if (parts[0].indexOf(':') >= 0) {
    var ipv6 = host.replace(/^\\[|\\]$/g, '').toLowerCase();
    if (rule === '::1/128') return ipv6 === '::1';
    if (rule === 'fc00::/7') return ipv6.indexOf('fc') === 0 || ipv6.indexOf('fd') === 0;
    if (rule === 'fe80::/10') return /^(fe8|fe9|fea|feb)/.test(ipv6);
    return false;
  }
  var mask = ipv4Mask(parts[1]);
  return Boolean(mask) && isInNet(host, parts[0], mask);
}

function makeDomainMap(domains) {
  var map = {};
  for (var i = 0; i < domains.length; i += 1) map['@' + domains[i]] = true;
  return map;
}

var ROUTE_DOMAIN_MAP = makeDomainMap(ROUTE_DOMAINS);
var BYPASS_DOMAIN_MAP = makeDomainMap(BYPASS_DOMAINS);

function matchesDomain(host, domainMap) {
  var candidate = host;
  while (candidate) {
    if (domainMap['@' + candidate]) return true;
    var dot = candidate.indexOf('.');
    if (dot < 0) break;
    candidate = candidate.slice(dot + 1);
  }
  return false;
}

function matchesRuleSet(host, domainMap, patterns, cidrs, local) {
  if (local && isPlainHostName(host)) return true;
  if (matchesDomain(host, domainMap)) return true;
  for (var i = 0; i < patterns.length; i += 1) {
    if (shExpMatch(host, patterns[i])) return true;
  }
  for (var j = 0; j < cidrs.length; j += 1) {
    if (matchesCidr(host, cidrs[j])) return true;
  }
  return false;
}

function FindProxyForURL(url, host) {
  host = String(host || '').replace(/\\.$/, '').toLowerCase();
  if (matchesRuleSet(host, BYPASS_DOMAIN_MAP, BYPASS_PATTERNS, BYPASS_CIDRS, BYPASS_LOCAL)) return 'DIRECT';
  if (SELECTED_ONLY && !matchesRuleSet(host, ROUTE_DOMAIN_MAP, ROUTE_PATTERNS, ROUTE_CIDRS, ROUTE_LOCAL)) return 'DIRECT';
  if (url.indexOf('https:') === 0 || url.indexOf('wss:') === 0) return PROXY_HTTPS;
  if (url.indexOf('http:') === 0 || url.indexOf('ws:') === 0) return PROXY_HTTP;
  return PROXY_OTHER;
}`.trim();

  if (script.length > MAX_PAC_SCRIPT_LENGTH) {
    throw new Error('Список маршрутизации слишком велик для безопасного PAC-скрипта Chrome.');
  }
  return script;
}

function buildPacProxyConfig(profile, protocol) {
  return {
    mode: 'pac_script',
    pacScript: {
      data: buildPacScript(profile, protocol),
      mandatory: profile?.killSwitch === true,
    },
  };
}

function addBypassList(rules, bypassList) {
  const normalized = normalizeBypassListForChrome(bypassList);
  if (normalized.length > 0) {
    rules.bypassList = normalized;
  }
  return rules;
}

export function endpointToProxyServer(endpoint) {
  if (!endpoint || typeof endpoint.host !== 'string') {
    return null;
  }

  const host = normalizeProxyHost(endpoint.host);
  const port = normalizePort(endpoint.port);
  if (!isValidProxyHost(host) || !PROXY_SCHEMES.has(endpoint.scheme) || !port) {
    return null;
  }

  return { scheme: endpoint.scheme, host, port };
}

function buildProxyConfig(profile) {
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
  addBypassList(rules, profile.bypassList);

  return httpProxy || httpsProxy || socksProxy
    ? { mode: 'fixed_servers', rules }
    : { mode: 'direct' };
}

export function buildSelectedProxyConfig(profile, protocol = 'auto') {
  if (profile?.routingMode === 'selected' || profile?.killSwitch === true) {
    if (!PROTOCOLS.includes(protocol)) {
      throw new Error('Неизвестный протокол прокси.');
    }
    return buildPacProxyConfig(profile, protocol);
  }

  if (protocol === 'auto') {
    return buildProxyConfig(profile);
  }
  if (!PROTOCOLS.includes(protocol)) {
    throw new Error('Неизвестный протокол прокси.');
  }

  const endpoint = getProfileEndpoint(profile, protocol);
  const server = endpointToProxyServer(endpoint);
  if (!server) {
    throw new Error('Для выбранного протокола не настроен прокси.');
  }

  return {
    mode: 'fixed_servers',
    rules: addBypassList({
      singleProxy: server,
    }, profile?.bypassList),
  };
}
