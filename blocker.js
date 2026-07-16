import { resolveGeositeBypassList } from './geosite.js';

const BLOCK_RULE_ID_START = 1000000;
const MAX_BLOCK_RULES = 30000;
const BUILT_IN_BLOCK_LISTS = {
  tracking: 'geosite:category-public-tracker',
};

function domainToAscii(entry) {
  if (typeof entry !== 'string') {
    return null;
  }

  let value = entry.trim();
  if (!value || value.startsWith('<') || value.includes('/')) {
    return null;
  }
  value = value.replace(/^\*\./, '').replace(/^\.+/, '').replace(/\.$/, '');

  try {
    return new URL(`http://${value}`).hostname;
  } catch {
    return null;
  }
}

function buildBlockRules(entries) {
  const domains = [...new Set(entries.map(domainToAscii).filter(Boolean))];
  if (domains.length > MAX_BLOCK_RULES) {
    throw new Error(`Список блокировки содержит ${domains.length} доменов. Лимит Chrome — ${MAX_BLOCK_RULES}.`);
  }

  return domains.map((domain, index) => ({
    id: BLOCK_RULE_ID_START + index,
    priority: 1,
    action: { type: 'block' },
    condition: {
      urlFilter: `||${domain}^`,
      resourceTypes: [
        'main_frame',
        'sub_frame',
        'stylesheet',
        'script',
        'image',
        'font',
        'object',
        'xmlhttprequest',
        'ping',
        'media',
        'websocket',
        'other',
      ],
    },
  }));
}

export async function updateBlockRules(blockList = [], settings = {}) {
  const builtInList = [];
  if (settings.tracking) builtInList.push(BUILT_IN_BLOCK_LISTS.tracking);
  const expandedList = await resolveGeositeBypassList([...blockList, ...builtInList]);
  const rules = buildBlockRules(expandedList);
  const allRules = rules.map((rule, index) => ({
    ...rule,
    id: BLOCK_RULE_ID_START + index,
  }));
  const currentRules = await chrome.declarativeNetRequest.getDynamicRules();
  // This extension owns the whole dynamic ruleset. Remove every existing
  // dynamic rule so rules created by an older version cannot survive after
  // the user disables blocking or reloads the unpacked extension.
  const managedRuleIds = currentRules.map((rule) => rule.id);

  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: managedRuleIds,
    addRules: allRules,
  });

  return allRules.length;
}
