// One item per feed. Source label is derived from the hostname later, so this list is all you edit.
const feeds = [
  ["BleepingComputer", "https://www.bleepingcomputer.com/feed/"],
  ["The Hacker News",  "https://feeds.feedburner.com/TheHackersNews"],
  ["AskWoody",         "https://www.askwoody.com/feed/"],
  ["ASD ACSC",         "https://www.cyber.gov.au/rss/alerts"],
  ["ASD ACSC",         "https://www.cyber.gov.au/rss/advisories"],
  ["CISA",             "https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml"],
  ["MSRC",             "https://api.msrc.microsoft.com/update-guide/rss"],
  ["Fortinet PSIRT",   "https://filestore.fortinet.com/fortiguard/rss/ir.xml"],
];
return feeds.map(([source, url]) => ({ json: { source, url } }));
