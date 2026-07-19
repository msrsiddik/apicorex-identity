import { api } from "./api";
import type { PluginEntry } from "./types";

// Core's live plugin registry (currently-connected plugins). Used both by the
// Plugins tab and to populate plugin-name dropdowns elsewhere. Cached per page
// load — plugins don't come and go often enough to justify refetching on every
// render; call clearPluginCache() (the Plugins tab's Refresh) to force a
// re-fetch.
let entriesCache: PluginEntry[] | null = null;

export async function fetchPluginEntries(): Promise<PluginEntry[]> {
  if (entriesCache) return entriesCache;
  try {
    const list = await api<PluginEntry[]>("/plugins");
    entriesCache = list || [];
  } catch {
    entriesCache = [];
  }
  return entriesCache;
}

export async function availablePluginNames(): Promise<string[]> {
  const entries = await fetchPluginEntries();
  return Array.from(new Set(entries.map((p) => p.plugin_name))).sort();
}

export function clearPluginCache(): void {
  entriesCache = null;
}
