"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import {
  availablePluginNames,
  clearPluginCache,
  fetchPluginEntries,
} from "@/lib/plugins";
import type { BatchResult, PluginEntry } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { TableSkeleton } from "@/components/ui/table-skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import { RefreshCw, Plug } from "lucide-react";

function routeCount(routes: PluginEntry["routes"]): number {
  if (typeof routes === "number") return routes;
  if (Array.isArray(routes)) return routes.length;
  return 0;
}

function isHealthy(status: string): boolean {
  return status === "up" || status === "healthy" || status === "alive";
}

export default function PluginsPanel() {
  const [entries, setEntries] = useState<PluginEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [names, setNames] = useState<string[]>([]);
  const [batchName, setBatchName] = useState("");
  const [batchStatus, setBatchStatus] = useState("");
  const [results, setResults] = useState<BatchResult[] | null>(null);

  async function loadPlugins() {
    setLoading(true);
    const list = await fetchPluginEntries();
    setEntries(list);
    setLoading(false);
  }

  async function loadNames() {
    const available = await availablePluginNames();
    setNames(available);
    setBatchName((cur) => cur || available[0] || "");
  }

  useEffect(() => {
    loadPlugins();
    loadNames();
  }, []);

  function refresh() {
    clearPluginCache();
    loadPlugins();
    loadNames();
  }

  async function runBatch(path: string, verb: string, pastTense: string) {
    if (!batchName) {
      toast.error("Pick a plugin first");
      return;
    }
    setBatchStatus(verb + "…");
    setResults(null);
    try {
      const res = await api<{ tenants?: BatchResult[] }>(path, {
        method: "POST",
        body: JSON.stringify({ plugin_name: batchName }),
      });
      const list = res.tenants || [];
      setResults(list);
      setBatchStatus(`${list.length} tenant(s) ${pastTense} for ${batchName}`);
      toast.success(`${pastTense} ${batchName} for ${list.length} tenant(s)`);
    } catch (e: any) {
      setBatchStatus("");
      toast.error(e.message);
    }
  }

  return (
    <section className="flex flex-col gap-4">
      <div className="flex items-center justify-between gap-2">
        <span className="text-sm text-muted-foreground">
          {loading ? "Loading…" : `${entries.length} plugin(s) registered with Core`}
        </span>
        <Button variant="outline" size="sm" onClick={refresh}>
          <RefreshCw /> Refresh
        </Button>
      </div>

      {!loading && entries.length === 0 ? (
        <EmptyState
          icon={Plug}
          title="No plugins registered"
          description="Plugins register themselves with Core on startup. Once one is running, it shows up here automatically."
        />
      ) : (
        <div className="rounded-xl border bg-card">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Version</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Routes</TableHead>
                <TableHead className="hidden sm:table-cell">Plugin ID</TableHead>
              </TableRow>
            </TableHeader>
            {loading ? (
              <TableSkeleton rows={3} cols={5} />
            ) : (
              <TableBody>
                {entries.map((p) => (
                  <TableRow key={p.plugin_id}>
                    <TableCell className="font-medium">{p.plugin_name}</TableCell>
                    <TableCell className="text-muted-foreground">
                      {p.version}
                    </TableCell>
                    <TableCell>
                      <Badge variant={isHealthy(p.status) ? "ok" : "default"}>
                        {p.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground tabular-nums">
                      {routeCount(p.routes)}
                    </TableCell>
                    <TableCell className="hidden sm:table-cell text-muted-foreground">
                      <code className="rounded bg-muted px-1.5 py-0.5 text-xs">
                        {p.plugin_id}
                      </code>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            )}
          </Table>
        </div>
      )}

      <div className="rounded-xl border bg-card p-4 flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <Select value={batchName} onValueChange={setBatchName}>
            <SelectTrigger className="max-w-56">
              <SelectValue placeholder="Select a plugin" />
            </SelectTrigger>
            <SelectContent>
              {names.length ? (
                names.map((p) => (
                  <SelectItem key={p} value={p}>
                    {p}
                  </SelectItem>
                ))
              ) : (
                <SelectItem value="__none" disabled>
                  no plugins registered
                </SelectItem>
              )}
            </SelectContent>
          </Select>
          <Button
            variant="outline"
            onClick={() =>
              runBatch("/plugins/install-all", "Installing", "processed")
            }
          >
            Install to all tenants
          </Button>
          <Button
            variant="outline"
            onClick={() =>
              runBatch("/plugins/reconcile", "Reconciling", "reconciled")
            }
          >
            Reconcile to all tenants
          </Button>
        </div>
        <p className="text-sm text-muted-foreground">
          <strong className="text-foreground">Install to all tenants</strong>{" "}
          adds the plugin to every active tenant that doesn&apos;t already have
          it. <strong className="text-foreground">Reconcile</strong> rolls a
          plugin&apos;s newly-added migrations out to tenants that already have
          it installed. New tenants get every currently-installed plugin
          automatically at registration.
        </p>
        {batchStatus && (
          <p className="text-sm text-muted-foreground">{batchStatus}</p>
        )}
        {results && results.length > 0 && (
          <div className="rounded-lg border bg-background">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Tenant</TableHead>
                  <TableHead>Result</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {results.map((r, i) => {
                  const ok = !r.error;
                  return (
                    <TableRow key={r.tenant_id || r.slug || i}>
                      <TableCell>
                        <code className="rounded bg-muted px-1.5 py-0.5 text-xs">
                          {r.slug || r.tenant_id}
                        </code>
                      </TableCell>
                      <TableCell>
                        {ok ? (
                          <Badge variant="ok">ok</Badge>
                        ) : (
                          <span className="text-destructive text-sm">
                            {r.error}
                          </span>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </div>
    </section>
  );
}
