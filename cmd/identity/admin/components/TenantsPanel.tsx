"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { availablePluginNames } from "@/lib/plugins";
import type { Tenant } from "@/lib/types";
import { useConfirm } from "@/components/ConfirmProvider";
import RegisterTenantDialog from "./RegisterTenantDialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
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
import {
  ChevronDown,
  ChevronRight,
  RefreshCw,
  Users,
  Store,
  SearchX,
} from "lucide-react";

function statusBadge(status: string) {
  if (status === "active") return <Badge variant="ok">active</Badge>;
  if (status === "suspended") return <Badge variant="danger">suspended</Badge>;
  return <Badge variant="default">{status}</Badge>;
}

export default function TenantsPanel({
  onDrill,
}: {
  // Drill-in is lifted to the shell so the breadcrumb can reflect it.
  onDrill: (t: Tenant) => void;
}) {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [filter, setFilter] = useState("");
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    try {
      const res = await api<{ tenants: Tenant[] }>("/tenants");
      setTenants(res.tenants || []);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  function replaceTenant(t: Tenant) {
    setTenants((prev) => prev.map((x) => (x.id === t.id ? t : x)));
  }

  const q = filter.trim().toLowerCase();
  const shown = q
    ? tenants.filter(
        (t) =>
          t.name.toLowerCase().includes(q) || t.slug.toLowerCase().includes(q),
      )
    : tenants;

  return (
    <section className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <Input
          className="max-w-xs"
          placeholder="Filter by name or slug…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        <Button variant="outline" size="sm" onClick={load}>
          <RefreshCw /> Refresh
        </Button>
        <RegisterTenantDialog
          onRegistered={(slug) => {
            toast.success(`Tenant "${slug}" registered`);
            load();
          }}
        />
        <span className="ml-auto text-sm text-muted-foreground">
          {loading ? "Loading…" : `${tenants.length} tenant(s)`}
        </span>
      </div>

      {!loading && tenants.length === 0 ? (
        <EmptyState
          icon={Store}
          title="No tenants yet"
          description="Register your first tenant to get started — it creates the tenant, its owner account, and installs every registered plugin."
          action={
            <RegisterTenantDialog
              onRegistered={(slug) => {
                toast.success(`Tenant "${slug}" registered`);
                load();
              }}
            />
          }
        />
      ) : !loading && shown.length === 0 ? (
        <EmptyState
          icon={SearchX}
          title="No matches"
          description={`No tenant matches "${filter}".`}
        />
      ) : (
        <div className="rounded-xl border bg-card">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-8" />
                <TableHead>Name</TableHead>
                <TableHead>Slug</TableHead>
                <TableHead>Plan</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="hidden sm:table-cell">ID</TableHead>
              </TableRow>
            </TableHeader>
            {loading ? (
              <TableSkeleton rows={3} cols={6} />
            ) : (
              <TableBody>
                {shown.map((t) => (
                  <TenantRow
                    key={t.id}
                    tenant={t}
                    expanded={expanded === t.id}
                    onToggle={() =>
                      setExpanded((cur) => (cur === t.id ? null : t.id))
                    }
                    onTenantUpdated={replaceTenant}
                    onManageMembers={() => onDrill(t)}
                  />
                ))}
              </TableBody>
            )}
          </Table>
        </div>
      )}
    </section>
  );
}

function TenantRow({
  tenant,
  expanded,
  onToggle,
  onTenantUpdated,
  onManageMembers,
}: {
  tenant: Tenant;
  expanded: boolean;
  onToggle: () => void;
  onTenantUpdated: (t: Tenant) => void;
  onManageMembers: () => void;
}) {
  return (
    <>
      <TableRow className="cursor-pointer" onClick={onToggle}>
        <TableCell className="text-muted-foreground">
          {expanded ? (
            <ChevronDown className="h-4 w-4" />
          ) : (
            <ChevronRight className="h-4 w-4" />
          )}
        </TableCell>
        <TableCell className="font-medium">{tenant.name}</TableCell>
        <TableCell>
          <code className="rounded bg-muted px-1.5 py-0.5 text-xs">
            {tenant.slug}
          </code>
        </TableCell>
        <TableCell className="text-muted-foreground">{tenant.plan}</TableCell>
        <TableCell>{statusBadge(tenant.status)}</TableCell>
        <TableCell className="hidden sm:table-cell text-muted-foreground">
          <code className="rounded bg-muted px-1.5 py-0.5 text-xs">
            {tenant.id}
          </code>
        </TableCell>
      </TableRow>
      {expanded && (
        <TableRow className="hover:bg-transparent">
          <TableCell colSpan={6} className="p-0">
            <TenantDetail
              tenant={tenant}
              onTenantUpdated={onTenantUpdated}
              onManageMembers={onManageMembers}
            />
          </TableCell>
        </TableRow>
      )}
    </>
  );
}

function TenantDetail({
  tenant,
  onTenantUpdated,
  onManageMembers,
}: {
  tenant: Tenant;
  onTenantUpdated: (t: Tenant) => void;
  onManageMembers: () => void;
}) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [installed, setInstalled] = useState<string[]>([]);
  const [names, setNames] = useState<string[]>([]);
  const [selected, setSelected] = useState("");
  const [editing, setEditing] = useState(false);
  const [editName, setEditName] = useState(tenant.name);
  const [editPlan, setEditPlan] = useState(tenant.plan || "starter");
  const confirm = useConfirm();

  async function saveEdit() {
    try {
      const res = await api<{ tenant: Tenant }>(
        "/tenants/" + encodeURIComponent(tenant.id),
        {
          method: "PATCH",
          body: JSON.stringify({ name: editName.trim(), plan: editPlan.trim() }),
        },
      );
      onTenantUpdated(res.tenant);
      setEditing(false);
      toast.success("Tenant updated");
    } catch (e: any) {
      toast.error(e.message);
    }
  }

  async function reload() {
    setLoading(true);
    setError("");
    try {
      const res = await api<{ plugins?: string[] }>(
        "/tenants/" + encodeURIComponent(tenant.id) + "/plugins",
      );
      const inst = res.plugins || [];
      const available = await availablePluginNames();
      setInstalled(inst);
      setNames(available);
      setSelected((cur) => cur || available[0] || "");
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tenant.id]);

  async function pluginAction(action: "install" | "uninstall", dropData: boolean) {
    if (!selected) {
      toast.error("Pick a plugin first");
      return;
    }
    try {
      const body: Record<string, unknown> = {
        tenant_id: tenant.id,
        plugin_name: selected,
      };
      if (action === "uninstall") body.drop_data = dropData;
      await api("/plugins/" + action, {
        method: "POST",
        body: JSON.stringify(body),
      });
      toast.success(`${selected} ${action}ed`);
      reload();
    } catch (e: any) {
      toast.error(e.message);
    }
  }

  async function toggleStatus() {
    const next = tenant.status === "active" ? "suspended" : "active";
    const verb = next === "suspended" ? "Suspend" : "Reactivate";
    const ok = await confirm({
      title: `${verb} ${tenant.name}?`,
      description:
        next === "suspended"
          ? "This blocks login for every user of this tenant."
          : "This restores login access.",
      confirmLabel: verb,
      destructive: next === "suspended",
    });
    if (!ok) return;
    try {
      const res = await api<{ tenant: Tenant }>(
        "/tenants/" + encodeURIComponent(tenant.id) + "/status",
        { method: "PATCH", body: JSON.stringify({ status: next }) },
      );
      onTenantUpdated(res.tenant);
      toast.success("Tenant " + next);
    } catch (e: any) {
      toast.error(e.message);
    }
  }

  async function uninstallDropData() {
    const ok = await confirm({
      title: `Permanently drop ${selected}'s tables?`,
      description: `This deletes ${selected}'s data for ${tenant.name}. This cannot be undone.`,
      confirmLabel: "Drop data",
      destructive: true,
    });
    if (!ok) return;
    pluginAction("uninstall", true);
  }

  const canToggle = tenant.status === "active" || tenant.status === "suspended";

  return (
    <div className="bg-background/50 border-t border-border px-4 py-4">
      {loading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : error ? (
        <p className="text-sm text-destructive">{error}</p>
      ) : (
        <div className="flex flex-col gap-4">
          {/* Primary drill-in action */}
          <div>
            <Button size="sm" onClick={onManageMembers}>
              <Users /> Manage tenant
            </Button>
          </div>

          {/* Status + edit controls */}
          <div className="flex flex-wrap items-center gap-3">
            {canToggle && (
              <>
                <span className="text-sm text-muted-foreground">
                  Status: {statusBadge(tenant.status)}
                </span>
                {tenant.status === "active" ? (
                  <Button variant="destructive" size="sm" onClick={toggleStatus}>
                    Suspend tenant
                  </Button>
                ) : (
                  <Button variant="outline" size="sm" onClick={toggleStatus}>
                    Reactivate tenant
                  </Button>
                )}
              </>
            )}
            {!editing && (
              <>
                <span className="text-sm text-muted-foreground">
                  Plan: <Badge variant="default">{tenant.plan || "—"}</Badge>
                </span>
                <Button variant="outline" size="sm" onClick={() => setEditing(true)}>
                  Edit name / plan
                </Button>
              </>
            )}
          </div>

          {editing && (
            <div className="flex flex-col gap-3 rounded-lg border bg-card p-3 max-w-md">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="flex flex-col gap-1.5">
                  <label className="text-xs text-muted-foreground">Name</label>
                  <Input
                    value={editName}
                    onChange={(e) => setEditName(e.target.value)}
                  />
                </div>
                <div className="flex flex-col gap-1.5">
                  <label className="text-xs text-muted-foreground">Plan</label>
                  <Select value={editPlan} onValueChange={setEditPlan}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="starter">starter</SelectItem>
                      <SelectItem value="pro">pro</SelectItem>
                      <SelectItem value="enterprise">enterprise</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Button size="sm" onClick={saveEdit}>
                  Save
                </Button>
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={() => {
                    setEditName(tenant.name);
                    setEditPlan(tenant.plan || "starter");
                    setEditing(false);
                  }}
                >
                  Cancel
                </Button>
                <span className="text-xs text-muted-foreground">
                  Slug{" "}
                  <code className="rounded bg-muted px-1 py-0.5">
                    {tenant.slug}
                  </code>{" "}
                  is immutable
                </span>
              </div>
            </div>
          )}

          {/* Installed plugins */}
          <div className="text-sm">
            <span className="font-medium">Installed plugins:</span>{" "}
            {installed.length ? (
              installed.join(", ")
            ) : (
              <span className="text-muted-foreground">none</span>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Select value={selected} onValueChange={setSelected}>
              <SelectTrigger className="max-w-56">
                <SelectValue placeholder="Select a plugin" />
              </SelectTrigger>
              <SelectContent>
                {names.length ? (
                  names.map((p) => (
                    <SelectItem key={p} value={p}>
                      {p}
                      {installed.includes(p) ? " (installed)" : ""}
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
              size="sm"
              onClick={() => pluginAction("install", false)}
            >
              Install
            </Button>
            <Button
              variant="destructive"
              size="sm"
              onClick={() => pluginAction("uninstall", false)}
            >
              Uninstall (keep data)
            </Button>
            <Button variant="destructive" size="sm" onClick={uninstallDropData}>
              Uninstall (drop data)
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
