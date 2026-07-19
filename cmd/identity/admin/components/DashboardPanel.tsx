"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { Tenant, PlatformAdmin, Role } from "@/lib/types";
import type { SectionId } from "@/components/Sidebar";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { EmptyState } from "@/components/ui/empty-state";
import {
  Store,
  ShieldCheck,
  UsersRound,
  Plug,
  ArrowRight,
  UserPlus,
  KeyRound,
} from "lucide-react";

interface Stats {
  tenants: Tenant[];
  admins: number;
  roles: number;
  pluginInstalls: number;
}

function StatCard({
  icon: Icon,
  label,
  value,
  loading,
  hint,
}: {
  icon: typeof Store;
  label: string;
  value: number;
  loading: boolean;
  hint?: string;
}) {
  return (
    <div className="flex items-center gap-3 rounded-xl border bg-card px-4 py-3.5">
      <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-accent text-accent-foreground">
        <Icon className="h-5 w-5" />
      </div>
      <div className="flex flex-col">
        <span className="text-xs text-muted-foreground">{label}</span>
        {loading ? (
          <Skeleton className="h-7 w-10" />
        ) : (
          <span className="text-2xl font-semibold tabular-nums">{value}</span>
        )}
        {hint && !loading && (
          <span className="text-[11px] text-muted-foreground">{hint}</span>
        )}
      </div>
    </div>
  );
}

function statusBadge(status: string) {
  if (status === "active") return <Badge variant="ok">active</Badge>;
  if (status === "suspended") return <Badge variant="danger">suspended</Badge>;
  return <Badge variant="default">{status}</Badge>;
}

export default function DashboardPanel({
  onNavigate,
  onDrill,
}: {
  onNavigate: (id: SectionId) => void;
  onDrill: (t: Tenant) => void;
}) {
  const [stats, setStats] = useState<Stats | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [t, a, r] = await Promise.all([
          api<{ tenants: Tenant[] }>("/tenants"),
          api<{ admins?: PlatformAdmin[] }>("/platform-admins").catch(
            () => ({ admins: [] }),
          ),
          api<{ roles?: Role[] }>("/roles").catch(() => ({ roles: [] })),
        ]);
        const tenants = t.tenants || [];
        const pluginCounts = await Promise.all(
          tenants.map((tn) =>
            api<{ plugins?: string[] }>(
              "/tenants/" + encodeURIComponent(tn.id) + "/plugins",
            )
              .then((res) => (res.plugins || []).length)
              .catch(() => 0),
          ),
        );
        if (cancelled) return;
        setStats({
          tenants,
          admins: (a.admins || []).length,
          roles: (r.roles || []).length,
          pluginInstalls: pluginCounts.reduce((sum, n) => sum + n, 0),
        });
      } catch {
        if (!cancelled)
          setStats({ tenants: [], admins: 0, roles: 0, pluginInstalls: 0 });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const loading = stats === null;
  const tenants = stats?.tenants ?? [];
  const activeCount = tenants.filter((t) => t.status === "active").length;
  const suspendedCount = tenants.filter((t) => t.status === "suspended").length;
  const recent = tenants.slice(0, 6);

  return (
    <section className="flex flex-col gap-5">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          icon={Store}
          label="Tenants"
          value={tenants.length}
          loading={loading}
          hint={
            !loading
              ? `${activeCount} active · ${suspendedCount} suspended`
              : undefined
          }
        />
        <StatCard
          icon={ShieldCheck}
          label="Platform admins"
          value={stats?.admins ?? 0}
          loading={loading}
        />
        <StatCard
          icon={UsersRound}
          label="Roles"
          value={stats?.roles ?? 0}
          loading={loading}
        />
        <StatCard
          icon={Plug}
          label="Plugin installs"
          value={stats?.pluginInstalls ?? 0}
          loading={loading}
          hint="across all tenants"
        />
      </div>

      {/* Quick actions */}
      <div className="flex flex-wrap items-center gap-2 rounded-xl border bg-card px-4 py-3">
        <span className="text-sm font-medium">Quick actions</span>
        <div className="ml-auto flex flex-wrap gap-2">
          <Button variant="outline" size="sm" onClick={() => onNavigate("tenants")}>
            <Store /> Register tenant
          </Button>
          <Button variant="outline" size="sm" onClick={() => onNavigate("admins")}>
            <UserPlus /> Add platform admin
          </Button>
          <Button variant="outline" size="sm" onClick={() => onNavigate("roles")}>
            <KeyRound /> View roles
          </Button>
        </div>
      </div>

      {/* Recent tenants */}
      <div className="flex flex-col gap-3">
        <div className="flex items-center">
          <h2 className="text-sm font-semibold">Recent tenants</h2>
          <Button
            variant="ghost"
            size="sm"
            className="ml-auto"
            onClick={() => onNavigate("tenants")}
          >
            View all <ArrowRight />
          </Button>
        </div>

        {!loading && recent.length === 0 ? (
          <EmptyState
            icon={Store}
            title="No tenants yet"
            description="Register your first tenant from the Tenants section to get started."
          />
        ) : (
          <div className="rounded-xl border bg-card">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Slug</TableHead>
                  <TableHead>Plan</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading
                  ? Array.from({ length: 4 }).map((_, i) => (
                      <TableRow key={i}>
                        {Array.from({ length: 4 }).map((__, j) => (
                          <TableCell key={j}>
                            <Skeleton className="h-4 w-full max-w-24" />
                          </TableCell>
                        ))}
                      </TableRow>
                    ))
                  : recent.map((t) => (
                      <TableRow
                        key={t.id}
                        className="cursor-pointer"
                        onClick={() => onDrill(t)}
                      >
                        <TableCell className="font-medium">{t.name}</TableCell>
                        <TableCell>
                          <code className="rounded bg-muted px-1.5 py-0.5 text-xs">
                            {t.slug}
                          </code>
                        </TableCell>
                        <TableCell className="text-muted-foreground">
                          {t.plan}
                        </TableCell>
                        <TableCell>{statusBadge(t.status)}</TableCell>
                      </TableRow>
                    ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>
    </section>
  );
}
