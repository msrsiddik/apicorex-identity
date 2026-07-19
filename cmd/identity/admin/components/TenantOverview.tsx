"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { Tenant } from "@/lib/types";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Users, GitBranch, Plug } from "lucide-react";

interface Counts {
  members: number;
  branches: number;
  plugins: number;
}

function StatCard({
  icon: Icon,
  label,
  value,
  loading,
}: {
  icon: typeof Users;
  label: string;
  value: number;
  loading: boolean;
}) {
  return (
    <div className="flex items-center gap-3 rounded-xl border bg-card px-4 py-3">
      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-accent text-accent-foreground">
        <Icon className="h-4.5 w-4.5" />
      </div>
      <div className="flex flex-col">
        <span className="text-xs text-muted-foreground">{label}</span>
        {loading ? (
          <Skeleton className="h-6 w-8" />
        ) : (
          <span className="text-xl font-semibold tabular-nums">{value}</span>
        )}
      </div>
    </div>
  );
}

// A quick "at a glance" summary shown above the drill-in sub-tabs: how big is
// this tenant, and is it in good standing.
export default function TenantOverview({ tenant }: { tenant: Tenant }) {
  const [counts, setCounts] = useState<Counts | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [m, b, p] = await Promise.all([
          api<{ members: unknown[] }>(
            "/tenants/" + encodeURIComponent(tenant.id) + "/members",
          ),
          api<{ branches: unknown[] }>(
            "/tenants/" + encodeURIComponent(tenant.id) + "/branches",
          ),
          api<{ plugins?: string[] }>(
            "/tenants/" + encodeURIComponent(tenant.id) + "/plugins",
          ),
        ]);
        if (cancelled) return;
        setCounts({
          members: (m.members || []).length,
          branches: (b.branches || []).length,
          plugins: (p.plugins || []).length,
        });
      } catch {
        if (!cancelled) setCounts({ members: 0, branches: 0, plugins: 0 });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [tenant.id]);

  const loading = counts === null;

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant={tenant.status === "active" ? "ok" : "danger"}>
          {tenant.status}
        </Badge>
        <span className="text-sm text-muted-foreground">
          Plan: <span className="text-foreground">{tenant.plan || "—"}</span>
        </span>
      </div>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <StatCard
          icon={Users}
          label="Members"
          value={counts?.members ?? 0}
          loading={loading}
        />
        <StatCard
          icon={GitBranch}
          label="Branches"
          value={counts?.branches ?? 0}
          loading={loading}
        />
        <StatCard
          icon={Plug}
          label="Plugins installed"
          value={counts?.plugins ?? 0}
          loading={loading}
        />
      </div>
    </div>
  );
}
