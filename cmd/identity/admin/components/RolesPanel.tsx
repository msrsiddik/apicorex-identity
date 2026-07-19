"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { Role } from "@/lib/types";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { TableSkeleton } from "@/components/ui/table-skeleton";

export default function RolesPanel() {
  const [roles, setRoles] = useState<Role[]>([]);
  const [loading, setLoading] = useState(true);
  // roles is tenant-scoped; a platform admin with no tenant membership may not
  // be able to list it — surface the error in-table, this tab is best-effort.
  const [error, setError] = useState("");

  useEffect(() => {
    (async () => {
      try {
        const res = await api<{ roles?: Role[] }>("/roles");
        setRoles(res.roles || []);
      } catch (e: any) {
        setError(e.message);
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  return (
    <section className="flex flex-col gap-4">
      <p className="text-sm text-muted-foreground">
        System roles (seeded, apply to every tenant unless overridden by a
        tenant&apos;s own custom role).
      </p>
      <div className="rounded-xl border bg-card">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Slug</TableHead>
              <TableHead>Name</TableHead>
              <TableHead>System</TableHead>
            </TableRow>
          </TableHeader>
          {loading ? (
            <TableSkeleton rows={3} cols={3} />
          ) : (
            <TableBody>
              {error ? (
                <TableRow>
                  <TableCell colSpan={3} className="text-muted-foreground">
                    {error}
                  </TableCell>
                </TableRow>
              ) : (
                roles.map((r) => (
                  <TableRow key={r.slug}>
                    <TableCell>
                      <code className="rounded bg-muted px-1.5 py-0.5 text-xs">
                        {r.slug}
                      </code>
                    </TableCell>
                    <TableCell>{r.name}</TableCell>
                    <TableCell>
                      {r.is_system ? (
                        <Badge variant="ok">system</Badge>
                      ) : (
                        <Badge variant="outline">custom</Badge>
                      )}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          )}
        </Table>
      </div>
    </section>
  );
}
