"use client";

import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import type { Role, Tenant } from "@/lib/types";
import { useConfirm } from "@/components/ConfirmProvider";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import RoleEditorDialog from "./RoleEditorDialog";
import { TableSkeleton } from "@/components/ui/table-skeleton";
import { Plus } from "lucide-react";

const rolesBase = (id: string) =>
  "/tenants/" + encodeURIComponent(id) + "/roles";

export default function RolesView({ tenant }: { tenant: Tenant }) {
  const [roles, setRoles] = useState<Role[]>([]);
  const [permissions, setPermissions] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState<Role | null>(null);
  const [creating, setCreating] = useState(false);
  const confirm = useConfirm();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [r, p] = await Promise.all([
        api<{ roles: Role[] }>(rolesBase(tenant.id)),
        api<{ permissions: string[] }>("/permissions"),
      ]);
      setRoles(r.roles || []);
      setPermissions(p.permissions || []);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setLoading(false);
    }
  }, [tenant.id]);

  useEffect(() => {
    load();
  }, [load]);

  async function remove(role: Role) {
    const ok = await confirm({
      title: `Delete the "${role.name}" role?`,
      description: "Members using it must be reassigned first.",
      confirmLabel: "Delete",
      destructive: true,
    });
    if (!ok) return;
    try {
      await api(rolesBase(tenant.id) + "/" + encodeURIComponent(role.id), {
        method: "DELETE",
      });
      toast.success(`Role "${role.name}" deleted`);
      load();
    } catch (e: any) {
      toast.error(e.message);
    }
  }

  return (
    <section className="flex flex-col gap-4">
      <div className="flex items-center justify-between gap-2">
        <span className="text-sm text-muted-foreground">
          {loading ? "Loading…" : `${roles.length} role(s)`}
        </span>
        <Button size="sm" onClick={() => setCreating(true)}>
          <Plus /> New role
        </Button>
      </div>

      <div className="rounded-xl border bg-card">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Role</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Permissions</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          {loading ? (
            <TableSkeleton rows={3} cols={4} />
          ) : (
          <TableBody>
            {roles.map((r) => (
              <TableRow key={r.id}>
                <TableCell>
                  <div className="flex flex-col">
                    <span className="font-medium">{r.name}</span>
                    <code className="text-xs text-muted-foreground">
                      {r.slug}
                    </code>
                  </div>
                </TableCell>
                <TableCell>
                  {r.is_system ? (
                    <Badge variant="default">system</Badge>
                  ) : (
                    <Badge variant="ok">custom</Badge>
                  )}
                </TableCell>
                <TableCell>
                  <div className="flex flex-wrap gap-1 max-w-md">
                    {r.permissions.slice(0, 6).map((p) => (
                      <code
                        key={p}
                        className="rounded bg-muted px-1.5 py-0.5 text-xs"
                      >
                        {p}
                      </code>
                    ))}
                    {r.permissions.length > 6 && (
                      <span className="text-xs text-muted-foreground">
                        +{r.permissions.length - 6} more
                      </span>
                    )}
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex justify-end gap-1.5">
                    {r.is_system ? (
                      <span className="text-xs text-muted-foreground">
                        read-only
                      </span>
                    ) : (
                      <>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setEditing(r)}
                        >
                          Edit
                        </Button>
                        <Button
                          variant="destructive"
                          size="sm"
                          onClick={() => remove(r)}
                        >
                          Delete
                        </Button>
                      </>
                    )}
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
          )}
        </Table>
      </div>

      {creating && (
        <RoleEditorDialog
          tenant={tenant}
          permissions={permissions}
          onClose={() => setCreating(false)}
          onDone={(name) => {
            setCreating(false);
            toast.success(`Role "${name}" created`);
            load();
          }}
        />
      )}
      {editing && (
        <RoleEditorDialog
          tenant={tenant}
          permissions={permissions}
          role={editing}
          onClose={() => setEditing(null)}
          onDone={(name) => {
            setEditing(null);
            toast.success(`Role "${name}" updated`);
            load();
          }}
        />
      )}
    </section>
  );
}
