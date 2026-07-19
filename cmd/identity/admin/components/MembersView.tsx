"use client";

import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import type { Member, Role, Tenant } from "@/lib/types";
import { useConfirm } from "@/components/ConfirmProvider";
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
import AddMemberDialog from "./AddMemberDialog";
import ResetPasswordDialog from "./ResetPasswordDialog";
import { TableSkeleton } from "@/components/ui/table-skeleton";
import { EmptyState } from "@/components/ui/empty-state";
import { RefreshCw, Users } from "lucide-react";

const base = (id: string) => "/tenants/" + encodeURIComponent(id) + "/members";

export default function MembersView({ tenant }: { tenant: Tenant }) {
  const [members, setMembers] = useState<Member[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [loading, setLoading] = useState(true);
  const [resetFor, setResetFor] = useState<Member | null>(null);
  const confirm = useConfirm();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [m, r] = await Promise.all([
        api<{ members: Member[] }>(base(tenant.id)),
        api<{ roles: Role[] }>(
          "/tenants/" + encodeURIComponent(tenant.id) + "/roles",
        ),
      ]);
      setMembers(m.members || []);
      setRoles(r.roles || []);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setLoading(false);
    }
  }, [tenant.id]);

  useEffect(() => {
    load();
  }, [load]);

  async function changeRole(m: Member, roleSlug: string) {
    if (roleSlug === m.role_slug) return;
    try {
      await api(base(tenant.id) + "/" + encodeURIComponent(m.user_id) + "/role", {
        method: "PATCH",
        body: JSON.stringify({ role: roleSlug }),
      });
      toast.success(`${m.email} → ${roleSlug}`);
      load();
    } catch (e: any) {
      toast.error(e.message);
      load(); // revert the optimistic select
    }
  }

  async function toggleStatus(m: Member) {
    const next = m.status === "active" ? "suspended" : "active";
    const verb = next === "suspended" ? "Suspend" : "Reactivate";
    const ok = await confirm({
      title: `${verb} ${m.email}?`,
      description:
        next === "suspended"
          ? "They won't be able to sign in until reactivated."
          : "This restores their sign-in access.",
      confirmLabel: verb,
      destructive: next === "suspended",
    });
    if (!ok) return;
    try {
      await api(
        base(tenant.id) + "/" + encodeURIComponent(m.user_id) + "/status",
        { method: "PATCH", body: JSON.stringify({ status: next }) },
      );
      toast.success(`${m.email} ${next}`);
      load();
    } catch (e: any) {
      toast.error(e.message);
    }
  }

  async function remove(m: Member) {
    const ok = await confirm({
      title: `Remove ${m.email} from ${tenant.name}?`,
      description: "This deletes their membership. Their account elsewhere is unaffected.",
      confirmLabel: "Remove",
      destructive: true,
    });
    if (!ok) return;
    try {
      await api(base(tenant.id) + "/" + encodeURIComponent(m.user_id), {
        method: "DELETE",
      });
      toast.success(`${m.email} removed`);
      load();
    } catch (e: any) {
      toast.error(e.message);
    }
  }

  return (
    <section className="flex flex-col gap-4">
      <div className="flex items-center justify-between gap-2">
        <span className="text-sm text-muted-foreground">
          {loading ? "Loading…" : `${members.length} member(s)`}
        </span>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={load}>
            <RefreshCw /> Refresh
          </Button>
          <AddMemberDialog
            tenant={tenant}
            roles={roles}
            onAdded={(email) => {
              toast.success(`${email} added`);
              load();
            }}
          />
        </div>
      </div>

      {!loading && members.length === 0 ? (
        <EmptyState
          icon={Users}
          title="No members yet"
          description="Add the first member to give someone access to this tenant."
          action={
            <AddMemberDialog
              tenant={tenant}
              roles={roles}
              onAdded={(email) => {
                toast.success(`${email} added`);
                load();
              }}
            />
          }
        />
      ) : (
      <div className="rounded-xl border bg-card">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Member</TableHead>
              <TableHead>Role</TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          {loading ? (
            <TableSkeleton rows={3} cols={4} />
          ) : (
          <TableBody>
            {members.map((m) => (
              <TableRow key={m.user_id}>
                <TableCell>
                  <div className="flex flex-col">
                    <span className="font-medium">
                      {m.full_name || m.email}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {m.email}
                    </span>
                  </div>
                </TableCell>
                <TableCell>
                  <Select
                    value={m.role_slug}
                    onValueChange={(v) => changeRole(m, v)}
                  >
                    <SelectTrigger className="h-8 w-36">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {roles.map((r) => (
                        <SelectItem key={r.slug} value={r.slug}>
                          {r.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </TableCell>
                <TableCell>
                  {m.status === "active" ? (
                    <Badge variant="ok">active</Badge>
                  ) : (
                    <Badge variant="danger">suspended</Badge>
                  )}
                </TableCell>
                <TableCell>
                  <div className="flex justify-end gap-1.5">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setResetFor(m)}
                    >
                      Password
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => toggleStatus(m)}
                    >
                      {m.status === "active" ? "Suspend" : "Reactivate"}
                    </Button>
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => remove(m)}
                    >
                      Remove
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
          )}
        </Table>
      </div>
      )}

      {resetFor && (
        <ResetPasswordDialog
          tenant={tenant}
          member={resetFor}
          onClose={() => setResetFor(null)}
          onDone={(email) => {
            setResetFor(null);
            toast.success(`Password reset for ${email}`);
          }}
        />
      )}
    </section>
  );
}
