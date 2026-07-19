"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import type { PlatformAdmin } from "@/lib/types";
import { useConfirm } from "@/components/ConfirmProvider";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
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
import { ShieldCheck } from "lucide-react";

export default function AdminsPanel() {
  const [admins, setAdmins] = useState<PlatformAdmin[]>([]);
  const [loading, setLoading] = useState(true);
  const [email, setEmail] = useState("");
  const confirm = useConfirm();

  async function load() {
    setLoading(true);
    try {
      const res = await api<{ admins?: PlatformAdmin[] }>("/platform-admins");
      setAdmins(res.admins || []);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function grant() {
    const e = email.trim();
    if (!e) {
      toast.error("Email is required");
      return;
    }
    try {
      await api("/platform-admins", {
        method: "POST",
        body: JSON.stringify({ email: e }),
      });
      setEmail("");
      toast.success(`Granted platform admin to ${e}`);
      load();
    } catch (ex: any) {
      toast.error(ex.message);
    }
  }

  async function revoke(targetEmail: string) {
    const ok = await confirm({
      title: `Revoke platform admin for ${targetEmail}?`,
      description: "They keep their tenant memberships — this only removes cross-tenant access.",
      confirmLabel: "Revoke",
      destructive: true,
    });
    if (!ok) return;
    try {
      await api("/platform-admins/" + encodeURIComponent(targetEmail), {
        method: "DELETE",
      });
      toast.success(`Revoked ${targetEmail}`);
      load();
    } catch (ex: any) {
      toast.error(ex.message);
    }
  }

  return (
    <section className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <Input
          className="max-w-xs"
          placeholder="user@example.com"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && grant()}
        />
        <Button onClick={grant}>Grant platform admin</Button>
      </div>
      {!loading && admins.length === 0 ? (
        <EmptyState
          icon={ShieldCheck}
          title="No platform admins yet"
          description="Grant an existing user cross-tenant access using the field above."
        />
      ) : (
        <div className="rounded-xl border bg-card">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Email</TableHead>
                <TableHead className="hidden sm:table-cell">User ID</TableHead>
                <TableHead className="text-right">Action</TableHead>
              </TableRow>
            </TableHeader>
            {loading ? (
              <TableSkeleton rows={3} cols={3} />
            ) : (
              <TableBody>
                {admins.map((a) => (
                  <TableRow key={a.email}>
                    <TableCell className="font-medium">{a.email}</TableCell>
                    <TableCell className="hidden sm:table-cell text-muted-foreground">
                      <code className="rounded bg-muted px-1.5 py-0.5 text-xs">
                        {a.user_id}
                      </code>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="destructive"
                        size="sm"
                        onClick={() => revoke(a.email)}
                      >
                        Revoke
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            )}
          </Table>
        </div>
      )}
    </section>
  );
}
