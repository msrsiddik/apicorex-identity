"use client";

import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import type { Branch, Tenant } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { TableSkeleton } from "@/components/ui/table-skeleton";
import { Plus } from "lucide-react";

const base = (id: string) => "/tenants/" + encodeURIComponent(id) + "/branches";

export default function BranchesView({ tenant }: { tenant: Tenant }) {
  const [branches, setBranches] = useState<Branch[]>([]);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState<Branch | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api<{ branches: Branch[] }>(base(tenant.id));
      setBranches(res.branches || []);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setLoading(false);
    }
  }, [tenant.id]);

  useEffect(() => {
    load();
  }, [load]);

  async function toggleArchive(b: Branch) {
    const next = b.status === "active" ? "archived" : "active";
    try {
      await api(base(tenant.id) + "/" + encodeURIComponent(b.id), {
        method: "PATCH",
        body: JSON.stringify({ status: next }),
      });
      toast.success(`${b.name} ${next}`);
      load();
    } catch (e: any) {
      toast.error(e.message);
    }
  }

  return (
    <section className="flex flex-col gap-4">
      <div className="flex items-center justify-between gap-2">
        <span className="text-sm text-muted-foreground">
          {loading ? "Loading…" : `${branches.length} branch(es)`}
        </span>
        <CreateBranchDialog
          tenant={tenant}
          onCreated={(name) => {
            toast.success(`Branch "${name}" created`);
            load();
          }}
        />
      </div>

      <div className="rounded-xl border bg-card">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Slug</TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          {loading ? (
            <TableSkeleton rows={2} cols={4} />
          ) : (
          <TableBody>
            {branches.map((b) => (
              <TableRow key={b.id}>
                <TableCell className="font-medium">{b.name}</TableCell>
                <TableCell>
                  <code className="rounded bg-muted px-1.5 py-0.5 text-xs">
                    {b.slug}
                  </code>
                </TableCell>
                <TableCell>
                  {b.status === "active" ? (
                    <Badge variant="ok">active</Badge>
                  ) : (
                    <Badge variant="default">archived</Badge>
                  )}
                </TableCell>
                <TableCell>
                  <div className="flex justify-end gap-1.5">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setEditing(b)}
                    >
                      Rename
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => toggleArchive(b)}
                    >
                      {b.status === "active" ? "Archive" : "Restore"}
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
          )}
        </Table>
      </div>

      {editing && (
        <RenameBranchDialog
          tenant={tenant}
          branch={editing}
          onClose={() => setEditing(null)}
          onDone={(name) => {
            setEditing(null);
            toast.success(`Branch renamed to "${name}"`);
            load();
          }}
        />
      )}
    </section>
  );
}

function CreateBranchDialog({
  tenant,
  onCreated,
}: {
  tenant: Tenant;
  onCreated: (name: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [slug, setSlug] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  async function submit() {
    setErr("");
    if (!slug.trim() || !name.trim()) {
      setErr("Slug and name are required.");
      return;
    }
    setBusy(true);
    try {
      await api("/tenants/" + encodeURIComponent(tenant.id) + "/branches", {
        method: "POST",
        body: JSON.stringify({ slug: slug.trim(), name: name.trim() }),
      });
      onCreated(name.trim());
      setOpen(false);
      setSlug("");
      setName("");
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm">
          <Plus /> New branch
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle>New branch</DialogTitle>
          <DialogDescription>
            Add a branch (outlet / location) to <strong>{tenant.name}</strong>.
          </DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-3">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="cb-name">Name</Label>
            <Input
              id="cb-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Dhaka Office"
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="cb-slug">Slug</Label>
            <Input
              id="cb-slug"
              value={slug}
              onChange={(e) => setSlug(e.target.value)}
              placeholder="dhaka"
            />
          </div>
        </div>
        {err && <p className="text-sm text-destructive">{err}</p>}
        <div className="flex items-center justify-end gap-2">
          <Button variant="outline" onClick={() => setOpen(false)} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={busy}>
            {busy ? "Creating…" : "Create branch"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function RenameBranchDialog({
  tenant,
  branch,
  onClose,
  onDone,
}: {
  tenant: Tenant;
  branch: Branch;
  onClose: () => void;
  onDone: (name: string) => void;
}) {
  const [name, setName] = useState(branch.name);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  async function submit() {
    setErr("");
    if (!name.trim()) {
      setErr("Name is required.");
      return;
    }
    setBusy(true);
    try {
      await api(
        "/tenants/" +
          encodeURIComponent(tenant.id) +
          "/branches/" +
          encodeURIComponent(branch.id),
        { method: "PATCH", body: JSON.stringify({ name: name.trim() }) },
      );
      onDone(name.trim());
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle>Rename branch</DialogTitle>
          <DialogDescription>
            Slug{" "}
            <code className="rounded bg-muted px-1 py-0.5">{branch.slug}</code>{" "}
            is immutable.
          </DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="rb-name">Name</Label>
          <Input
            id="rb-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && submit()}
            autoFocus
          />
        </div>
        {err && <p className="text-sm text-destructive">{err}</p>}
        <div className="flex items-center justify-end gap-2">
          <Button variant="outline" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={busy}>
            {busy ? "Saving…" : "Save"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
