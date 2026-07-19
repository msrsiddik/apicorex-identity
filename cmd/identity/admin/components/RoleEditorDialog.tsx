"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import type { Role, Tenant } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { cn } from "@/lib/utils";

export default function RoleEditorDialog({
  tenant,
  permissions,
  role,
  onClose,
  onDone,
}: {
  tenant: Tenant;
  permissions: string[];
  role?: Role; // present = edit, absent = create
  onClose: () => void;
  onDone: (name: string) => void;
}) {
  const isEdit = !!role;
  const [slug, setSlug] = useState(role?.slug || "");
  const [name, setName] = useState(role?.name || "");
  const [selected, setSelected] = useState<Set<string>>(
    new Set(role?.permissions || []),
  );
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  function toggle(p: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(p)) next.delete(p);
      else next.add(p);
      return next;
    });
  }

  async function submit() {
    setErr("");
    if (!name.trim() || (!isEdit && !slug.trim())) {
      setErr("Name and slug are required.");
      return;
    }
    setBusy(true);
    const perms = Array.from(selected);
    try {
      if (isEdit) {
        await api(
          "/tenants/" +
            encodeURIComponent(tenant.id) +
            "/roles/" +
            encodeURIComponent(role!.id),
          {
            method: "PATCH",
            body: JSON.stringify({ name: name.trim(), permissions: perms }),
          },
        );
      } else {
        await api("/tenants/" + encodeURIComponent(tenant.id) + "/roles", {
          method: "POST",
          body: JSON.stringify({
            slug: slug.trim(),
            name: name.trim(),
            permissions: perms,
          }),
        });
      }
      onDone(name.trim());
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{isEdit ? "Edit role" : "New role"}</DialogTitle>
          <DialogDescription>
            {isEdit ? (
              <>
                Editing <strong>{role!.name}</strong> in {tenant.name}.
              </>
            ) : (
              <>Define a custom role for {tenant.name}.</>
            )}
          </DialogDescription>
        </DialogHeader>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="re-name">Name</Label>
            <Input
              id="re-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Auditor"
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="re-slug">Slug</Label>
            <Input
              id="re-slug"
              value={slug}
              onChange={(e) => setSlug(e.target.value)}
              placeholder="auditor"
              disabled={isEdit}
            />
          </div>
        </div>

        <div className="flex flex-col gap-2">
          <Label>Permissions</Label>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5 max-h-56 overflow-y-auto rounded-lg border p-2">
            {permissions.map((p) => {
              const on = selected.has(p);
              return (
                <button
                  key={p}
                  type="button"
                  onClick={() => toggle(p)}
                  className={cn(
                    "flex items-center gap-2 rounded-md px-2 py-1.5 text-left text-xs transition-colors",
                    on
                      ? "bg-accent text-accent-foreground"
                      : "hover:bg-secondary text-muted-foreground",
                  )}
                >
                  <span
                    className={cn(
                      "flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded-sm border",
                      on ? "bg-primary border-primary" : "border-input",
                    )}
                  >
                    {on && (
                      <svg
                        viewBox="0 0 12 12"
                        className="h-2.5 w-2.5 text-primary-foreground"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2.5"
                      >
                        <path d="M2 6l3 3 5-6" strokeLinecap="round" strokeLinejoin="round" />
                      </svg>
                    )}
                  </span>
                  <code>{p}</code>
                </button>
              );
            })}
          </div>
          <span className="text-xs text-muted-foreground">
            {selected.size} selected
          </span>
        </div>

        {err && <p className="text-sm text-destructive">{err}</p>}

        <div className="flex items-center justify-end gap-2">
          <Button variant="outline" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={busy}>
            {busy ? "Saving…" : isEdit ? "Save changes" : "Create role"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
