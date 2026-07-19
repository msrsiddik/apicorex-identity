"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import type { Member, Tenant } from "@/lib/types";
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

export default function ResetPasswordDialog({
  tenant,
  member,
  onClose,
  onDone,
}: {
  tenant: Tenant;
  member: Member;
  onClose: () => void;
  onDone: (email: string) => void;
}) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  async function submit() {
    setErr("");
    if (!password) {
      setErr("Enter a new password.");
      return;
    }
    setBusy(true);
    try {
      await api(
        "/tenants/" +
          encodeURIComponent(tenant.id) +
          "/members/" +
          encodeURIComponent(member.user_id) +
          "/password",
        { method: "PATCH", body: JSON.stringify({ new_password: password }) },
      );
      onDone(member.email);
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
          <DialogTitle>Reset password</DialogTitle>
          <DialogDescription>
            Set a new password for <strong>{member.email}</strong>. They can sign
            in with it immediately.
          </DialogDescription>
        </DialogHeader>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="rp-pass">New password</Label>
          <Input
            id="rp-pass"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && submit()}
            placeholder="••••••••"
            autoFocus
          />
        </div>
        {err && <p className="text-sm text-destructive">{err}</p>}
        <div className="flex items-center justify-end gap-2">
          <Button variant="outline" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={busy}>
            {busy ? "Saving…" : "Reset password"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
