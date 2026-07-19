"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import type { Role, Tenant } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { UserPlus } from "lucide-react";

export default function AddMemberDialog({
  tenant,
  roles,
  onAdded,
}: {
  tenant: Tenant;
  roles: Role[];
  onAdded: (email: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [fullName, setFullName] = useState("");
  const [phone, setPhone] = useState("");
  const [role, setRole] = useState("member");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  function reset() {
    setEmail("");
    setFullName("");
    setPhone("");
    setRole("member");
    setPassword("");
    setErr("");
  }

  async function submit() {
    setErr("");
    if (!email.trim()) {
      setErr("Email is required.");
      return;
    }
    setBusy(true);
    try {
      await api("/tenants/" + encodeURIComponent(tenant.id) + "/members", {
        method: "POST",
        body: JSON.stringify({
          email: email.trim(),
          full_name: fullName.trim(),
          phone: phone.trim(),
          role,
          password, // only required when the user is new to the platform
        }),
      });
      onAdded(email.trim());
      setOpen(false);
      reset();
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (!o) reset();
      }}
    >
      <DialogTrigger asChild>
        <Button size="sm">
          <UserPlus /> Add member
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add a member</DialogTitle>
          <DialogDescription>
            Grants access to <strong>{tenant.name}</strong>. If the email has no
            account yet, a password is required to create one.
          </DialogDescription>
        </DialogHeader>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="flex flex-col gap-1.5 sm:col-span-2">
            <Label htmlFor="am-email">Email</Label>
            <Input
              id="am-email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="member@acme.com"
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="am-name">Full name</Label>
            <Input
              id="am-name"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              placeholder="New Member"
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="am-phone">Phone</Label>
            <Input
              id="am-phone"
              value={phone}
              onChange={(e) => setPhone(e.target.value)}
              placeholder="+1-555-0101"
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="am-role">Role</Label>
            <Select value={role} onValueChange={setRole}>
              <SelectTrigger id="am-role">
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
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="am-pass">Password (new users only)</Label>
            <Input
              id="am-pass"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
            />
          </div>
        </div>

        {err && <p className="text-sm text-destructive">{err}</p>}

        <div className="flex items-center justify-end gap-2">
          <Button
            variant="outline"
            onClick={() => {
              setOpen(false);
              reset();
            }}
            disabled={busy}
          >
            Cancel
          </Button>
          <Button onClick={submit} disabled={busy}>
            {busy ? "Adding…" : "Add member"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
