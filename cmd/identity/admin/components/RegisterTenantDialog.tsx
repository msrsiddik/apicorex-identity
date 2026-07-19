"use client";

import { useRef, useState } from "react";
import { api } from "@/lib/api";
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
import { Plus } from "lucide-react";

interface SlugCheck {
  slug: string;
  available: boolean;
  valid: boolean;
  reason?: string;
}

export default function RegisterTenantDialog({
  onRegistered,
}: {
  onRegistered: (slug: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [slugTouched, setSlugTouched] = useState(false);
  const [plan, setPlan] = useState("starter");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [fullName, setFullName] = useState("");
  const [slugState, setSlugState] = useState<SlugCheck | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const slugTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  function reset() {
    setName("");
    setSlug("");
    setSlugTouched(false);
    setPlan("starter");
    setEmail("");
    setPassword("");
    setFullName("");
    setSlugState(null);
    setErr("");
  }

  async function suggestFromName(n: string) {
    if (slugTouched || !n.trim()) return;
    try {
      const res = await api<{ slug: string }>(
        "/auth/slug-suggest?name=" + encodeURIComponent(n.trim()),
      );
      if (!slugTouched && res.slug) {
        setSlug(res.slug);
        checkSlug(res.slug);
      }
    } catch {
      /* best-effort */
    }
  }

  function checkSlug(value: string) {
    if (slugTimer.current) clearTimeout(slugTimer.current);
    if (!value.trim()) {
      setSlugState(null);
      return;
    }
    slugTimer.current = setTimeout(async () => {
      try {
        const res = await api<SlugCheck>(
          "/auth/slug-available?slug=" + encodeURIComponent(value.trim()),
        );
        setSlugState(res);
      } catch {
        setSlugState(null);
      }
    }, 300);
  }

  async function submit() {
    setErr("");
    if (!name.trim() || !email.trim() || !password) {
      setErr("Name, owner email, and password are required.");
      return;
    }
    if (slugState && (!slugState.valid || !slugState.available)) {
      setErr("Fix the slug first.");
      return;
    }
    setBusy(true);
    try {
      const res = await api<{ slug: string }>("/auth/register", {
        method: "POST",
        body: JSON.stringify({
          name: name.trim(),
          slug: slug.trim(),
          plan,
          email: email.trim(),
          password,
          full_name: fullName.trim(),
        }),
      });
      onRegistered(res.slug);
      setOpen(false);
      reset();
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  const slugHint = slugState
    ? !slugState.valid
      ? { text: slugState.reason || "invalid slug", cls: "text-destructive" }
      : !slugState.available
        ? { text: slugState.reason || "slug is taken", cls: "text-destructive" }
        : { text: "available", cls: "text-ok" }
    : { text: "", cls: "" };

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
          <Plus /> Register tenant
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>Register a new tenant</DialogTitle>
          <DialogDescription>
            Creates the tenant, its owner account, and installs every
            currently-registered plugin.
          </DialogDescription>
        </DialogHeader>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="rt-name">Tenant name</Label>
            <Input
              id="rt-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              onBlur={(e) => suggestFromName(e.target.value)}
              placeholder="Acme Corp"
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="rt-slug">Slug (optional)</Label>
            <Input
              id="rt-slug"
              value={slug}
              onChange={(e) => {
                setSlugTouched(true);
                setSlug(e.target.value);
                checkSlug(e.target.value);
              }}
              placeholder="auto from name"
            />
            <small className={"min-h-3.5 text-xs " + slugHint.cls}>
              {slugHint.text}
            </small>
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="rt-plan">Plan</Label>
            <Select value={plan} onValueChange={setPlan}>
              <SelectTrigger id="rt-plan">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="starter">starter</SelectItem>
                <SelectItem value="pro">pro</SelectItem>
                <SelectItem value="enterprise">enterprise</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="rt-owner">Owner full name</Label>
            <Input
              id="rt-owner"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              placeholder="Ada Owner"
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="rt-email">Owner email</Label>
            <Input
              id="rt-email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="owner@acme.com"
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="rt-pass">Owner password</Label>
            <Input
              id="rt-pass"
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
            {busy ? "Registering…" : "Register tenant"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
