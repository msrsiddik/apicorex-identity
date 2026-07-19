"use client";

import { useState } from "react";
import { api, setToken } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";

interface LoginResponse {
  token?: string;
  access_token?: string;
}

export default function LoginCard({
  error,
  onAuthed,
}: {
  error?: string;
  onAuthed: () => void | Promise<void>;
}) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState(error || "");
  const [busy, setBusy] = useState(false);

  async function signIn() {
    setErr("");
    const e = email.trim();
    if (!e || !password) {
      setErr("Email and password are required");
      return;
    }
    setBusy(true);
    try {
      const res = await api<LoginResponse>("/auth/login", {
        method: "POST",
        body: JSON.stringify({ email: e, password }),
      });
      // Login returns a single opaque device token: { token }. (Older builds
      // returned { access_token }; keep a fallback so a stale response shape
      // doesn't silently store `undefined`.)
      const t = res.token || res.access_token;
      if (!t) throw new Error("Login returned no token");
      setToken(t);
      await onAuthed();
    } catch (ex: any) {
      setErr(ex.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle className="text-base">Welcome to ApiCoreX</CardTitle>
          <CardDescription>
            Sign in with your platform admin account to manage tenants, plugins,
            and admins.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              type="email"
              autoComplete="username"
              placeholder="you@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && signIn()}
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="password">Password</Label>
            <Input
              id="password"
              type="password"
              autoComplete="current-password"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && signIn()}
            />
          </div>
          <Button onClick={signIn} disabled={busy} className="w-full">
            {busy ? "Signing in…" : "Sign in"}
          </Button>
          {err && (
            <p className="min-h-4 text-sm text-destructive">{err}</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
