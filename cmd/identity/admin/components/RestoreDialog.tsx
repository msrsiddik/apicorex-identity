"use client";

import { useState } from "react";
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

// A destructive restore, guarded by type-to-confirm. The caller supplies the
// word the user must type (a tenant slug, or "RESTORE" for the whole DB) and
// the async action to run on confirm.
export default function RestoreDialog({
  confirmWord,
  target,
  scope,
  onClose,
  onConfirm,
  onDone,
}: {
  confirmWord: string;
  target: string;
  scope: "tenant" | "database";
  onClose: () => void;
  onConfirm: () => Promise<void>;
  onDone: () => void;
}) {
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const matches = typed.trim() === confirmWord;

  async function run() {
    if (!matches) return;
    setBusy(true);
    setErr("");
    try {
      await onConfirm();
      onDone();
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open onOpenChange={(o) => !o && !busy && onClose()}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="text-destructive">
            Restore {scope === "tenant" ? target : "the entire database"}?
          </DialogTitle>
          <DialogDescription>
            {scope === "tenant" ? (
              <>
                This drops and recreates <strong>{target}</strong>&apos;s tables
                from the dump. Current data that isn&apos;t in the dump is lost.
              </>
            ) : (
              <>
                This overwrites <strong>every tenant</strong> in the database
                from the dump. This cannot be undone.
              </>
            )}
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-1.5">
          <Label htmlFor="confirm">
            Type <code className="rounded bg-muted px-1 py-0.5">{confirmWord}</code>{" "}
            to confirm
          </Label>
          <Input
            id="confirm"
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && run()}
            autoFocus
            autoComplete="off"
          />
        </div>

        {err && <p className="text-sm text-destructive">{err}</p>}

        <div className="flex items-center justify-end gap-2">
          <Button variant="outline" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            onClick={run}
            disabled={!matches || busy}
          >
            {busy ? "Restoring…" : "Restore now"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
