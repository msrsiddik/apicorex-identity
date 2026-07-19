"use client";

import { useRef, useState } from "react";
import { toast } from "sonner";
import { download, upload } from "@/lib/api";
import type { Tenant } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import RestoreDialog from "./RestoreDialog";
import { Download } from "lucide-react";

export default function BackupView({ tenant }: { tenant: Tenant }) {
  const [busy, setBusy] = useState(false);
  const [restoreOpen, setRestoreOpen] = useState(false);
  const fileRef = useRef<File | null>(null);

  async function doBackup() {
    setBusy(true);
    try {
      await download("/tenants/" + encodeURIComponent(tenant.id) + "/backup");
      toast.success("Backup downloaded");
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="flex flex-col gap-4 max-w-2xl">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Backup</CardTitle>
          <CardDescription>
            Download a SQL dump of <strong>{tenant.name}</strong>&apos;s schema
            (<code className="text-xs">tenant_{tenant.slug}</code>). The file is
            generated on demand and streamed to your browser — nothing is stored
            on the server.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button onClick={doBackup} disabled={busy}>
            <Download /> {busy ? "Preparing…" : "Download backup"}
          </Button>
        </CardContent>
      </Card>

      <Card className="border-destructive/40">
        <CardHeader>
          <CardTitle className="text-base">Restore</CardTitle>
          <CardDescription>
            Replace this tenant&apos;s data from a dump file. This is{" "}
            <strong className="text-destructive">destructive</strong> — it drops
            and recreates the tenant&apos;s tables. Use a dump taken from this
            tenant.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="restore-file">Dump file (.sql)</Label>
            <Input
              id="restore-file"
              type="file"
              accept=".sql"
              onChange={(e) => {
                fileRef.current = e.target.files?.[0] || null;
              }}
            />
          </div>
          <div>
            <Button
              variant="destructive"
              onClick={() => {
                if (!fileRef.current) {
                  toast.error("Choose a .sql file first");
                  return;
                }
                setRestoreOpen(true);
              }}
            >
              Restore this tenant…
            </Button>
          </div>
        </CardContent>
      </Card>

      {restoreOpen && fileRef.current && (
        <RestoreDialog
          confirmWord={tenant.slug}
          target={tenant.name}
          scope="tenant"
          onClose={() => setRestoreOpen(false)}
          onConfirm={async () => {
            await upload(
              "/tenants/" + encodeURIComponent(tenant.id) + "/restore",
              fileRef.current!,
            );
          }}
          onDone={() => {
            setRestoreOpen(false);
            toast.success("Restore complete");
          }}
        />
      )}
    </section>
  );
}
