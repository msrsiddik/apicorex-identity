"use client";

import { useRef, useState } from "react";
import { toast } from "sonner";
import { download, upload } from "@/lib/api";
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

// Full-database backup & restore. Platform-wide (all tenants), so it lives in
// its own top-level tab, not the per-tenant drill-in. The routes are under
// /platform/db/... (Core's firewall blocks /admin/db).
export default function DatabasePanel() {
  const [busy, setBusy] = useState(false);
  const [restoreOpen, setRestoreOpen] = useState(false);
  const fileRef = useRef<File | null>(null);

  async function doBackup() {
    setBusy(true);
    try {
      await download("/platform/db/backup");
      toast.success("Full backup downloaded");
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
          <CardTitle className="text-base">Full database backup</CardTitle>
          <CardDescription>
            Download a SQL dump of the entire database — every tenant&apos;s
            schema and the shared tables. Generated on demand and streamed to
            your browser.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button onClick={doBackup} disabled={busy}>
            <Download /> {busy ? "Preparing…" : "Download full backup"}
          </Button>
        </CardContent>
      </Card>

      <Card className="border-destructive/40">
        <CardHeader>
          <CardTitle className="text-base">Full database restore</CardTitle>
          <CardDescription>
            Overwrite the <strong>entire database</strong> from a dump.{" "}
            <strong className="text-destructive">
              This replaces every tenant&apos;s data and cannot be undone.
            </strong>
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="db-restore-file">Dump file (.sql)</Label>
            <Input
              id="db-restore-file"
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
              Restore entire database…
            </Button>
          </div>
        </CardContent>
      </Card>

      {restoreOpen && fileRef.current && (
        <RestoreDialog
          confirmWord="RESTORE"
          target="the entire database"
          scope="database"
          onClose={() => setRestoreOpen(false)}
          onConfirm={async () => {
            await upload("/platform/db/restore", fileRef.current!);
          }}
          onDone={() => {
            setRestoreOpen(false);
            toast.success("Full restore complete");
          }}
        />
      )}
    </section>
  );
}
