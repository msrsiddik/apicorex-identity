"use client";

import { useEffect, useState } from "react";
import { Command } from "cmdk";
import { api } from "@/lib/api";
import { useTheme } from "@/components/ThemeProvider";
import type { SectionId } from "@/components/Sidebar";
import type { Tenant } from "@/lib/types";
import {
  LayoutDashboard,
  Store,
  Plug,
  ShieldCheck,
  UsersRound,
  Database,
  Sun,
  Moon,
  LogOut,
  Building2,
} from "lucide-react";

const SECTIONS: { id: SectionId; label: string; Icon: typeof Store }[] = [
  { id: "dashboard", label: "Go to Dashboard", Icon: LayoutDashboard },
  { id: "tenants", label: "Go to Tenants", Icon: Store },
  { id: "plugins", label: "Go to Plugins", Icon: Plug },
  { id: "admins", label: "Go to Platform admins", Icon: ShieldCheck },
  { id: "roles", label: "Go to Roles", Icon: UsersRound },
  { id: "database", label: "Go to Database", Icon: Database },
];

export default function CommandPalette({
  open,
  onOpenChange,
  onNavigate,
  onDrillTenant,
  onLogout,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onNavigate: (id: SectionId) => void;
  onDrillTenant: (t: Tenant) => void;
  onLogout: () => void;
}) {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const { theme, toggle } = useTheme();

  useEffect(() => {
    if (!open) return;
    api<{ tenants: Tenant[] }>("/tenants")
      .then((res) => setTenants(res.tenants || []))
      .catch(() => setTenants([]));
  }, [open]);

  function run(fn: () => void) {
    onOpenChange(false);
    fn();
  }

  return (
    <Command.Dialog
      open={open}
      onOpenChange={onOpenChange}
      label="Command palette"
      className="fixed left-1/2 top-[20%] z-50 w-full max-w-lg -translate-x-1/2 overflow-hidden rounded-xl border border-border bg-popover text-popover-foreground shadow-lg"
    >
      <div className="border-b border-border px-3">
        <Command.Input
          placeholder="Search sections or jump to a tenant…"
          className="h-11 w-full bg-transparent text-sm outline-none placeholder:text-muted-foreground"
        />
      </div>
      <Command.List className="max-h-80 overflow-y-auto p-1.5">
        <Command.Empty className="py-6 text-center text-sm text-muted-foreground">
          No results.
        </Command.Empty>

        <Command.Group
          heading="Sections"
          className="px-2 py-1.5 [&_[cmdk-group-heading]]:text-[11px] [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wide [&_[cmdk-group-heading]]:text-muted-foreground [&_[cmdk-group-items]]:mt-1"
        >
          {SECTIONS.map(({ id, label, Icon }) => (
            <Command.Item
              key={id}
              onSelect={() => run(() => onNavigate(id))}
              className="flex cursor-pointer items-center gap-2.5 rounded-md px-2 py-2 text-sm text-foreground data-[selected=true]:bg-accent data-[selected=true]:text-accent-foreground"
            >
              <Icon className="h-4 w-4 shrink-0 text-muted-foreground" />
              {label}
            </Command.Item>
          ))}
        </Command.Group>

        {tenants.length > 0 && (
          <Command.Group
            heading="Jump to tenant"
            className="px-2 py-1.5 [&_[cmdk-group-heading]]:text-[11px] [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wide [&_[cmdk-group-heading]]:text-muted-foreground [&_[cmdk-group-items]]:mt-1"
          >
            {tenants.map((t) => (
              <Command.Item
                key={t.id}
                value={`${t.name} ${t.slug}`}
                onSelect={() => run(() => onDrillTenant(t))}
                className="flex cursor-pointer items-center gap-2.5 rounded-md px-2 py-2 text-sm text-foreground data-[selected=true]:bg-accent data-[selected=true]:text-accent-foreground"
              >
                <Building2 className="h-4 w-4 shrink-0 text-muted-foreground" />
                <span className="flex-1 truncate">{t.name}</span>
                <code className="text-xs text-muted-foreground">{t.slug}</code>
              </Command.Item>
            ))}
          </Command.Group>
        )}

        <Command.Group
          heading="General"
          className="px-2 py-1.5 [&_[cmdk-group-heading]]:text-[11px] [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wide [&_[cmdk-group-heading]]:text-muted-foreground [&_[cmdk-group-items]]:mt-1"
        >
          <Command.Item
            onSelect={() => run(toggle)}
            className="flex cursor-pointer items-center gap-2.5 rounded-md px-2 py-2 text-sm text-foreground data-[selected=true]:bg-accent data-[selected=true]:text-accent-foreground"
          >
            {theme === "dark" ? (
              <Sun className="h-4 w-4 shrink-0 text-muted-foreground" />
            ) : (
              <Moon className="h-4 w-4 shrink-0 text-muted-foreground" />
            )}
            Switch to {theme === "dark" ? "light" : "dark"} theme
          </Command.Item>
          <Command.Item
            onSelect={() => run(onLogout)}
            className="flex cursor-pointer items-center gap-2.5 rounded-md px-2 py-2 text-sm text-destructive data-[selected=true]:bg-accent"
          >
            <LogOut className="h-4 w-4 shrink-0" />
            Sign out
          </Command.Item>
        </Command.Group>
      </Command.List>
    </Command.Dialog>
  );
}
