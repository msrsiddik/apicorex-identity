"use client";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { useTheme } from "@/components/ThemeProvider";
import {
  Store,
  Plug,
  ShieldCheck,
  UsersRound,
  Database,
  PanelLeftClose,
  PanelLeft,
  LogOut,
  Search,
  Sun,
  Moon,
} from "lucide-react";
import type { Me } from "@/lib/types";

export type SectionId =
  | "tenants"
  | "plugins"
  | "admins"
  | "roles"
  | "database";

const NAV: { id: SectionId; label: string; Icon: typeof Store }[] = [
  { id: "tenants", label: "Tenants", Icon: Store },
  { id: "plugins", label: "Plugins", Icon: Plug },
  { id: "admins", label: "Platform admins", Icon: ShieldCheck },
  { id: "roles", label: "Roles", Icon: UsersRound },
  { id: "database", label: "Database", Icon: Database },
];

export default function Sidebar({
  active,
  onNavigate,
  collapsed,
  onToggleCollapse,
  me,
  onLogout,
  onOpenPalette,
}: {
  active: SectionId;
  onNavigate: (id: SectionId) => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
  me: Me;
  onLogout: () => void;
  onOpenPalette: () => void;
}) {
  const { theme, toggle } = useTheme();
  return (
    <aside
      className={cn(
        "flex shrink-0 flex-col border-r border-border bg-card transition-[width] duration-200",
        collapsed ? "w-[60px]" : "w-[210px]",
      )}
    >
      {/* Brand + collapse */}
      <div className="flex items-center gap-2 px-3 py-3.5">
        <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-primary text-sm font-semibold text-primary-foreground">
          A
        </span>
        {!collapsed && (
          <span className="flex-1 truncate text-sm font-semibold">
            ApiCoreX
          </span>
        )}
        <Button
          variant="ghost"
          size="icon"
          className="h-7 w-7"
          onClick={onToggleCollapse}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? (
            <PanelLeft className="h-4 w-4" />
          ) : (
            <PanelLeftClose className="h-4 w-4" />
          )}
        </Button>
      </div>

      {/* Quick search / command palette */}
      <div className="px-2">
        <button
          onClick={onOpenPalette}
          title={collapsed ? "Search (⌘K)" : undefined}
          className={cn(
            "flex w-full items-center gap-2.5 rounded-md border border-border bg-background/40 px-2.5 py-1.5 text-sm text-muted-foreground transition-colors hover:bg-secondary",
            collapsed && "justify-center px-0",
          )}
        >
          <Search className="h-3.5 w-3.5 shrink-0" />
          {!collapsed && (
            <>
              <span className="flex-1 truncate text-left">Search</span>
              <kbd className="rounded border border-border bg-muted px-1 text-[10px]">
                ⌘K
              </kbd>
            </>
          )}
        </button>
      </div>

      {/* Nav */}
      <nav className="flex flex-1 flex-col gap-0.5 px-2 py-2">
        {!collapsed && (
          <span className="px-2 pb-1 pt-2 text-[11px] uppercase tracking-wide text-muted-foreground">
            Platform
          </span>
        )}
        {NAV.map(({ id, label, Icon }) => {
          const on = active === id;
          return (
            <button
              key={id}
              onClick={() => onNavigate(id)}
              title={collapsed ? label : undefined}
              className={cn(
                "flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm transition-colors",
                collapsed && "justify-center px-0",
                on
                  ? "bg-accent text-accent-foreground"
                  : "text-muted-foreground hover:bg-secondary hover:text-foreground",
              )}
            >
              <Icon className="h-4 w-4 shrink-0" />
              {!collapsed && <span className="truncate">{label}</span>}
            </button>
          );
        })}
      </nav>

      {/* Theme + user + logout */}
      <div className="border-t border-border p-2">
        <div
          className={cn(
            "flex items-center gap-2 rounded-md px-1.5 py-1.5",
            collapsed && "justify-center",
          )}
        >
          <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-accent text-[11px] font-medium text-accent-foreground">
            {(me.roles?.[0] || "u").slice(0, 2).toUpperCase()}
          </span>
          {!collapsed && (
            <div className="min-w-0 flex-1 leading-tight">
              <div className="truncate text-xs text-foreground">
                {(me.roles || []).join(", ") || "admin"}
              </div>
              <div className="truncate text-[11px] text-muted-foreground">
                {me.user_id}
              </div>
            </div>
          )}
          {!collapsed && (
            <>
              <Button
                variant="ghost"
                size="icon"
                className="h-7 w-7"
                onClick={toggle}
                aria-label={theme === "dark" ? "Switch to light" : "Switch to dark"}
              >
                {theme === "dark" ? (
                  <Sun className="h-4 w-4" />
                ) : (
                  <Moon className="h-4 w-4" />
                )}
              </Button>
              <Button
                variant="ghost"
                size="icon"
                className="h-7 w-7"
                onClick={onLogout}
                aria-label="Sign out"
              >
                <LogOut className="h-4 w-4" />
              </Button>
            </>
          )}
        </div>
        {collapsed && (
          <div className="mt-1 flex flex-col gap-1">
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-full"
              onClick={toggle}
              aria-label={theme === "dark" ? "Switch to light" : "Switch to dark"}
            >
              {theme === "dark" ? (
                <Sun className="h-4 w-4" />
              ) : (
                <Moon className="h-4 w-4" />
              )}
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-full"
              onClick={onLogout}
              aria-label="Sign out"
            >
              <LogOut className="h-4 w-4" />
            </Button>
          </div>
        )}
      </div>
    </aside>
  );
}
