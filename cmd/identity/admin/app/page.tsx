"use client";

import { useCallback, useEffect, useState } from "react";
import { api, clearToken } from "@/lib/api";
import type { Me, Tenant } from "@/lib/types";
import { clearPluginCache } from "@/lib/plugins";
import Sidebar, { type SectionId } from "@/components/Sidebar";
import Topbar from "@/components/Topbar";
import CommandPalette from "@/components/CommandPalette";
import LoginCard from "@/components/LoginCard";
import TenantsPanel from "@/components/TenantsPanel";
import TenantDrilldown from "@/components/TenantDrilldown";
import PluginsPanel from "@/components/PluginsPanel";
import AdminsPanel from "@/components/AdminsPanel";
import RolesPanel from "@/components/RolesPanel";
import DatabasePanel from "@/components/DatabasePanel";

const SECTION_LABELS: Record<SectionId, string> = {
  tenants: "Tenants",
  plugins: "Plugins",
  admins: "Platform admins",
  roles: "Roles",
  database: "Database",
};

export default function Page() {
  // undefined = still resuming; null = logged out; Me = logged in.
  const [me, setMe] = useState<Me | null | undefined>(undefined);
  const [loginError, setLoginError] = useState("");
  const [section, setSection] = useState<SectionId>("tenants");
  const [collapsed, setCollapsed] = useState(false);
  // Tenant drill-in lives at the shell so the breadcrumb reflects it.
  const [drillTenant, setDrillTenant] = useState<Tenant | null>(null);
  const [paletteOpen, setPaletteOpen] = useState(false);

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  const tryResume = useCallback(async () => {
    try {
      const resumed = await api<Me>("/me");
      if (resumed.user_type !== "platform_admin") {
        clearToken();
        setLoginError("This account is not a platform admin.");
        setMe(null);
        return;
      }
      setLoginError("");
      setMe(resumed);
    } catch {
      clearToken();
      setMe(null);
    }
  }, []);

  useEffect(() => {
    const hasToken =
      typeof window !== "undefined" &&
      !!localStorage.getItem("apicorex_admin_token");
    if (hasToken) {
      tryResume();
    } else {
      setMe(null);
    }
  }, [tryResume]);

  function logout() {
    clearToken();
    clearPluginCache();
    setMe(null);
  }

  function navigate(id: SectionId) {
    setDrillTenant(null); // leaving any drill-in when switching sections
    setSection(id);
  }

  function drillToTenant(t: Tenant) {
    setSection("tenants");
    setDrillTenant(t);
  }

  if (me === undefined) return null;
  if (!me) return <LoginCard error={loginError} onAuthed={tryResume} />;

  // Breadcrumb trail for the topbar.
  const crumbs =
    section === "tenants" && drillTenant
      ? [
          { label: "Tenants", onClick: () => setDrillTenant(null) },
          { label: drillTenant.name, slug: drillTenant.slug },
        ]
      : [{ label: SECTION_LABELS[section] }];

  return (
    <div className="flex min-h-screen">
      <Sidebar
        active={section}
        onNavigate={navigate}
        collapsed={collapsed}
        onToggleCollapse={() => setCollapsed((c) => !c)}
        me={me}
        onLogout={logout}
        onOpenPalette={() => setPaletteOpen(true)}
      />

      <CommandPalette
        open={paletteOpen}
        onOpenChange={setPaletteOpen}
        onNavigate={navigate}
        onDrillTenant={drillToTenant}
        onLogout={logout}
      />

      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar crumbs={crumbs} />
        <main className="min-w-0 flex-1 px-6 py-5">
          <div className="mx-auto max-w-6xl">
            {section === "tenants" &&
              (drillTenant ? (
                <TenantDrilldown tenant={drillTenant} />
              ) : (
                <TenantsPanel onDrill={setDrillTenant} />
              ))}
            {section === "plugins" && <PluginsPanel />}
            {section === "admins" && <AdminsPanel />}
            {section === "roles" && <RolesPanel />}
            {section === "database" && <DatabasePanel />}
          </div>
        </main>
      </div>
    </div>
  );
}
