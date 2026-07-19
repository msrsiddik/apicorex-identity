"use client";

import type { Tenant } from "@/lib/types";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import TenantOverview from "./TenantOverview";
import MembersView from "./MembersView";
import BranchesView from "./BranchesView";
import RolesView from "./RolesView";
import BackupView from "./BackupView";

// The drill-in surface for a single tenant: the console "impersonates" the
// tenant and manages its members, branches, and roles. Everything below is
// tenant-scoped via the /tenants/:id/... platform-admin routes. The breadcrumb
// in the shell shows which tenant this is and provides the way back.
export default function TenantDrilldown({ tenant }: { tenant: Tenant }) {
  return (
    <section className="flex flex-col gap-5">
      <TenantOverview tenant={tenant} />
      <Tabs defaultValue="members">
        <TabsList>
          <TabsTrigger value="members">Members</TabsTrigger>
          <TabsTrigger value="branches">Branches</TabsTrigger>
          <TabsTrigger value="roles">Roles</TabsTrigger>
          <TabsTrigger value="backup">Backup</TabsTrigger>
        </TabsList>
        <TabsContent value="members">
          <MembersView tenant={tenant} />
        </TabsContent>
        <TabsContent value="branches">
          <BranchesView tenant={tenant} />
        </TabsContent>
        <TabsContent value="roles">
          <RolesView tenant={tenant} />
        </TabsContent>
        <TabsContent value="backup">
          <BackupView tenant={tenant} />
        </TabsContent>
      </Tabs>
    </section>
  );
}
