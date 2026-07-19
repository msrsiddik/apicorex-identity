export interface Me {
  user_id: string;
  user_type: string;
  roles?: string[];
}

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  plan: string;
  status: string;
}

export interface PluginEntry {
  plugin_id: string;
  plugin_name: string;
  version: string;
  status: string;
  routes: number | unknown[];
}

export interface PlatformAdmin {
  email: string;
  user_id: string;
}

export interface Role {
  id: string;
  slug: string;
  name: string;
  is_system: boolean;
  permissions: string[];
}

export interface Branch {
  id: string;
  slug: string;
  name: string;
  status: string; // active | archived
}

export interface Member {
  user_id: string;
  email: string;
  full_name: string;
  phone: string;
  role_id: string;
  role_slug: string;
  role_name: string;
  branch_id: string;
  status: string; // active | suspended
}

export interface BatchResult {
  tenant_id?: string;
  slug?: string;
  error?: string;
}
