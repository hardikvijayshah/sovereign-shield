export interface NavItem {
  path: string;
  label: string;
}

/**
 * Navigation entries for the caller's allowed actions. Hiding an entry is a
 * convenience; the API rejects unauthorized requests regardless.
 */
export function navItems(allowedActions: readonly string[]): NavItem[] {
  const can = (action: string) => allowedActions.includes(action);
  const items: NavItem[] = [];
  if (can("view_scan")) items.push({ path: "/", label: "Scans" });
  if (can("start_scan")) items.push({ path: "/scans/new", label: "New scan" });
  if (can("view_accounts")) items.push({ path: "/accounts", label: "Accounts" });
  if (can("view_schedules")) items.push({ path: "/schedules", label: "Schedules" });
  if (can("view_audit_log")) items.push({ path: "/audit", label: "Audit log" });
  if (can("view_configuration")) items.push({ path: "/settings", label: "Settings" });
  return items;
}
