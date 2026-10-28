import type { Configuration, ScanRequestSummary } from "./types";

/**
 * Units the backend will plan: accounts x (regional services x regions + global services).
 * Mirrors `plan_work_items_for_request`; global services run once per account.
 */
export function estimateWorkUnits(scope: ScanRequestSummary, configuration: Configuration): number {
  const services = configuration.scanChoices.services.filter((service) => scope.services.includes(service.id));
  const regional = services.filter((service) => !service.global).length;
  const global = services.filter((service) => service.global).length;
  const perAccount = scope.scanRegions.length === 0 ? 0 : regional * scope.scanRegions.length + global;
  return targetAccountCount(scope, configuration) * perAccount;
}

export function targetAccountCount(scope: ScanRequestSummary, configuration: Configuration): number {
  if (scope.accountIds.length > 0) return scope.accountIds.length;
  return isOrganizationMode(configuration) ? configuration.organization.scannableAccountIds.length : 1;
}

export function isOrganizationMode(configuration: Configuration): boolean {
  return configuration.organization?.mode === "AWS_ORGANIZATIONS";
}

/** Client-side checks matching the API's; the API remains the authority. */
export function scopeProblem(scope: ScanRequestSummary, configuration: Configuration): string | null {
  if (scope.scanRegions.length === 0) return "Select at least one region.";
  if (scope.services.length === 0) return "Select at least one service.";
  const organization = configuration.organization;
  if (isOrganizationMode(configuration)) {
    const accounts = targetAccountCount(scope, configuration);
    if (accounts === 0) return "No onboarded accounts are available to scan.";
    if (accounts > organization.maxAccountsPerScan) {
      return `A scan may target at most ${organization.maxAccountsPerScan} accounts; ${accounts} are selected.`;
    }
  }
  const units = estimateWorkUnits(scope, configuration);
  const limit = organization?.maxWorkUnits ?? 1000;
  if (units > limit) {
    return `This scan needs ${units} account/region/service units; the limit is ${limit}. Select fewer accounts, regions, or services.`;
  }
  return null;
}
