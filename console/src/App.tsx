import { NavLink, Navigate, Route, Routes } from "react-router-dom";

import { navItems } from "./nav";
import { Accounts } from "./pages/Accounts";
import { AuditLog } from "./pages/AuditLog";
import { Dashboard } from "./pages/Dashboard";
import { NewScan } from "./pages/NewScan";
import { ScanDetail } from "./pages/ScanDetail";
import { Schedules } from "./pages/Schedules";
import { Settings } from "./pages/Settings";
import { useCan, useSession } from "./session";

export function App() {
  const { auth, configuration } = useSession();
  const email = auth.claims().email;
  const items = navItems(configuration.caller.allowedActions);

  return (
    <div className="app">
      <header className="topbar">
        <span className="brand">Sovereign Shield</span>
        <nav aria-label="Main">
          {items.map((item) => (
            <NavLink key={item.path} to={item.path} end={item.path === "/"}>
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="identity">
          <span>{email ?? "Signed in"}</span>
          <span className="muted">{configuration.caller.roles.join(", ")}</span>
          <button type="button" className="link-button" onClick={() => void auth.signOut()}>
            Sign out
          </button>
        </div>
      </header>
      <main>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scans/new" element={<Guard action="start_scan"><NewScan /></Guard>} />
          <Route path="/scans/:scanRunId" element={<ScanDetail />} />
          <Route path="/accounts" element={<Guard action="view_accounts"><Accounts /></Guard>} />
          <Route path="/schedules" element={<Guard action="view_schedules"><Schedules /></Guard>} />
          <Route path="/audit" element={<Guard action="view_audit_log"><AuditLog /></Guard>} />
          <Route path="/settings" element={<Guard action="view_configuration"><Settings /></Guard>} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
      <footer className="footer muted">
        Sovereign Shield provides evidence-based data-sovereignty assessments, not legal advice. Release{" "}
        {configuration.deployment.releaseVersion} · rule pack {configuration.deployment.rulePackVersion}
      </footer>
    </div>
  );
}

function Guard({ action, children }: { action: string; children: React.ReactElement }) {
  return useCan(action) ? children : <AccessDenied />;
}

export function AccessDenied() {
  return (
    <section className="panel">
      <h2>Access denied</h2>
      <p>Your role does not allow access to this page. Ask a Sovereign Shield administrator if you need it.</p>
    </section>
  );
}

export function NoRole() {
  return (
    <div className="centered">
      <h1>Sovereign Shield</h1>
      <p>
        You are signed in, but your account is not in the SovereignShieldAdministrators or
        SovereignShieldAuditors group. Ask an administrator to add you.
      </p>
    </div>
  );
}
