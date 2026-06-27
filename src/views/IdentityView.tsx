import { useMemo, useState } from "react";
import type { AuditRow } from "../lib/types";
import { Icon } from "../components/Icon";
import type { View } from "../components/Sidebar";
import {
  summarizeIdentities,
  assignRole,
  roleOf,
  ROLE_CAPS,
  ROLES,
  type Capability,
  type IdentityKind,
  type RbacModel,
  type Role,
} from "../lib/identity";

const CAP_LABEL: Record<Capability, string> = {
  approve: "Approve guarded actions",
  editPolicy: "Edit policy",
  viewAudit: "View audit",
};

/** R8 (enterprise half) — per-operator / per-agent activity dashboards + RBAC keyed on the operator. */
export function IdentityView({
  rows,
  rbac,
  onRbacChange,
  onNavigate,
}: {
  rows: AuditRow[];
  rbac: RbacModel;
  onRbacChange: (next: RbacModel) => void;
  onNavigate: (v: View) => void;
}) {
  const [kind, setKind] = useState<IdentityKind>("user");
  const identities = useMemo(() => summarizeIdentities(rows, kind), [rows, kind]);

  // Operators observed in the log + any already assigned a role (excluding the unattributed bucket).
  const operators = useMemo(() => {
    const observed = summarizeIdentities(rows, "user").map((u) => u.id);
    return [...new Set([...observed, ...Object.keys(rbac.assignments)])]
      .filter((o) => o !== "(unattributed)")
      .sort();
  }, [rows, rbac.assignments]);

  const empty = rows.filter((r) => r.outcome.ok).length === 0;

  return (
    <div className="view">
      <header className="page-head">
        <div>
          <h1>Identity &amp; access</h1>
          <p className="page-sub">
            Who operated your apps — every action attributed to a signed operator + agent — and which
            roles may approve, edit policy, or view the audit.
          </p>
        </div>
      </header>

      {empty ? (
        <div className="empty">
          <div className="empty-ico"><Icon name="users" size={22} /></div>
          <p className="empty-title">No attributed activity yet</p>
          <p>
            Operator + agent activity is read from the <strong>signed actor</strong> on each verified
            receipt. Connect a governed app to capture who did what — and assign roles.
          </p>
          <div className="page-actions">
            <button className="btn primary" onClick={() => onNavigate("connections")}>Add a connection</button>
          </div>
        </div>
      ) : (
        <>
          <div className="toolbar">
            <span className="count">
              {identities.length} {kind === "user" ? "operators" : "agents"}
            </span>
            <select value={kind} onChange={(e) => setKind(e.target.value as IdentityKind)}>
              <option value="user">Operators</option>
              <option value="agent">Agents</option>
            </select>
          </div>

          <div className="table-wrap">
            <table className="audit">
              <thead>
                <tr>
                  <th>{kind === "user" ? "Operator" : "Agent"}</th>
                  {kind === "user" && <th>Role</th>}
                  <th>Actions</th>
                  <th>Success</th>
                  <th>Apps</th>
                  <th>{kind === "user" ? "Agents" : "Operators"}</th>
                  <th>Last seen (UTC)</th>
                </tr>
              </thead>
              <tbody>
                {identities.map((id) => (
                  <tr key={id.id}>
                    <td className="mono strong">{id.id}</td>
                    {kind === "user" && (
                      <td>
                        <span className="badge">{roleOf(rbac, id.id)}</span>
                      </td>
                    )}
                    <td className="mono">{id.actions}</td>
                    <td className="mono">{Math.round(id.successRate * 100)}%</td>
                    <td className="mono" title={id.apps.join(", ")}>
                      {id.apps.length}
                    </td>
                    <td className="mono" title={id.counterparts.join(", ")}>
                      {id.counterparts.length}
                    </td>
                    <td className="mono">{id.lastSeenMs ? fmtTs(id.lastSeenMs) : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <h2 className="section-head">Role-based access (RBAC)</h2>
          <p className="muted small pad">
            Assign each operator a role; capabilities are fixed per role so an auditor can read them.
            (SSO/OIDC sign-in is a hosted-tier feature — these roles are authored and stored locally.)
          </p>

          <div className="rbac-grid">
            <div className="table-wrap">
              <table className="audit">
                <thead>
                  <tr>
                    <th>Operator</th>
                    <th>Role</th>
                    <th>Can</th>
                  </tr>
                </thead>
                <tbody>
                  {operators.length === 0 ? (
                    <tr>
                      <td colSpan={3} className="muted">
                        No attributed operators yet — load receipts signed with an actor (R8).
                      </td>
                    </tr>
                  ) : (
                    operators.map((op) => {
                      const role = roleOf(rbac, op);
                      return (
                        <tr key={op}>
                          <td className="mono strong">{op}</td>
                          <td>
                            <select
                              value={role}
                              onChange={(e) => onRbacChange(assignRole(rbac, op, e.target.value as Role))}
                            >
                              {ROLES.map((r) => (
                                <option key={r} value={r}>
                                  {r}
                                </option>
                              ))}
                            </select>
                          </td>
                          <td className="caps-cell">
                            {ROLE_CAPS[role].map((c) => (
                              <span key={c} className="pill">
                                {CAP_LABEL[c]}
                              </span>
                            ))}
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
            <aside className="role-legend">
              <h3>Roles</h3>
              {ROLES.map((r) => (
                <div key={r} className="role-row">
                  <span className="badge">{r}</span>
                  <span className="muted small">{ROLE_CAPS[r].map((c) => CAP_LABEL[c]).join(" · ")}</span>
                </div>
              ))}
            </aside>
          </div>
        </>
      )}
    </div>
  );
}

function fmtTs(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").slice(0, 19);
}
