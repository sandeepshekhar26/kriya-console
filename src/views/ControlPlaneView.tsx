import { useEffect, useState, type ComponentType } from "react";
import { Icon } from "../components/Icon";

/**
 * Control plane — the on-prem kriyad aggregator view (paid tier). In the SHIPPED desktop app this shows
 * the honest "no aggregator connected" empty state: the real cross-machine aggregator client is
 * demand-pulled (gated behind a design partner — see docs/ideas/CONTROL-PLANE-ROADMAP.md), so until one
 * is wired the Console never fabricates peer-fleet rows. The seeded demo dashboard (coverage table +
 * trustless re-prove/forge/tamper/hide walkthrough) lives in ControlPlaneDemo.tsx and is loaded ONLY in
 * a `__KRIYA_DEMO__` web build, so its sample data is tree-shaken out of the production bundle.
 */
export function ControlPlaneView() {
  const [Demo, setDemo] = useState<ComponentType | null>(null);

  useEffect(() => {
    if (!__KRIYA_DEMO__) return;
    let cancelled = false;
    void import("./ControlPlaneDemo").then((m) => {
      if (!cancelled) setDemo(() => m.default);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  if (__KRIYA_DEMO__) {
    return Demo ? <Demo /> : <div className="view" />;
  }
  return <ControlPlaneEmpty />;
}

function ControlPlaneEmpty() {
  return (
    <div className="view">
      <header className="page-head">
        <div>
          <h1>
            Control plane <span className="cp-tag"><Icon name="server" size={13} /> on-prem aggregator</span>
          </h1>
          <p className="page-sub">
            Your fleet's signed evidence, aggregated and re-verified on a box <b>you</b> control — inside
            your boundary, no egress. The engine is open; this cockpit is the paid tier.
          </p>
        </div>
      </header>

      <div className="empty" style={{ margin: "40px auto" }}>
        <div className="empty-ico"><Icon name="server" size={22} /></div>
        <p className="empty-title">No aggregator connected</p>
        <p>
          Point this Console at your on-prem <code>kriyad</code> (mTLS, no egress) to aggregate and
          re-verify your fleet's signed evidence across machines — trusting neither the devices nor the
          server. Nothing leaves your boundary.
        </p>
        <p className="muted small">
          Standing up an aggregator is part of the control-plane tier — see the kriyaD deploy guide.
        </p>
      </div>
    </div>
  );
}
