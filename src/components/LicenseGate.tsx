import type { LicenseStatus } from "../lib/tauri";
import { Icon } from "./Icon";

/**
 * The paywall a free-tier user sees on a paid view (Compliance, Fleet). The feature's *value* is
 * stated; the compute itself lives in the compiled Rust backend behind the license check (R29), so
 * there's nothing here to unlock by editing JS.
 */
export function LicenseGate({
  feature,
  blurb,
  license,
  onActivate,
}: {
  feature: string;
  blurb: string;
  license: LicenseStatus | null;
  onActivate: () => void;
}) {
  return (
    <div className="view">
      <header className="page-head">
        <div>
          <h1>{feature}</h1>
          <p className="page-sub">{blurb}</p>
        </div>
      </header>
      <section className="panel gate">
        <div className="gate-ico"><Icon name="lock" size={22} /></div>
        <h2>Compliance tier</h2>
        <p className="muted">
          {feature} is part of the paid tier. It runs entirely on-device in the compiled backend —
          activate a license to unlock it. Nothing is uploaded; the license is verified offline.
        </p>
        {license?.reason && <p className="warn-text small">Installed license rejected: {license.reason}</p>}
        <button className="btn primary" onClick={onActivate}>
          Activate a license <Icon name="arrow-right" size={14} />
        </button>
      </section>
    </div>
  );
}
