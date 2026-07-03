/**
 * One thin, monochrome line-icon set (currentColor) — replaces every emoji / unicode glyph the old
 * UI used as an icon (▣ 🔒 ☀ ☾ ▦ ◔ …). Stroke-based, 24×24, inherits color so status hue lives in
 * the icon's color, not in an emoji. Keep the set small and consistent.
 */

export type IconName =
  | "shield-check" | "shield-x" | "monitor" | "list" | "approvals" | "policy"
  | "gauge" | "users" | "evidence" | "fleet" | "link" | "settings" | "key"
  | "check" | "clock" | "ring" | "search" | "chevron-right" | "chevron-up" | "chevron-down" | "arrow-right"
  | "x" | "sun" | "moon" | "lock" | "plus" | "copy" | "download" | "refresh"
  | "external" | "pause" | "play" | "server" | "desktop" | "bolt" | "info" | "folder" | "alert"
  | "coverage";

const P: Record<IconName, JSX.Element> = {
  "shield-check": <><path d="M12 3 19 6v5c0 4.4-3 7.6-7 9-4-1.4-7-4.6-7-9V6z" /><path d="m9 11.5 2 2 4-4.5" /></>,
  "shield-x": <><path d="M12 3 19 6v5c0 4.4-3 7.6-7 9-4-1.4-7-4.6-7-9V6z" /><path d="m9.5 9.5 5 5M14.5 9.5l-5 5" /></>,
  monitor: <path d="M3 12h3.5l2.5 7 4-15 2.5 8H21" />,
  list: <><path d="M8 6h12M8 12h12M8 18h12" /><path d="M4 6h.01M4 12h.01M4 18h.01" /></>,
  approvals: <><circle cx="12" cy="12" r="9" /><path d="m8.5 12 2.4 2.4 4.6-5" /></>,
  policy: <><path d="M12 3 19 6v5c0 4.4-3 7.6-7 9-4-1.4-7-4.6-7-9V6z" /><path d="M9 12h6M9 9h6M9 15h4" /></>,
  gauge: <><path d="M4.5 18a8 8 0 1 1 15 0" /><path d="m12 14 3.5-3" /><circle cx="12" cy="14" r="1.1" fill="currentColor" stroke="none" /></>,
  users: <><circle cx="9" cy="8" r="3.2" /><path d="M3.5 19c0-3 2.6-5 5.5-5s5.5 2 5.5 5" /><path d="M16.5 5.7a3 3 0 0 1 0 5.8M17.5 19c0-2.4-1-4-2.6-4.8" /></>,
  evidence: <><path d="M7 3h7l5 5v13H7z" /><path d="M14 3v5h5" /><path d="M10 13h5M10 17h5" /></>,
  fleet: <><rect x="4" y="4.5" width="16" height="6" rx="1.2" /><rect x="4" y="13.5" width="16" height="6" rx="1.2" /><path d="M7.5 7.5h.01M7.5 16.5h.01" /></>,
  link: <><path d="M10.5 13.5 14 10" /><path d="M11 7.5 12.4 6a3.6 3.6 0 0 1 5 5L16 12.5" /><path d="M13 16.5 11.6 18a3.6 3.6 0 0 1-5-5L8 11.5" /></>,
  settings: <><path d="M4 7h9M4 12h2M4 17h6" /><path d="M20 7h-2M20 12h-9M20 17h-7" /><circle cx="15" cy="7" r="2" /><circle cx="8" cy="12" r="2" /><circle cx="16" cy="17" r="2" /></>,
  key: <><circle cx="8" cy="12" r="3.3" /><path d="M11.3 12H20M17 12v3M20 12v2.5" /></>,
  check: <path d="m5 12.5 4.5 4.5L19 7" />,
  clock: <><circle cx="12" cy="12" r="8.5" /><path d="M12 7.5V12l3 1.8" /></>,
  ring: <><circle cx="12" cy="12" r="8.5" opacity="0.35" /><path d="M12 3.5a8.5 8.5 0 0 1 8.5 8.5" /></>,
  search: <><circle cx="11" cy="11" r="6.5" /><path d="m20 20-4-4" /></>,
  "chevron-right": <path d="m9.5 6 6 6-6 6" />,
  "chevron-up": <path d="m6 14.5 6-6 6 6" />,
  "chevron-down": <path d="m6 9.5 6 6 6-6" />,
  "arrow-right": <><path d="M4.5 12h15" /><path d="m13 5.5 6.5 6.5-6.5 6.5" /></>,
  x: <path d="m6 6 12 12M18 6 6 18" />,
  sun: <><circle cx="12" cy="12" r="4" /><path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5 5l1.5 1.5M17.5 17.5 19 19M19 5l-1.5 1.5M6.5 17.5 5 19" /></>,
  moon: <path d="M20 13.2A8 8 0 1 1 10.8 4 6.3 6.3 0 0 0 20 13.2z" />,
  lock: <><rect x="5" y="11" width="14" height="9" rx="2" /><path d="M8 11V8a4 4 0 0 1 8 0v3" /></>,
  plus: <path d="M12 5v14M5 12h14" />,
  copy: <><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V5a2 2 0 0 1 2-2h8" /></>,
  download: <><path d="M12 4v11" /><path d="m7.5 11 4.5 4.5L16.5 11" /><path d="M5 19.5h14" /></>,
  refresh: <><path d="M20 11a8 8 0 0 0-14-4.5L4 8" /><path d="M4 4v4h4" /><path d="M4 13a8 8 0 0 0 14 4.5L20 16" /><path d="M20 20v-4h-4" /></>,
  external: <><path d="M14 4h6v6" /><path d="M20 4 10 14" /><path d="M19 14v5a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5" /></>,
  pause: <><path d="M9 5v14M15 5v14" /></>,
  play: <path d="M7 4.5v15l13-7.5z" fill="currentColor" stroke="none" />,
  server: <><rect x="4" y="5" width="16" height="6" rx="1.4" /><rect x="4" y="14" width="16" height="6" rx="1.4" /><path d="M8 8h.01M8 17h.01" /></>,
  desktop: <><rect x="3" y="4.5" width="18" height="11" rx="1.6" /><path d="M9 19.5h6M12 15.5v4" /></>,
  bolt: <path d="M13 3 5.5 13H11l-1 8 8.5-11H13z" />,
  info: <><circle cx="12" cy="12" r="9" /><path d="M12 11v5M12 8h.01" /></>,
  folder: <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />,
  alert: <><path d="M12 4 21 19H3z" /><path d="M12 10v4M12 17h.01" /></>,
  coverage: <><rect x="4" y="4.5" width="7" height="6.5" rx="1.2" /><rect x="13" y="4.5" width="7" height="6.5" rx="1.2" /><rect x="4" y="13" width="7" height="6.5" rx="1.2" /><path d="M13.5 16.5 15.5 18.5 19.5 14" /></>,
};

export function Icon({
  name,
  size = 16,
  strokeWidth = 1.6,
  className,
}: {
  name: IconName;
  size?: number;
  strokeWidth?: number;
  className?: string;
}) {
  return (
    <svg
      className={`icon${className ? ` ${className}` : ""}`}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {P[name]}
    </svg>
  );
}
