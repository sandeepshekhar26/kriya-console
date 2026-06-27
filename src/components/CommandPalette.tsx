import { useEffect, useMemo, useRef, useState } from "react";
import { Icon, type IconName } from "./Icon";

export interface Command {
  id: string;
  group: "Navigate" | "Actions" | "Approvals";
  label: string;
  icon: IconName;
  hint?: string;
  keywords?: string;
  run: () => void;
}

/**
 * ⌘K command palette — the navigation engine + action executor (Linear/Raycast). Jumps to any
 * surface and runs the common governance actions. Pure-frontend; closes on run/escape/backdrop.
 */
export function CommandPalette({
  open,
  onClose,
  commands,
}: {
  open: boolean;
  onClose: () => void;
  commands: Command[];
}) {
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (open) {
      setQuery("");
      setActive(0);
      // focus after paint
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return commands;
    return commands.filter((c) => `${c.label} ${c.group} ${c.keywords ?? ""}`.toLowerCase().includes(q));
  }, [commands, query]);

  // Clamp active when the result set shrinks.
  useEffect(() => {
    setActive((a) => Math.min(a, Math.max(0, filtered.length - 1)));
  }, [filtered.length]);

  if (!open) return null;

  const groups = ["Navigate", "Actions", "Approvals"] as const;

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((a) => Math.max(0, Math.min(a + 1, filtered.length - 1)));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((a) => Math.max(a - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const cmd = filtered[active];
      if (cmd) {
        onClose();
        cmd.run();
      }
    } else if (e.key === "Escape") {
      e.preventDefault();
      onClose();
    }
  }

  let renderIndex = -1;

  return (
    <div className="cmdk-backdrop" onMouseDown={onClose}>
      <div className="cmdk" onMouseDown={(e) => e.stopPropagation()}>
        <input
          ref={inputRef}
          className="cmdk-input"
          placeholder="Search or jump to…"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setActive(0);
          }}
          onKeyDown={onKeyDown}
          role="combobox"
          aria-expanded
          aria-controls="cmdk-list"
          aria-activedescendant={filtered.length ? `cmdk-opt-${active}` : undefined}
          aria-autocomplete="list"
          aria-label="Search or jump to a command"
        />
        <div className="sr-only" aria-live="polite">{filtered.length} command{filtered.length === 1 ? "" : "s"}</div>
        <div className="cmdk-list" id="cmdk-list" role="listbox" aria-label="Commands" ref={listRef}>
          {filtered.length === 0 && <div className="cmdk-empty">No matching commands.</div>}
          {groups.map((g) => {
            const items = filtered.filter((c) => c.group === g);
            if (items.length === 0) return null;
            return (
              <div key={g}>
                <div className="cmdk-group">{g}</div>
                {items.map((c) => {
                  renderIndex += 1;
                  const idx = renderIndex;
                  return (
                    <div
                      key={c.id}
                      id={`cmdk-opt-${idx}`}
                      role="option"
                      aria-selected={idx === active}
                      className={`cmdk-item ${idx === active ? "active" : ""}`}
                      onMouseEnter={() => setActive(idx)}
                      onClick={() => {
                        onClose();
                        c.run();
                      }}
                    >
                      <Icon name={c.icon} size={16} />
                      <span className="cmdk-item-label">{c.label}</span>
                      {c.hint && <span className="cmdk-item-hint">{c.hint}</span>}
                    </div>
                  );
                })}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
