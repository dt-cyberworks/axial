import { useEffect, useRef, useState } from "react";

interface Props {
  label: string;
  /** Every value that exists for this facet, from the audit facets endpoint. */
  options: string[];
  /** Values the operator has explicitly unchecked. Everything else is on. */
  excluded: Set<string>;
  onChange: (excluded: Set<string>) => void;
  /** Optional display transform (e.g. actor labels, action underscores). */
  renderOption?: (value: string) => string;
}

/**
 * REQ-AUDITUI-003: an Excel-style column filter - every value checked by
 * default, unchecking one excludes it.
 *
 * State is the EXCLUDED set rather than the selected set on purpose. The audit
 * log is live, so new actors/actions appear while the page is open; with a
 * selected-set model every newly-seen value would default to hidden and
 * silently drop events out of the operator's view. Tracking exclusions instead
 * means anything new is included until the operator says otherwise, which is
 * the fail-visible direction for an audit log.
 */
export default function MultiSelectFilter({ label, options, excluded, onChange, renderOption }: Props) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  // Close on outside click / Escape so the popover doesn't trap the toolbar.
  useEffect(() => {
    if (!open) return;
    function onPointerDown(event: MouseEvent) {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) setOpen(false);
    }
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  const selectedCount = options.filter((value) => !excluded.has(value)).length;
  const allSelected = selectedCount === options.length;

  function toggle(value: string) {
    const next = new Set(excluded);
    next.has(value) ? next.delete(value) : next.add(value);
    onChange(next);
  }

  return (
    <div className="facet-filter" ref={rootRef}>
      <button
        type="button"
        className={`chip ${allSelected ? "" : "chip-on"}`}
        aria-haspopup="true"
        aria-expanded={open}
        onClick={() => setOpen((prev) => !prev)}
      >
        {label}: {allSelected ? "all" : `${selectedCount}/${options.length}`} ▾
      </button>
      {open && (
        <div className="facet-popover" role="group" aria-label={`Filter by ${label.toLowerCase()}`}>
          <div className="facet-popover-actions">
            <button type="button" className="link-button" onClick={() => onChange(new Set())}>
              Select all
            </button>
            <button type="button" className="link-button" onClick={() => onChange(new Set(options))}>
              Clear all
            </button>
          </div>
          <div className="facet-options">
            {options.length === 0 && <span className="muted-line">No values yet.</span>}
            {options.map((value) => (
              <label key={value} className="facet-option">
                <input type="checkbox" checked={!excluded.has(value)} onChange={() => toggle(value)} />
                <span title={value}>{renderOption ? renderOption(value) : value}</span>
              </label>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
