"use client";

import { ChevronRight } from "lucide-react";
import { Fragment } from "react";

export interface Crumb {
  label: string;
  slug?: string;
  onClick?: () => void;
}

export default function Topbar({ crumbs }: { crumbs: Crumb[] }) {
  return (
    <header className="flex h-14 shrink-0 items-center gap-2 border-b border-border bg-card px-6">
      <nav className="flex items-center gap-2 text-sm" aria-label="Breadcrumb">
        {crumbs.map((c, i) => {
          const last = i === crumbs.length - 1;
          return (
            <Fragment key={i}>
              {i > 0 && (
                <ChevronRight
                  className="h-4 w-4 text-muted-foreground"
                  aria-hidden
                />
              )}
              {c.onClick && !last ? (
                <button
                  onClick={c.onClick}
                  className="text-muted-foreground transition-colors hover:text-foreground"
                >
                  {c.label}
                </button>
              ) : (
                <span
                  className={
                    last ? "font-medium text-foreground" : "text-muted-foreground"
                  }
                >
                  {c.label}
                </span>
              )}
              {last && c.slug && (
                <code className="rounded bg-muted px-1.5 py-0.5 text-xs text-muted-foreground">
                  {c.slug}
                </code>
              )}
            </Fragment>
          );
        })}
      </nav>
    </header>
  );
}
