import React, { useState } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { AlertTriangle, Check, Copy, Info, OctagonX } from 'lucide-react'
import type { InputType, Provenance } from '@shared/data/spectra'

const EASE = [0.23, 1, 0.32, 1] as const

export function CopyButton({ value, label = 'Copy' }: { value: string; label?: string }) {
  const [done, setDone] = useState(false)
  return (
    <button
      type="button"
      aria-label={`${label}: ${value}`}
      title={label}
      onClick={(e) => {
        e.stopPropagation()
        navigator.clipboard?.writeText(value).catch(() => {})
        setDone(true)
        setTimeout(() => setDone(false), 1200)
      }}
      className="inline-flex h-5 w-5 shrink-0 items-center justify-center rounded text-faint transition-colors duration-100 hover:bg-raised hover:text-fg"
    >
      {done ? <Check size={12} className="text-accent" /> : <Copy size={12} />}
    </button>
  )
}

export function Mono({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return <span className={`font-mono text-[12px] ${className}`}>{children}</span>
}

export function TypeChip({ type }: { type: InputType | string }) {
  return (
    <span className="inline-flex items-center whitespace-nowrap rounded border border-line-strong px-1.5 py-px font-mono text-[11px] text-muted">
      {type}
    </span>
  )
}

export function Chip({ children, tone = 'plain' }: { children: React.ReactNode; tone?: 'plain' | 'accent' }) {
  return (
    <span
      className={`inline-flex items-center whitespace-nowrap rounded px-1.5 py-px text-[11px] ${
        tone === 'accent' ? 'bg-accent-soft text-fg' : 'bg-raised text-muted'
      }`}
    >
      {children}
    </span>
  )
}

/** 5 segments plus the number. Segments are filled by rounding value × 5. */
export function ConfidenceBar({ value }: { value: number }) {
  const filled = Math.round(value * 5)
  return (
    <span className="inline-flex items-center gap-2" title={`confidence ${value.toFixed(2)}`}>
      <span className="flex gap-[2px]" aria-hidden>
        {[0, 1, 2, 3, 4].map((i) => (
          <span key={i} className={`h-2 w-[7px] rounded-[1px] ${i < filled ? 'bg-accent' : 'bg-line-strong'}`} />
        ))}
      </span>
      <span className="tabular font-mono text-[12px]">{value.toFixed(2)}</span>
    </span>
  )
}

export function GradeChip({ r, c, rationale }: { r: string; c: number; rationale?: string }) {
  return (
    <span
      title={rationale}
      className="inline-flex cursor-help items-center rounded border border-line-strong px-1.5 py-px font-mono text-[11px]"
    >
      {r}/{c}
    </span>
  )
}

export function ProvenanceBadge({ p }: { p: Provenance }) {
  if (p.kind === 'static') return <span className="whitespace-nowrap text-[12px] text-fg">Static</span>
  if (p.kind === 'sandbox') return <span className="whitespace-nowrap text-[12px] text-fg">Sandbox (CAPE)</span>
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-[12px] text-muted">
      Feed claim · {p.feed}
      <span className="rounded border border-dashed border-line-strong px-1 text-[10px] text-muted">claimed</span>
    </span>
  )
}

/** Amber and red always carry an icon and a word. */
export function LevelTag({ level }: { level: 'info' | 'warning' | 'error' }) {
  if (level === 'error')
    return (
      <span className="inline-flex items-center gap-1 whitespace-nowrap text-[12px] font-medium text-err">
        <OctagonX size={13} /> Error
      </span>
    )
  if (level === 'warning')
    return (
      <span className="inline-flex items-center gap-1 whitespace-nowrap text-[12px] font-medium text-warn">
        <AlertTriangle size={13} /> Warning
      </span>
    )
  return (
    <span className="inline-flex items-center gap-1 whitespace-nowrap text-[12px] text-muted">
      <Info size={13} /> Info
    </span>
  )
}

export function Notice({
  level,
  word,
  children,
}: {
  level: 'info' | 'warning'
  word: string
  children: React.ReactNode
}) {
  const warn = level === 'warning'
  return (
    <div
      className={`flex items-start gap-2 rounded border px-3 py-2 text-[12px] ${
        warn ? 'border-warn/40 bg-warn-soft' : 'border-line bg-raised'
      }`}
    >
      {warn ? <AlertTriangle size={14} className="mt-px shrink-0 text-warn" /> : <Info size={14} className="mt-px shrink-0 text-muted" />}
      <span className={`shrink-0 font-medium ${warn ? 'text-warn' : 'text-muted'}`}>{word}</span>
      <span className="text-fg">{children}</span>
    </div>
  )
}

/** The small "?" disclosure. Explanations live here, never inline. */
export function Help({ children, align = 'left' }: { children: React.ReactNode; align?: 'left' | 'right' }) {
  const [open, setOpen] = useState(false)
  return (
    <span className="relative inline-flex">
      <button
        type="button"
        aria-expanded={open}
        onClick={(e) => {
          e.stopPropagation()
          setOpen((o) => !o)
        }}
        className={`inline-flex h-4 w-4 items-center justify-center rounded-full border text-[10px] font-semibold transition-colors duration-100 ${
          open ? 'border-accent text-accent' : 'border-line-strong text-muted hover:text-fg'
        }`}
      >
        ?
      </button>
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -2, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -2, scale: 0.98 }}
            transition={{ duration: 0.15, ease: EASE }}
            onClick={(e) => e.stopPropagation()}
            className={`absolute top-6 z-30 w-[300px] rounded border border-line-strong bg-panel p-3 text-left text-[12px] font-normal normal-case leading-relaxed text-fg ${
              align === 'right' ? 'right-0' : 'left-0'
            }`}
          >
            {children}
          </motion.div>
        )}
      </AnimatePresence>
    </span>
  )
}

export function Button({
  children,
  variant = 'default',
  disabled,
  onClick,
  className = '',
}: {
  children: React.ReactNode
  variant?: 'default' | 'primary' | 'ghost'
  disabled?: boolean
  onClick?: () => void
  className?: string
}) {
  const styles = {
    default: 'border border-line-strong bg-raised text-fg hover:border-muted',
    primary: 'border border-accent bg-accent text-on-accent hover:opacity-90',
    ghost: 'text-muted hover:bg-raised hover:text-fg',
  }[variant]
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      className={`inline-flex h-7 items-center gap-1.5 whitespace-nowrap rounded px-2.5 text-[12px] font-medium transition-[background-color,border-color,opacity] duration-100 active:opacity-80 disabled:cursor-not-allowed disabled:opacity-45 ${styles} ${className}`}
    >
      {children}
    </button>
  )
}

export function Select({
  value,
  onChange,
  options,
  label,
  mono,
}: {
  value: string
  onChange?: (v: string) => void
  options: { value: string; label: string }[]
  label?: string
  mono?: boolean
}) {
  return (
    <label className="inline-flex items-center gap-1.5 whitespace-nowrap text-[12px] text-muted">
      {label && <span>{label}</span>}
      <select
        value={value}
        onChange={(e) => onChange?.(e.target.value)}
        className={`h-7 rounded border border-line-strong bg-panel px-1.5 text-[12px] text-fg outline-none focus:border-accent ${mono ? 'font-mono' : ''}`}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  )
}

export function Toggle({ checked, onChange, label }: { checked: boolean; onChange?: (v: boolean) => void; label: string }) {
  return (
    <label className="inline-flex cursor-pointer select-none items-center gap-1.5 whitespace-nowrap text-[12px] text-muted">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange?.(e.target.checked)}
        className="h-3.5 w-3.5 accent-[var(--mx-accent)]"
      />
      <span className={checked ? 'text-fg' : ''}>{label}</span>
    </label>
  )
}

export function Flag({ on, label }: { on: boolean; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-[12px]">
      <span className={`h-2 w-2 rounded-full border ${on ? 'border-accent bg-accent' : 'border-line-strong'}`} aria-hidden />
      <span className="text-muted">{label}</span>
      <span className="font-mono text-[12px]">{on ? 'yes' : 'no'}</span>
    </span>
  )
}

export function ReviewMark({ value, onChange }: { value: string; onChange?: (v: string) => void }) {
  const tone = value === 'Reviewed' ? 'text-accent' : value === 'Skip' ? 'text-faint' : 'text-muted'
  return (
    <select
      value={value}
      onClick={(e) => e.stopPropagation()}
      onChange={(e) => onChange?.(e.target.value)}
      className={`h-6 rounded border border-transparent bg-transparent px-0.5 text-[12px] outline-none hover:border-line-strong focus:border-accent ${tone}`}
      title="Local review mark. Stored in this browser only; never written into the spectrum."
    >
      <option>Unreviewed</option>
      <option>Reviewed</option>
      <option>Skip</option>
    </select>
  )
}
