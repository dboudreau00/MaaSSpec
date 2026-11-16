import { CopyButton, Help } from './ui'
import { formatBytes, shortHash } from '../format'
import type { Artifact, Spectrum } from '../types'

export function ArtifactTree({ spectrum, onPick }: { spectrum: Spectrum; onPick: (id: string) => void }) {
  const nodes = flatten(spectrum.artifacts)
  return (
    <div>
      <div className="flex items-center gap-1.5 border-b border-line px-4 py-2 text-[12px] text-muted">
        Select an artifact to filter findings by source.
        <Help>
          Artifacts form a tree through parent links. input is the file or document MaaSSpec read. submitted_sample and
          unpacked_layer come from UnpacMe. sample_reference is a hash the input points at; the sample itself was not
          fetched.
        </Help>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[720px] border-collapse text-left">
          <thead>
            <tr className="border-b border-line text-[11px] text-muted">
              <th className="px-3 py-1.5 font-normal">id</th>
              <th className="px-3 py-1.5 font-normal">type</th>
              <th className="px-3 py-1.5 font-normal">sha256</th>
              <th className="px-3 py-1.5 text-right font-normal">size</th>
              <th className="px-3 py-1.5 font-normal">produced by</th>
              <th className="px-3 py-1.5 text-right font-normal">findings</th>
            </tr>
          </thead>
          <tbody>
            {nodes.map(({ a, depth }) => {
              const count = spectrum.findings.filter((f) => f.source === a.id).length
              return (
                <tr
                  key={a.id}
                  onClick={() => onPick(a.id)}
                  className="cursor-pointer border-b border-line transition-colors duration-100 hover:bg-raised"
                >
                  <td className="px-3 py-1.5">
                    <span className="flex items-center font-mono text-[12px]" style={{ paddingLeft: depth * 20 }}>
                      {depth > 0 && <span className="mr-1.5 text-faint">└</span>}
                      {a.id}
                    </span>
                  </td>
                  <td className="px-3 py-1.5">
                    <span className="font-mono text-[12px]">{a.type}</span>
                    <span className="ml-2 text-[12px] text-muted">{a.name}</span>
                  </td>
                  <td className="px-3 py-1.5">
                    <span className="inline-flex items-center gap-1">
                      <span className="font-mono text-[12px] text-muted">{shortHash(a.sha256)}</span>
                      {a.sha256 && <CopyButton value={a.sha256} label="Copy sha256" />}
                    </span>
                  </td>
                  <td className="tabular px-3 py-1.5 text-right font-mono text-[12px] text-muted">{formatBytes(a.size)}</td>
                  <td className="px-3 py-1.5 font-mono text-[12px] text-muted">{a.producedBy}</td>
                  <td className={`tabular px-3 py-1.5 text-right font-mono text-[12px] ${count ? '' : 'text-faint'}`}>{count}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function flatten(list: Artifact[]) {
  const out: { a: Artifact; depth: number }[] = []
  const walk = (parent: string | undefined, depth: number) => {
    for (const a of list.filter((x) => x.parent === parent)) {
      out.push({ a, depth })
      walk(a.id, depth + 1)
    }
  }
  walk(undefined, 0)
  return out
}
