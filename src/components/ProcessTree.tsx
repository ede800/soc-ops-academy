import { TriangleAlert } from 'lucide-react'
import type { ProcessNode } from '../types'

function Node({ node, root = false }: { node: ProcessNode; root?: boolean }) {
  return (
    <li className={root ? '' : 'relative border-l border-line pl-5 before:absolute before:top-5 before:left-0 before:h-px before:w-4 before:bg-line last:border-l-transparent'}>
      <div className={`mb-2 rounded-md border p-2.5 ${node.flag ? 'border-amber/50 bg-amber/5' : 'border-line bg-bg'}`}>
        <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 font-mono text-[13px]">
          <span className="font-bold text-white">{node.name}</span>
          {node.pid && <span className="text-xs text-mute">PID {node.pid}</span>}
          {node.user && <span className="text-xs text-mute">{node.user}</span>}
        </div>
        {node.cmd && <p className="mt-1 font-mono text-xs break-all text-slate-300">{node.cmd}</p>}
        {node.flag && (
          <p className="mt-1.5 flex items-center gap-1.5 text-xs text-amber-300">
            <TriangleAlert size={13} aria-hidden /> {node.flag}
          </p>
        )}
      </div>
      {node.children && (
        <ul>
          {node.children.map((child, i) => (
            <Node key={`${child.name}-${i}`} node={child} />
          ))}
        </ul>
      )}
    </li>
  )
}

export function ProcessTree({ tree }: { tree: ProcessNode }) {
  return (
    <ul aria-label="Arbre des processus">
      <Node node={tree} root />
    </ul>
  )
}
