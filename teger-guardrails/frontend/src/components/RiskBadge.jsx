export default function RiskBadge({ level, score }) {
  const color = {
    LOW: 'bg-emerald-600',
    MEDIUM: 'bg-amber-600',
    HIGH: 'bg-orange-600',
    CRITICAL: 'bg-red-600',
  }[level] || 'bg-slate-600'
  return <span className={`px-3 py-1 rounded-full text-xs font-bold ${color}`}>{level} · {score}</span>
}
