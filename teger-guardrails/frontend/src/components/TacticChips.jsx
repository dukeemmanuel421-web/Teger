export default function TacticChips({ title, items = [] }) {
  return (
    <div>
      <h4 className="font-semibold mb-2">{title}</h4>
      <div className="flex flex-wrap gap-2">
        {items.map((i) => <span key={i} className="text-xs bg-slate-800 rounded-full px-2 py-1">{i}</span>)}
      </div>
    </div>
  )
}
