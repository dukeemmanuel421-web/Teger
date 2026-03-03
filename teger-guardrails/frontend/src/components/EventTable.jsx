export default function EventTable({ items, onSelect }) {
  return (
    <table className="w-full text-sm">
      <thead>
        <tr className="text-left border-b border-slate-800">
          <th>ID</th><th>Time</th><th>Sender</th><th>Level</th><th>Score</th>
        </tr>
      </thead>
      <tbody>
        {items.map((e) => (
          <tr key={e.id} className="border-b border-slate-900 hover:bg-slate-900 cursor-pointer" onClick={() => onSelect(e)}>
            <td>{e.id.slice(0, 8)}</td><td>{new Date(e.created_at).toLocaleString()}</td><td>{e.sender}</td><td>{e.threat_level}</td><td>{e.risk_score}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
