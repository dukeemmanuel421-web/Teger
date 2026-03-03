export default function JsonViewer({ data }) {
  return <pre className="text-xs bg-slate-950 border border-slate-700 rounded p-3 overflow-auto">{JSON.stringify(data, null, 2)}</pre>
}
