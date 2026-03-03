import { useState } from 'react'
import { apiFetch } from '../api/client'
import EventTable from '../components/EventTable'
import JsonViewer from '../components/JsonViewer'

export default function ForensicVault() {
  const [filters, setFilters] = useState({ threat_level: '', category: '', q: '', from: '', to: '' })
  const [items, setItems] = useState([])
  const [selected, setSelected] = useState(null)

  const load = async () => {
    const params = new URLSearchParams(Object.entries(filters).filter(([,v])=>v))
    const data = await apiFetch(`/v1/events?${params.toString()}`)
    setItems(data.items || [])
  }

  return (
    <div className="p-6 space-y-4">
      <div className="card">
        <h2 className="text-xl font-bold">Forensic Vault</h2>
        <div className="grid grid-cols-2 gap-2 my-2">
          {Object.keys(filters).map(k => <input key={k} className="input" placeholder={k} value={filters[k]} onChange={e=>setFilters({...filters,[k]:e.target.value})} />)}
        </div>
        <button className="btn" onClick={load}>Load Events</button>
      </div>
      <div className="card"><EventTable items={items} onSelect={setSelected} /></div>
      {selected && <div className="card"><h3 className="font-semibold">Event {selected.id}</h3><JsonViewer data={selected.payload} /></div>}
    </div>
  )
}
