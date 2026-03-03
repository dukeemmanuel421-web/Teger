import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { apiFetch } from '../api/client'
import RiskBadge from '../components/RiskBadge'
import TacticChips from '../components/TacticChips'

const scenarios = [
  ['CEO urgent transfer', { sender: 'ceo@company-mail.com', platform: 'email', content: 'Urgent: wire $75,000 now to new legal escrow. Keep confidential.' }],
  ['Invoice account switch', { sender: 'vendor@billing-alerts.com', platform: 'email', content: 'Please update remit account details for invoice INV-9001. New bank attached.' }],
  ['Fake bank alert', { sender: 'security@bank-safe-alert.com', platform: 'sms', content: 'Your account will be frozen. Verify OTP and password at http://bank-safe-reset.co' }],
  ['Gift card scam', { sender: 'exec-assistant@outlookmail.co', platform: 'chat', content: 'Need 25 gift cards for board guests now. Send codes immediately.' }],
  ['Payroll diversion', { sender: 'employee.personal@gmail.com', platform: 'email', content: 'Changed salary account; update payroll to 1234567890 before noon.' }],
  ['Benign request', { sender: 'ap@trustedvendor.com', platform: 'email', content: 'Sharing monthly statement and asking for payment confirmation by Friday.' }],
]

export default function Dashboard() {
  const nav = useNavigate()
  const [form, setForm] = useState({ sender: '', platform: 'email', content: '' })
  const [demoMode, setDemoMode] = useState(true)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  const analyze = async () => {
    setError('')
    try {
      const data = await apiFetch('/v1/analyze', { method: 'POST', body: JSON.stringify(form) })
      setResult(data)
      localStorage.setItem('lastAnalysis', JSON.stringify(data))
      localStorage.setItem('demoMode', JSON.stringify(demoMode))
    } catch (e) { setError(e.message) }
  }

  return (
    <div className="p-6 space-y-4">
      {demoMode && <div className="card border-cyan-700">Demo Mode ON: mock payment checks prioritized for reliability.</div>}
      <div className="card">
        <div className="flex items-center justify-between"><h2 className="text-xl font-bold">Message Analysis</h2>
        <label><input type="checkbox" checked={demoMode} onChange={e=>setDemoMode(e.target.checked)} /> Demo Mode</label></div>
        <div className="grid gap-3 mt-3">
          <input className="input" placeholder="sender" value={form.sender} onChange={e=>setForm({...form, sender:e.target.value})} />
          <input className="input" placeholder="platform" value={form.platform} onChange={e=>setForm({...form, platform:e.target.value})} />
          <textarea className="input min-h-36" placeholder="content" value={form.content} onChange={e=>setForm({...form, content:e.target.value})} />
          <button className="btn" onClick={analyze}>Analyze</button>
          {error && <p className="text-red-400 text-sm">{error}</p>}
        </div>
      </div>
      <div className="card"><h3 className="font-semibold mb-2">Demo Scenarios</h3><div className="flex gap-2 flex-wrap">
        {scenarios.map(([label, val])=> <button className="btn" key={label} onClick={()=>setForm(val)}>{label}</button>)}
      </div></div>
      {result && <div className="card space-y-3">
        <div className="flex items-center justify-between"><RiskBadge level={result.threat_level} score={result.risk_score} /><span>Provider: {result.provider}</span></div>
        <div>Risk Gauge: <progress value={result.risk_score} max="100" className="w-full" /></div>
        <TacticChips title="Categories" items={result.categories} />
        <TacticChips title="Tactics" items={result.tactics} />
        <TacticChips title="Triggers" items={result.triggers} />
        <div className="card"><strong>Recommended action:</strong> {result.recommended_action}<p>{result.user_message}</p></div>
        <button className="btn" onClick={()=>nav('/payment-guard')}>Create Guardrail Decision</button>
      </div>}
    </div>
  )
}
