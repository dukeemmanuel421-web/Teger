import { useMemo, useState } from 'react'
import { apiFetch } from '../api/client'

export default function PaymentGuard() {
  const analysis = useMemo(() => JSON.parse(localStorage.getItem('lastAnalysis') || 'null'), [])
  const demoMode = JSON.parse(localStorage.getItem('demoMode') || 'true')
  const [intent, setIntent] = useState({ accountNumber: '', bankCode: '', beneficiaryName: '', amount: 0, narration: '' })
  const [inquiry, setInquiry] = useState(null)
  const [decision, setDecision] = useState(null)
  const [error, setError] = useState('')

  const runInquiry = async () => {
    setError('')
    try {
      const data = await apiFetch('/v1/payments/guard/credit-inquiry', { method: 'POST', body: JSON.stringify(intent) })
      setInquiry(data)
    } catch (e) { setError(e.message) }
  }

  const runDecision = async () => {
    setError('')
    try {
      if (!analysis) throw new Error('Run an analysis first from Dashboard.')
      const data = await apiFetch('/v1/payments/guard/decision', {
        method: 'POST',
        body: JSON.stringify({ analysis, payment_intent: intent })
      })
      setDecision(data)
    } catch (e) { setError(e.message) }
  }

  return (
    <div className="p-6 space-y-4">
      {demoMode && <div className="card border-cyan-700">Demo Mode ON (credit inquiry should be mock unless backend is live-enabled).</div>}
      <div className="card grid gap-2">
        <h2 className="text-xl font-bold">Payment Guardrail Simulator</h2>
        {['accountNumber','bankCode','beneficiaryName','amount','narration'].map((k)=><input key={k} className="input" placeholder={k} value={intent[k]} onChange={e=>setIntent({...intent,[k]:e.target.value})} />)}
        <div className="flex gap-2"><button className="btn" onClick={runInquiry}>Credit Inquiry</button><button className="btn" onClick={runDecision}>Guardrail Decision</button></div>
        {error && <p className="text-red-400 text-sm">{error}</p>}
      </div>
      {inquiry && <div className="card"><h3 className="font-semibold">Inquiry ({inquiry.mode})</h3><pre>{JSON.stringify(inquiry.data, null, 2)}</pre></div>}
      {decision && <div className="card"><h3 className="text-xl font-bold">{decision.decision}</h3><p>{decision.rationale}</p><p>Checks: {decision.required_checks.join(', ')}</p></div>}
    </div>
  )
}
