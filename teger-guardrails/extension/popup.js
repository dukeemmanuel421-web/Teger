const out = document.getElementById('out')
document.getElementById('scan').onclick = async () => {
  const api = document.getElementById('api').value
  const sender = document.getElementById('sender').value
  const content = document.getElementById('content').value
  try {
    const res = await fetch(`${api}/v1/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sender, content, platform: 'extension' })
    })
    const data = await res.json()
    out.textContent = `Risk: ${data.risk_score}\nLevel: ${data.threat_level}\nTactics: ${(data.tactics||[]).slice(0,3).join(', ')}`
  } catch (e) { out.textContent = e.message }
}
