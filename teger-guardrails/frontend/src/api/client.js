const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export async function apiFetch(path, options = {}, timeoutMs = 12000) {
  const controller = new AbortController()
  const id = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const res = await fetch(`${API_URL}${path}`, {
      ...options,
      headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
      signal: controller.signal,
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) throw new Error(data.detail || data.error || 'Request failed')
    return data
  } catch (err) {
    if (err.name === 'AbortError') throw new Error('Request timed out. Please retry.')
    throw new Error(`API error: ${err.message}`)
  } finally {
    clearTimeout(id)
  }
}

export { API_URL }
