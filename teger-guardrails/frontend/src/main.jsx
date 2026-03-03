import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter, NavLink, Route, Routes } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import PaymentGuard from './pages/PaymentGuard'
import ForensicVault from './pages/ForensicVault'
import './styles.css'

function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen text-slate-100 bg-slate-950">
        <nav className="p-4 border-b border-slate-800 flex gap-4">
          <NavLink to="/" className="hover:text-cyan-300">Dashboard</NavLink>
          <NavLink to="/payment-guard" className="hover:text-cyan-300">Payment Guard</NavLink>
          <NavLink to="/forensic-vault" className="hover:text-cyan-300">Forensic Vault</NavLink>
        </nav>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/payment-guard" element={<PaymentGuard />} />
          <Route path="/forensic-vault" element={<ForensicVault />} />
        </Routes>
      </div>
    </BrowserRouter>
  )
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />)
