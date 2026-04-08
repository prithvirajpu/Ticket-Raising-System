import React from 'react'
import Navbar from '../components/Navbar'
import useAgentTimer from '../hooks/useAgentTimer'

const DashboardLayout = ({ title, subtitle, headerAction, children }) => {
  const seconds = useAgentTimer() // global timer

  // Format seconds to hh:mm:ss
  const formatTime = (secs) => {
    const h = Math.floor(secs / 3600)
    const m = Math.floor((secs % 3600) / 60)
    const s = secs % 60
    return `${h.toString().padStart(2, '0')}h ${m
      .toString()
      .padStart(2, '0')}m ${s.toString().padStart(2, '0')}s`
  }

  return (
    <div className="min-h-screen bg-white">
      <Navbar />
      <main className="max-w-7xl mx-auto p-6">
        <div className="flex justify-between items-start mb-8">
          <div>
            <h1 className="text-4xl font-bold text-black mb-2">{title}</h1>
            {subtitle && <p className="text-gray-400 text-sm">{subtitle}</p>}
          </div>

          <div className="flex items-center gap-4">
            <span className="font-mono text-sm font-medium text-zinc-100 tabular-nums">
              {formatTime(seconds)}
            </span>

            {/* Optional custom header action */}
            {headerAction && <div>{headerAction}</div>}
          </div>
        </div>

        {children}
      </main>
    </div>
  )
}

export default DashboardLayout