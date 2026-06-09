import React, { useEffect } from 'react'
import Navbar from '../components/Navbar'

const DashboardLayout = ({ title, subtitle, headerAction, children }) => {
  return (
    <div className="min-h-screen bg-white w-full flex flex-col overflow-x-hidden">
      <Navbar />
      
      {/* Optimized wrapper container for table/grid protections */}
      <main className="w-full max-w-7xl mx-auto p-4 sm:p-6 flex-1 min-w-0">
        
        {/* Header container blocks */}
        <div className="flex flex-col sm:flex-row justify-between items-start gap-4 mb-6 sm:mb-8 w-full">
          <div className="min-w-0">
            <h1 className="text-2xl sm:text-4xl font-bold text-black mb-2 tracking-tight truncate">
              {title}
            </h1>
            {subtitle && <p className="text-gray-400 text-xs sm:text-sm">{subtitle}</p>}
          </div>
          {headerAction && <div className="flex-shrink-0 w-full sm:w-auto">{headerAction}</div>}
        </div>

        {/* Dynamic User Area View Content */}
        <div className="w-full min-w-0 overflow-hidden">
          {children}
        </div>
        
      </main>
    </div>
  )
}

export default DashboardLayout