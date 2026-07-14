import React from 'react'
import Navbar from '../components/Navbar'
import { useAuth } from '../auth/AuthContext' // Added to dynamically check theme role

const DashboardLayout = ({ title, subtitle, headerAction, children }) => {
  const { userRole } = useAuth()
  
  // Dynamic dark theme check for USER role
  const isUserTheme = userRole === 'USER'

  // Dynamic Theme Styling Classes
const containerBg = isUserTheme ? 'bg-[#fbfbfa]' : 'bg-white'
const textTitle = isUserTheme ? 'text-neutral-900' : 'text-black'
const textSubtitle = isUserTheme ? 'text-neutral-500' : 'text-gray-400'
  return (
    <div className={`min-h-screen w-full flex flex-col overflow-x-hidden transition-colors duration-300 font-sans ${containerBg}`}>
      
      {/* Background structural mesh decoration strictly for USER dark mode to match the footer */}
      {isUserTheme && (
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#80808005_1px,transparent_1px),linear-gradient(to_bottom,#80808005_1px,transparent_1px)] bg-[size:32px_32px] pointer-events-none" />
      )}

      <Navbar />
      
      {/* Optimized wrapper container for table/grid protections */}
      <main className="w-full max-w-7xl mx-auto p-4 sm:p-6 flex-1 min-w-0 z-10">
        
        {/* Header container blocks */}
        <div className="flex flex-col sm:flex-row justify-between items-start gap-4 mb-6 sm:mb-8 w-full">
          <div className="min-w-0">
            <h1 className={`text-2xl sm:text-4xl font-bold mb-2 tracking-tight truncate ${textTitle}`}>
              {title}
            </h1>
            {subtitle && (
              <p className={`text-xs sm:text-sm tracking-wide ${textSubtitle}`}>
                {subtitle}
              </p>
            )}
          </div>
          {headerAction && (
            <div className="flex-shrink-0 w-full sm:w-auto">
              {headerAction}
            </div>
          )}
        </div>

        {/* Dynamic User Area View Content */}
        <div className="w-full min-w-0">
          {children}
        </div>
        
      </main>
    </div>
  )
}

export default DashboardLayout