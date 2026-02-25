import React from 'react'
import Navbar from '../components/Navbar'

const DashboardLayout = ({title,subtitle,headerAction,children}) => {
  return (
        <div className="min-h-screen bg-white">
          <Navbar />
          <main className="max-w-7xl mx-auto p-8">
            <div className="flex justify-between items-start mb-8">
              <div>
                <h1 className="text-4xl font-bold text-black mb-2">{title}</h1>
                {subtitle && <p className="text-gray-400 text-sm">{subtitle}</p>}
              </div>
              {headerAction && <div>{headerAction}</div>}
            </div>
            {children}
          </main>
        </div>
  )
}

export default DashboardLayout
