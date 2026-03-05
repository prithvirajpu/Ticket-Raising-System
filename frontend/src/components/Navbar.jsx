import React, { useState } from 'react'
import { useAuth } from '../auth/AuthContext'
import { Link, useLocation } from 'react-router-dom'
import { LogOut, User, Ticket } from 'lucide-react' 
import ConfirmModal from './modals/ConfirmModal'

const Navbar = () => {
  const { userRole, logout } = useAuth()
  const [loading,setLoading]=useState(false)
  const [isModalOpen,setIsModalOpen]=useState(false)
  const location = useLocation()

  // Helper to determine dashboard link based on role
  const getDashboardLink = () => {
    if (userRole === "ADMIN") return "/admin/dashboard";
    if (userRole === "AGENT") return "/agent/dashboard";
    return "/client/dashboard";
  }

  const navItems = [
    { label: 'Dashboard', path: getDashboardLink() },
    { label: 'Agent Management', path: '/admin/agent-manage' },
    { label: 'Client Management', path: '/admin/client-manage' },
    { label: 'About', path: '/about' },
  ]

  return (
    <header className="w-full bg-white border-b border-gray-200">
      <div className="max-w-7xl mx-auto px-8 h-16 flex items-center justify-between">
        
        {/* Left Section: Logo and Nav Links */}
        <div className="flex items-center gap-12">
          <Link to="/" className="flex items-center gap-2">
            <div className="bg-green-100 p-1 rounded">
              <Ticket className="w-5 h-5 text-green-600" strokeWidth={2.5} />
            </div>
            <span className="font-bold text-xl tracking-tight text-[#0f172a]">TicketFlow</span>
          </Link>

          <nav className="hidden md:flex items-center gap-8">
            {navItems.map((item) => (
              <Link
                key={item.label}
                to={item.path}
                className={`text-sm font-semibold transition-colors ${
                  location.pathname === item.path ? 'text-black' : 'text-gray-500 hover:text-black'
                }`}
              >
                {item.label}
              </Link>
            ))}
          </nav>
        </div>

        <div className="flex items-center gap-6">
          <button 
            onClick={()=>setIsModalOpen(true)}
            className="text-gray-700 hover:text-red-600 transition-colors p-1"
            title="Logout"
          >
            <LogOut className="w-5 h-5" />
          </button>
          
          <div className="flex items-center gap-2 pl-2 border-l border-gray-200">
            <div className="p-1.5 bg-gray-50 rounded-full border border-gray-200">
              <User className="w-4 h-4 text-gray-600" />
            </div>
            <span className="text-sm font-medium text-gray-700 capitalize">
              {userRole?.toLowerCase() || 'Company'}
            </span>
          </div>
        </div>

      </div>
      <ConfirmModal isOpen={isModalOpen} title='Confirm Logout' message='Are you sure you want to logout?' 
      confirmText='Logout' loadingText='Logging out...' onCancel={()=>setIsModalOpen(false)} 
      onConfirm={async()=>{
        setLoading(true);
        try {
          logout();
        } finally {
          setLoading(false)
          setIsModalOpen(false);
        }
      }} loading={loading} />
    </header>
  )
}

export default Navbar