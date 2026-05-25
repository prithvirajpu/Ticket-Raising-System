import React, { useState } from 'react'
import { useAuth } from '../auth/AuthContext'
import { Link, useLocation } from 'react-router-dom'
import { LogOut, User, Ticket, Menu, X } from 'lucide-react'
import ConfirmModal from './modals/ConfirmModal'

const Navbar = () => {
  const { userRole, logout } = useAuth()
  const [loading, setLoading] = useState(false)
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false)
  const location = useLocation()

  // Define nav items for each role
  const getNavItems = () => {
    switch (userRole) {
      case 'ADMIN':
        return [
          { label: 'Dashboard', path: '/admin/dashboard' },
          { label: 'Agent Management', path: '/admin/agent-manage' },
          { label: 'Client Management', path: '/admin/client-manage' },
          { label: 'User Management', path: '/admin/user-manage' },
          { label: 'SLA Rules', path: '/admin/sla' },
          { label: 'Hierarchy', path: '/admin/hierarchy' },
          { label: 'About', path: '/about' },
        ]
      case 'AGENT':
        return [
          { label: 'Dashboard', path: '/agent/dashboard' },
          { label: 'Manage Tickets', path: '/agents/requests/' },
          { label: 'Assigned Tickets', path: '/agent/assigned-tickets' },
          { label: 'Summary', path: '/agent/summary' },
          { label: 'Practice', path: '/agent/practice' },
          { label: 'About', path: '/about' },
        ]
      case 'TEAM_LEAD':
        return [
          { label: 'Dashboard', path: '/team-lead/dashboard' },
          { label: 'Team Tickets', path: '/team-lead/assigned-tickets' },
          { label: 'Summary', path: '/team-lead/summaries' },
          { label: 'About', path: '/about' },
        ]
      case 'MANAGER':
        return [
          { label: 'Dashboard', path: '/manager/dashboard' },
          { label: 'Manage Tickets', path: '/tickets/manager/tickets' },
          { label: 'Clients', path: '/manager/clients' },
          { label: 'About', path: '/about' },
        ]
      case 'USER':
        return [
          { label: 'Dashboard', path: '/user/dashboard' },
          { label: 'My Tickets', path: '/user/tickets' },
          { label: 'About', path: '/about' },
        ]
      case 'CLIENT':
      default:
        return [
          { label: 'Dashboard', path: '/client/dashboard' },
          { label: 'My Tickets', path: '/client/tickets' },
          { label: 'Upload', path: '/client/upload' },
          { label: 'Plans', path: '/client/plans' },
          { label: 'About', path: '/about' },
        ]
    }
  }

  const navItems = getNavItems()

  // Helper to close mobile menu when navigating
  const closeMobileMenu = () => setIsMobileMenuOpen(false)

  return (
    <header className="w-full bg-white border-b border-gray-200 sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Left Section: Logo and Desktop Nav */}
        <div className="flex items-center gap-8 lg:gap-12">
          <Link to="/" className="flex items-center gap-2 flex-shrink-0" onClick={closeMobileMenu}>
            <div className="bg-green-100 p-1 rounded">
              <Ticket className="w-5 h-5 text-green-600" strokeWidth={2.5} />
            </div>
            <span className="font-bold text-xl tracking-tight text-[#0f172a]">TicketFlow</span>
          </Link>

          <nav className="hidden md:flex items-center gap-4 lg:gap-8">
            {navItems.map((item) => (
              <Link
                key={item.label}
                to={item.path}
                className={`text-sm font-semibold transition-colors whitespace-nowrap ${
                  location.pathname === item.path
                    ? 'text-black'
                    : 'text-gray-500 hover:text-black'
                }`}
              >
                {item.label}
              </Link>
            ))}
          </nav>
        </div>

        {/* Right Section: Actions */}
        <div className="flex items-center gap-2 sm:gap-6">
          {/* Desktop Only Actions */}
          <div className="hidden md:flex items-center gap-6 border-r border-gray-200 pr-6">
            <button
              onClick={() => setIsModalOpen(true)}
              className="text-gray-500 hover:text-red-600 transition-colors p-1"
              title="Logout"
            >
              <LogOut className="w-5 h-5" />
            </button>
          </div>

          {/* User Profile - Visible on all screens, but smaller on mobile */}
          <div className="flex items-center gap-2 sm:pl-2">
            <Link 
              to='/profile' 
              className="p-1.5 bg-gray-50 rounded-full border border-gray-200 hover:bg-gray-100 transition-colors"
              onClick={closeMobileMenu}
            >
              <User className="w-4 h-4 text-gray-600" />
            </Link>
            <Link to='/profile' className="hidden sm:block" onClick={closeMobileMenu}>
              <span className="text-sm font-medium text-gray-700 capitalize">
                {userRole?.toLowerCase() || 'Company'}
              </span>
            </Link>
          </div>

          {/* Mobile Menu Toggle Button */}
          <button 
            className="md:hidden p-2 text-gray-600 hover:bg-gray-100 rounded-md transition-colors"
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
          >
            {isMobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>
      </div>

      {/* Mobile Navigation Dropdown */}
      {isMobileMenuOpen && (
        <div className="md:hidden bg-white border-b border-gray-200 animate-in fade-in slide-in-from-top-2 duration-200">
          <nav className="flex flex-col px-4 pt-2 pb-6 space-y-1">
            {navItems.map((item) => (
              <Link
                key={item.label}
                to={item.path}
                onClick={closeMobileMenu}
                className={`block px-3 py-3 rounded-md text-base font-medium ${
                  location.pathname === item.path
                    ? 'bg-green-50 text-green-700'
                    : 'text-gray-600 hover:bg-gray-50 hover:text-black'
                }`}
              >
                {item.label}
              </Link>
            ))}
            <div className="pt-4 mt-4 border-t border-gray-100">
              <button
                onClick={() => {
                  closeMobileMenu()
                  setIsModalOpen(true)
                }}
                className="flex w-full items-center gap-3 px-3 py-3 text-base font-medium text-red-600 hover:bg-red-50 rounded-md transition-colors"
              >
                <LogOut className="w-5 h-5" />
                Logout
              </button>
            </div>
          </nav>
        </div>
      )}

      <ConfirmModal
        isOpen={isModalOpen}
        title="Confirm Logout"
        message="Are you sure you want to logout?"
        confirmText="Logout"
        loadingText="Logging out..."
        onCancel={() => setIsModalOpen(false)}
        onConfirm={async () => {
          setLoading(true)
          try {
            await logout()
          } finally {
            setLoading(false)
            setIsModalOpen(false)
          }
        }}
        loading={loading}
      />
    </header>
  )
}

export default Navbar