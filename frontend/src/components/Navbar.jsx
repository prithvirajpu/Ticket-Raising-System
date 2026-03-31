import React, { useState } from 'react'
import { useAuth } from '../auth/AuthContext'
import { Link, useLocation } from 'react-router-dom'
import { LogOut, User, Ticket } from 'lucide-react'
import ConfirmModal from './modals/ConfirmModal'

const Navbar = () => {
  const { userRole, logout } = useAuth()
  const [loading, setLoading] = useState(false)
  const [isModalOpen, setIsModalOpen] = useState(false)
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
          { label: 'About', path: '/about' },
        ]

      case 'AGENT':
        return [
          { label: 'Dashboard', path: '/agent/dashboard' },
          { label: 'Manage Tickets', path: '/agents/requests/' },
          { label: 'Assigned Tickets', path: '/agent/assigned-tickets' },
          { label: 'About', path: '/about' },
        ]

      case 'TEAM_LEAD':
        return [
          { label: 'Dashboard', path: '/team-lead/dashboard' },
          { label: 'Team Tickets', path: '/team-lead/assigned-tickets' },
          { label: 'Reports', path: '/team-lead/reports' },
          { label: 'About', path: '/about' },
        ]

      case 'MANAGER':
        return [
          { label: 'Dashboard', path: '/manager/dashboard' },
          { label: 'Manage Tickets', path: '/tickets/manager/tickets' },
          { label: 'Reports', path: '/manager/reports' },
          { label: 'Clients', path: '/manager/clients' },
          { label: 'About', path: '/about' },
        ]

      case 'USER': // Internal user / corporate user
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
          { label: 'Upload', path: '/client/upload' }, // client has this
          { label: 'About', path: '/about' },
        ]
    }
  }

  const navItems = getNavItems()

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

        {/* Right Section: Logout + User Badge */}
        <div className="flex items-center gap-6">
          <button
            onClick={() => setIsModalOpen(true)}
            className="text-gray-700 hover:text-red-600 transition-colors p-1"
            title="Logout"
          >
            <LogOut title='logout' className="w-5 h-5" />
          </button>

          <div className="flex items-center gap-2 pl-2 border-l border-gray-200">
            <div className="p-1.5 bg-gray-50 rounded-full border border-gray-200">
              <Link to='/profile' title='Profile'><User className="w-4 h-4 text-gray-600" /></Link>
            </div>
            <Link title='Profile' to='/profile'>
            <span className="text-sm font-medium text-gray-700 capitalize">
              {userRole?.toLowerCase() || 'Company'}
            </span></Link>
          </div>
        </div>
      </div>

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
            logout()
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
