import React, { useState } from 'react'
import { useAuth } from '../auth/AuthContext'
import { Link, useLocation } from 'react-router-dom'
import { LogOut, User, Ticket, Menu, X, Bell } from 'lucide-react'
import ConfirmModal from './modals/ConfirmModal'
import { useNotifications } from '../auth/NotificationProvider'
import NotificationPage from './NotificationsPage'

const Navbar = () => {
  const { userRole, logout } = useAuth()
  const { unreadCount } = useNotifications()
  const [loading, setLoading] = useState(false)
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false)
  const [showNotifications, setShowNotifications] = useState(false)
  const location = useLocation()

  const getNavItems = () => {
    switch (userRole) {
      case 'ADMIN':
        return [
          { label: 'Dashboard', path: '/admin/dashboard' },
          { label: 'Agents', path: '/admin/agent-manage' }, // Shortened for middle breakpoints
          { label: 'Clients', path: '/admin/client-manage' }, // Shortened for middle breakpoints
          { label: 'Users', path: '/admin/user-manage' },     // Shortened for middle breakpoints
          { label: 'SLA', path: '/admin/sla' },               // Shortened for middle breakpoints
          { label: 'About', path: '/about' },
        ]
      case 'AGENT':
        return [
          { label: 'Dashboard', path: '/agent/dashboard' },
          { label: 'Manage', path: '/agents/requests/' },
          { label: 'Assigned', path: '/agent/assigned-tickets' },
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
          { label: 'Guideline', path: '/client/guideline' },
          { label: 'About', path: '/about' },
        ]
    }
  }

  const navItems = getNavItems()
  const closeMobileMenu = () => setIsMobileMenuOpen(false)

  return (
    <header className="w-full bg-white border-b border-gray-200 sticky top-0 z-50">
      {/* Changed md:px-4 to safe padding distributions */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
        
        {/* Left Section: Logo and Desktop Nav */}
        {/* Added min-w-0 layout rendering safeguards */}
        <div className="flex items-center gap-4 lg:gap-8 min-w-0 flex-1">
          <Link to="/" className="flex items-center gap-2 flex-shrink-0" onClick={closeMobileMenu}>
            <div className="bg-green-100 p-1 rounded">
              <Ticket className="w-5 h-5 text-green-600" strokeWidth={2.5} />
            </div>
            <span className="font-bold text-xl tracking-tight text-[#0f172a] hidden sm:block">TicketFlow</span>
          </Link>

          {/* Desktop Nav: Dynamically adjusts gaps and hides extra elements between 768px-1024px */}
          <nav className="hidden md:flex items-center gap-2 lg:gap-6 min-w-0 overflow-x-auto no-scrollbar py-1">
            {navItems.map((item) => (
              <Link
                key={item.label}
                to={item.path}
                className={`text-xs lg:text-sm font-semibold transition-colors whitespace-nowrap px-2 py-1 rounded-md ${
                  location.pathname === item.path
                    ? 'text-black bg-gray-50'
                    : 'text-gray-500 hover:text-black hover:bg-gray-50/50'
                }`}
              >
                {item.label}
              </Link>
            ))}
          </nav>
        </div>

        {/* Right Section: Actions */}
        <div className="flex items-center gap-2 sm:gap-4 flex-shrink-0">
          
          {/* Notification Bell */}
          <div className="relative z-50">
            <button
              onClick={() => setShowNotifications(prev => !prev)}
              className="relative p-1.5 rounded-full hover:bg-gray-100 transition-colors text-gray-600 hover:text-black"
            >
              <Bell size={20} />
              {unreadCount > 0 && (
                <span className="absolute -top-1 -right-1 bg-red-500 text-white text-[9px] font-bold rounded-full h-4 min-w-[16px] px-1 flex items-center justify-center">
                  {unreadCount}
                </span>
              )}
            </button>

            <NotificationPage
              isOpen={showNotifications}
              onClose={() => setShowNotifications(false)}
            />
          </div>

          {/* Desktop Only Actions */}
          <div className="hidden md:flex items-center border-l border-gray-200 pl-2 lg:pl-4">
            <button
              onClick={() => setIsModalOpen(true)}
              className="text-gray-500 hover:text-red-600 transition-colors p-1.5 rounded-full hover:bg-gray-50"
              title="Logout"
            >
              <LogOut className="w-4 h-4 lg:w-5 h-5" />
            </button>
          </div>

          {/* User Profile */}
          <div className="flex items-center gap-1.5">
            <Link 
              to='/profile' 
              className="p-1.5 bg-gray-50 rounded-full border border-gray-200 hover:bg-gray-100 transition-colors"
              onClick={closeMobileMenu}
            >
              <User className="w-3.5 h-3.5 text-gray-600" />
            </Link>
            {/* Hidden completely between 768px and 1024px to claim horizontal real estate space */}
            <Link to='/profile' className="hidden lg:block" onClick={closeMobileMenu}>
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
            {isMobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
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
                className={`block px-3 py-2.5 rounded-md text-base font-medium ${
                  location.pathname === item.path
                    ? 'bg-green-50 text-green-700'
                    : 'text-gray-600 hover:bg-gray-50 hover:text-black'
                }`}
              >
                {item.label}
              </Link>
            ))}

            <div className="pt-2 mt-2 border-t border-gray-100">
              <button
                onClick={() => {
                  closeMobileMenu()
                  setIsModalOpen(true)
                }}
                className="flex w-full items-center gap-3 px-3 py-2.5 text-base font-medium text-red-600 hover:bg-red-50 rounded-md transition-colors"
              >
                <LogOut className="w-5 h-5" />
                Logout
              </button>
            </div>
          </nav>
        </div>
      )}

      {/* Confirmation Modal */}
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