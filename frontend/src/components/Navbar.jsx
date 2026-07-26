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

  const isUserTheme = userRole === 'USER'

  const getNavItems = () => {
    switch (userRole) {
      case 'ADMIN':
        return [
          { label: 'Dashboard', path: '/admin/dashboard' },
          { label: 'Agents', path: '/admin/agent-manage' },
          { label: 'Clients', path: '/admin/client-manage' },
          { label: 'Users', path: '/admin/user-manage' },
          { label: 'SLA', path: '/admin/sla' },
          { label: 'Wallet', path: '/admin/wallet-transactions' },
          { label: 'Revenue', path: '/admin/finance' },
          { label: 'About', path: '/about' },
        ]
      case 'AGENT':
        return [
          { label: 'Dashboard', path: '/agent/dashboard' },
          { label: 'Manage', path: '/agents/requests/' },
          { label: 'Assigned', path: '/agent/assigned-tickets' },
          { label: 'Summary', path: '/agent/summary' },
          { label: 'Practice', path: '/agent/practice' },
          { label: 'Wallet', path: '/wallet' },
          { label: 'About', path: '/about' },
        ]
      case 'TEAM_LEAD':
        return [
          { label: 'Dashboard', path: '/team-lead/dashboard' },
          { label: 'Team Tickets', path: '/team-lead/assigned-tickets' },
          { label: 'Summary', path: '/team-lead/summaries' },
          { label: 'Wallet', path: '/wallet' },
          { label: 'About', path: '/about' },
        ]
      case 'MANAGER':
        return [
          { label: 'Dashboard', path: '/manager/dashboard' },
          { label: 'Manage Tickets', path: '/tickets/manager/tickets' },
          { label: 'Clients', path: '/manager/clients' },
          { label: 'Wallet', path: '/wallet' },
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
          { label: 'Upload', path: '/client/upload' },
          { label: 'Plans', path: '/client/plans' },
          { label: 'Guideline', path: '/client/guideline' },
          { label: 'About', path: '/about' },
        ]
    }
  }

  const navItems = getNavItems()
  const closeMobileMenu = () => setIsMobileMenuOpen(false)

  // Dynamic Theme Styling Classes
  const headerBg = isUserTheme ? 'bg-[#0f172a] border-slate-800' : 'bg-white border-gray-200'
  const textPrimary = isUserTheme ? 'text-slate-100' : 'text-[#0f172a]'
  const textSecondary = isUserTheme ? 'text-slate-400 hover:text-white' : 'text-gray-500 hover:text-black'
  const hoverBg = isUserTheme ? 'hover:bg-slate-800/60' : 'hover:bg-gray-50'
  const activeNavItem = isUserTheme ? 'text-emerald-400 bg-slate-800' : 'text-black bg-gray-50'
  const inactiveNavItem = isUserTheme ? 'text-slate-400 hover:text-emerald-400 hover:bg-slate-800/40' : 'text-gray-500 hover:text-black hover:bg-gray-50/50'

  return (
    <header className={`w-full border-b sticky top-0 z-50 transition-colors duration-300 font-sans ${headerBg}`}>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
        
        {/* Left Section: Logo and Desktop Nav */}
        <div className="flex items-center gap-4 lg:gap-8 min-w-0 flex-1">
          <Link to="/" className="flex items-center gap-2 flex-shrink-0" onClick={closeMobileMenu}>
            <div className={`p-1.5 rounded-lg transition-colors ${isUserTheme ? 'bg-emerald-950/50 border border-emerald-500/20' : 'bg-green-100'}`}>
              <Ticket className={`w-5 h-5 ${isUserTheme ? 'text-emerald-400' : 'text-green-600'}`} strokeWidth={2.5} />
            </div>
            <span className={`font-bold text-xl tracking-tight hidden sm:block ${textPrimary}`}>
              TicketFlow
            </span>
          </Link>

          {/* Desktop Nav */}
          <nav className="hidden lg:flex items-center gap-3 min-w-0 py-1">
            {navItems.map((item) => (
              <Link
                key={item.label}
                to={item.path}
                className={`text-sm font-medium transition-all duration-200 whitespace-nowrap px-3 py-1.5 rounded-md ${
                  location.pathname === item.path ? activeNavItem : inactiveNavItem
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
              className={`relative p-2 rounded-full transition-all duration-200 ${
                isUserTheme ? 'text-slate-400 hover:text-emerald-400 hover:bg-slate-800' : 'text-gray-600 hover:text-black hover:bg-gray-100'
              }`}
            >
              <Bell size={20} />
              {unreadCount > 0 && (
                <span className="absolute -top-0.5 -right-0.5 bg-red-500 text-white text-[9px] font-bold rounded-full h-4 min-w-[16px] px-1 flex items-center justify-center border-2 border-transparent">
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
          <div className={`hidden lg:flex items-center border-l pl-4 ${isUserTheme ? 'border-slate-800' : 'border-gray-200'}`}>
            <button
              onClick={() => setIsModalOpen(true)}
              className={`transition-all duration-200 p-2 rounded-full ${
                isUserTheme ? 'text-slate-400 hover:text-red-400 hover:bg-slate-850' : 'text-gray-500 hover:text-red-600 hover:bg-gray-50'
              }`}
              title="Logout"
            >
              <LogOut className="w-5 h-5" />
            </button>
          </div>

          {/* User Profile */}
          <div className="flex items-center gap-2">
            <Link 
              to='/profile' 
              className={`p-2 rounded-full border transition-all duration-200 ${
                isUserTheme ? 'bg-slate-800/80 border-slate-700 hover:bg-slate-800 hover:border-slate-600' : 'bg-gray-50 border-gray-200 hover:bg-gray-100'
              }`}
              onClick={closeMobileMenu}
            >
              <User className={`w-3.5 h-3.5 ${isUserTheme ? 'text-slate-300' : 'text-gray-600'}`} />
            </Link>
            <Link to='/profile' className="hidden lg:block" onClick={closeMobileMenu}>
              <span className={`text-sm font-semibold capitalize tracking-wide transition-colors ${
                isUserTheme ? 'text-slate-200 hover:text-emerald-400' : 'text-gray-700'
              }`}>
                {userRole?.toLowerCase() || 'Company'}
              </span>
            </Link>
          </div>

          {/* Mobile Menu Toggle Button */}
          <button 
            className={`lg:hidden p-2 rounded-md transition-colors ${
              isUserTheme ? 'text-slate-400 hover:text-white hover:bg-slate-800' : 'text-gray-600 hover:bg-gray-100'
            }`}
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
          >
            {isMobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
      </div>

      {/* Mobile Navigation Dropdown */}
      {isMobileMenuOpen && (
        <div className={`lg:hidden border-b animate-in fade-in slide-in-from-top-2 duration-200 ${isUserTheme ? 'bg-[#0f172a] border-slate-800' : 'bg-white border-gray-200'}`}>
          <nav className="flex flex-col px-4 pt-2 pb-6 space-y-1">
            {navItems.map((item) => (
              <Link
                key={item.label}
                to={item.path}
                onClick={closeMobileMenu}
                className={`block px-3 py-2.5 rounded-md text-base font-medium transition-colors ${
                  location.pathname === item.path
                    ? isUserTheme ? 'bg-slate-800 text-emerald-400' : 'bg-green-50 text-green-700'
                    : isUserTheme ? 'text-slate-300 hover:bg-slate-800/50 hover:text-white' : 'text-gray-600 hover:bg-gray-50 hover:text-black'
                }`}
              >
                {item.label}
              </Link>
            ))}

            <div className={`pt-2 mt-2 border-t ${isUserTheme ? 'border-slate-800' : 'border-gray-100'}`}>
              <button
                onClick={() => {
                  closeMobileMenu()
                  setIsModalOpen(true)
                }}
                className={`flex w-full items-center gap-3 px-3 py-2.5 text-base font-medium rounded-md transition-colors ${
                  isUserTheme ? 'text-red-400 hover:bg-red-950/20' : 'text-red-600 hover:bg-red-50'
                }`}
              >
                <LogOut className="w-5 h-5" />
                Logout
              </button>
            </div>
          </nav>
        </div>
      )}

      {/* Confirmation Modal Wrapper (Ensuring strict center-alignment) */}
      {isModalOpen && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm transition-opacity duration-300">
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
        </div>
      )}
    </header>
  )
}

export default Navbar