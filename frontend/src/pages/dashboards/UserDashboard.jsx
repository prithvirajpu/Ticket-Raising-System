import React from 'react';
import { 
  Ticket, 
  Info, 
  History, 
  CheckCircle2, 
  Plus, 
  Bell, 
  LogOut, 
  UserCircle 
} from 'lucide-react';
import { useAuth } from '../../auth/AuthContext';

const UserDashboard = () => {
  // Mock data based on your screenshot
  const stats = [
    { label: 'Total Tickets', value: 2, icon: <Ticket size={20} />, color: 'text-gray-600' },
    { label: 'Open', value: 1, icon: <Info size={20} />, color: 'text-red-500' },
    { label: 'In Progress', value: 0, icon: <History size={20} />, color: 'text-yellow-600' },
    { label: 'Resolved', value: 1, icon: <CheckCircle2 size={20} />, color: 'text-green-500', active: true },
  ];
  const {logout}=useAuth()

  return (
    <div className="min-h-screen bg-gray-50 font-sans">
      {/* Navigation Bar */}
      <nav className="flex items-center justify-between px-8 py-4 bg-white border-b border-gray-200">
        <div className="flex items-center gap-8">
          <div className="flex items-center gap-2 text-green-600 font-bold text-xl">
            <Ticket className="rotate-45" />
            <span className="text-gray-900">TicketFlow</span>
          </div>
          <div className="hidden md:flex gap-6 text-sm font-medium text-gray-700">
            <a href="#" className="hover:text-black">Dashboard</a>
            <a href="#" className="hover:text-black">My Tickets</a>
            <a href="#" className="hover:text-black">About</a>
          </div>
        </div>

        <div className="flex items-center gap-4 text-gray-600">
          <Bell size={20} className="cursor-pointer hover:text-black" />
          <LogOut onClick={logout} size={20} className="cursor-pointer hover:text-black" />
          <div className="flex items-center gap-2 ml-2">
            <UserCircle size={24} />
            <span className="text-sm font-medium text-gray-900">User_here</span>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto p-8">
        <div className="flex justify-between items-start mb-8">
          <div>
            <h1 className="text-4xl font-bold text-gray-900">My Dashboard</h1>
            <p className="text-gray-400 mt-2 text-lg">Manage your support tickets</p>
          </div>
          <button className="flex items-center gap-2 bg-black text-white px-5 py-2.5 rounded-xl font-medium hover:bg-gray-800 transition-colors">
            <Plus size={18} strokeWidth={3} />
            Raise New Ticket
          </button>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {stats.map((stat, index) => (
            <div 
              key={index}
              className={`bg-white p-6 rounded-3xl border-2 transition-all cursor-default
                ${stat.active ? 'border-blue-400 ring-1 ring-blue-400' : 'border-gray-200'}`}
            >
              <div className="flex justify-between items-start mb-4">
                <span className="font-bold text-gray-900">{stat.label}</span>
                <span className={stat.color}>{stat.icon}</span>
              </div>
              <div className="text-4xl font-bold text-gray-900">
                {stat.value}
              </div>
            </div>
          ))}
        </div>
      </main>
    </div>
  );
};

export default UserDashboard;