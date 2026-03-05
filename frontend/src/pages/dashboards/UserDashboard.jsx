import React from 'react';
import { 
  Ticket, 
  Info, 
  History, 
  CheckCircle2, 
  Plus, 
} from 'lucide-react';
import { useAuth } from '../../auth/AuthContext';
import DashboardLayout from '../../layouts/DashboardLayout';

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
    <>
      <DashboardLayout 
      title="Dashboard" 
      subtitle="Manage your assigned tickets"
      headerAction={
          <button className="flex items-center gap-2 bg-black text-white px-5 py-2.5 rounded-xl font-medium hover:bg-gray-800 transition-colors">
            <Plus size={18} strokeWidth={3} />
            Raise New Ticket
          </button>
      }
    ></DashboardLayout>
    </>
  );
};

export default UserDashboard;