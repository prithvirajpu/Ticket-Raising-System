import React, { useEffect, useState } from 'react';
import { 
  Ticket, 
  Info, 
  History, 
  CheckCircle2, 
  CheckCircle ,
  Plus, 
} from 'lucide-react';
import DashboardLayout from '../../layouts/DashboardLayout';
import { Link, useNavigate } from 'react-router-dom';
import StatsCard from '../../components/StatsCard';
import { getUserDashboard } from '../../services/ticketService';


const UserDashboard = () => {
  const [data,setData]=useState({})
  const navigate = useNavigate();
   
  useEffect(()=>{
    fetchData();
  },[])

    const fetchData=async()=>{
      try {
        const res= await getUserDashboard();
        setData(res.message)
      } catch (error) {
        console.log(error)
      }
    }


  return (
    <>
      <DashboardLayout 
      title="Dashboard" 
      subtitle="Manage your assigned tickets"
      
    >
      <div className="flex justify-end mb-8 -mt-16">
          <button
              onClick={() => navigate("/user/create-ticket")}
              className="flex items-center gap-2 bg-black text-white px-5 py-2.5 rounded-xl hover:bg-gray-800 transition-all text-sm font-bold"
          >
              <Plus size={18} />
              Raise New Ticket
          </button>
      </div>
      

      
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-10">
        <StatsCard 
          label="Total Tickets" 
          icon={Ticket} 
          iconColor="text-black"
          value={data.total_tickets || 0}
        />
        <StatsCard 
          label="Escalated" 
          icon={Info} 
          iconColor="text-red-500"
          value={data.escalated || 0}
        />
        <StatsCard 
          label="In Progress" 
          icon={History} 
          iconColor="text-orange-500"
          value={data.in_progress || 0}
        />
        <StatsCard
          label="Resolved" 
          value={data.resolved}
          icon={CheckCircle} 
          iconColor="text-green-500"
        />
      </div>
    </DashboardLayout>
    </>
  );
};

export default UserDashboard;