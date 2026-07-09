import { useEffect, useState } from 'react';
import DashboardLayout from '../../layouts/DashboardLayout'
import {  Users, Ticket, Info, CheckCircle  } from 'lucide-react'
import StatsCard from '../../components/StatsCard'
import { getManagerDashboard } from '../../services/ticketService';


const ManagerDashboard = () => {
const [data, setData] = useState({});
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchData();
  }, [])

  const fetchData = async () => {
    try {
      setLoading(true)
      const res = await getManagerDashboard();
      setData(res.message); 
    } catch (error) {
      console.log(error)
    } finally {
      setLoading(false)
    }
  }

  return (
    <DashboardLayout 
      title="Dashboard" 
      subtitle="Overview of your Manager"
    >
      <div className="space-y-6 text-slate-800 antialiased">
        
        {/* RESPONSIVE STATS GRID MATRIX */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
         <StatsCard
    label="Team Leaders"
    value={data.team_leads || 0}
    icon={Users}
/>

<StatsCard
    label="Agents"
    value={data.agents || 0}
    icon={Users}
/>

<StatsCard
    label="Total Tickets"
    value={data.total_tickets || 0}
    icon={Ticket}
/>

<StatsCard
    label="Resolved"
    value={data.resolved_tickets || 0}
    icon={CheckCircle}
/>
        </div>

        <hr className="border-slate-200/80 my-8" />

      </div>
    </DashboardLayout>
  )
}

export default ManagerDashboard
