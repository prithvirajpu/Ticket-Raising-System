import { useEffect, useState } from "react";
import DashboardLayout from "../../layouts/DashboardLayout"
import { getTLDashboard } from "../../services/ticketService";
import StatsCard from '../../components/StatsCard'
import {  Users, Ticket, Info, CheckCircle  } from 'lucide-react'


const TeamLeadDashboard = () => {
  const [data, setData] = useState({});
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchData();
  }, [])

  const fetchData = async () => {
    try {
      setLoading(true)
      const res = await getTLDashboard();
      console.log('This is the TL dboard',res.message)
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
      subtitle="Overview of your Team Lead"
    >
      <div className="space-y-6 text-slate-800 antialiased">
        
        {/* RESPONSIVE STATS GRID MATRIX */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatsCard
    label="Total Agents"
    value={data.total_agents || 0}
    icon={Users}
    iconColor="text-blue-500"
/>

<StatsCard
    label="Assigned Tickets"
    value={data.assigned_tickets || 0}
    icon={Ticket}
    iconColor="text-black"
/>

<StatsCard
    label="Open Tickets"
    value={data.open_tickets || 0}
    icon={Info}
    iconColor="text-red-500"
/>

<StatsCard
    label="Resolved Tickets"
    value={data.resolved_tickets || 0}
    icon={CheckCircle}
    iconColor="text-green-500"
/>
        </div>

        <hr className="border-slate-200/80 my-8" />

      </div>
    </DashboardLayout>
  )
}

export default TeamLeadDashboard
