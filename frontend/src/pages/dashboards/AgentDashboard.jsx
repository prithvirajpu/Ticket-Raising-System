import DashboardLayout from '../../layouts/DashboardLayout'
import StatsCard from '../../components/StatsCard'
import { Ticket, Info, History, CheckCircle, Star, Settings } from 'lucide-react'
import { useEffect, useState } from 'react'
import { getAgentDashboard } from '../../services/ticketService'

const AgentDashboard = () => {
  // const seconds= useAgentTimer()
  const [data,setData]= useState({})
  const [loading,setLoading]=useState(true);

  useEffect(()=>{
    fetchData();
  },[])

    const fetchData= async()=>{
      try {
        setLoading(true)
        const res= await getAgentDashboard();
        setData(res.message)
      } catch (error) {
        console.log('dashboard fetch error',error)
      } finally{
        setLoading(false)
      }
    }

  return (
   <DashboardLayout 
      title="Agent Dashboard" 
      subtitle="Manage your assigned tickets"

    >
      {/* Stats Grid - 4 Columns based on image */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-10">
        <StatsCard 
          label="Assigned Tickets" 
          icon={Ticket} 
          iconColor="text-black"
          value={data.assigned_tickets || 0}
        />
        <StatsCard 
          label="Open" 
          icon={Info} 
          iconColor="text-red-500"
          value={data.open || 0}
        />
        <StatsCard 
          label="In Progress" 
          icon={History} 
          iconColor="text-orange-500"
          value={data.in_progress || 0}
        />
       
      </div>

      <hr className="border-gray-200 mb-10" />

      {/* Content Sections from Screenshot */}
      <div className="space-y-12 max-w-4xl">
        <section>
          <div className="flex items-center gap-3 mb-4">
            <Star className="w-5 h-5 fill-black" />
            <h2 className="text-2xl font-bold">About the support system</h2>
          </div>
          <p className="text-gray-400 leading-relaxed text-sm">
            This support system is designed to streamline customer issue resolution through a structured ticket-based workflow. 
            Each support request raised by users is converted into a ticket and automatically routed to agents based on priority, 
            availability, and category.
          </p>
        </section>

        <section>
          <div className="flex items-center gap-3 mb-4">
            <Settings className="w-5 h-5" />
            <h2 className="text-2xl font-bold">Ticket Assignment & Workflow</h2>
          </div>
          <p className="text-gray-400 leading-relaxed text-sm">
            Tickets are auto-assigned to agents using a priority-driven logic that considers workload and expertise. 
            Agents can view, manage, and update the status of assigned tickets in real time.
          </p>
        </section>
      </div>
      
    </DashboardLayout>
  )
}

export default AgentDashboard
