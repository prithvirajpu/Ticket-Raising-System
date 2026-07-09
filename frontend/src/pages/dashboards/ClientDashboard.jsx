import DashboardLayout from '../../layouts/DashboardLayout'
import StatsCard from '../../components/StatsCard'
import { TrendingUp, Users, Ticket, Star, Settings, CreditCard } from 'lucide-react'
import { useEffect, useState } from 'react'
import { getClientDashboard } from '../../services/ticketService'

const ClientDashboard = () => {
  const [data, setData] = useState({});
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchData();
  }, [])

  const fetchData = async () => {
    try {
      setLoading(true)
      const res = await getClientDashboard();
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
      subtitle="Overview of your organization"
    >
      <div className="space-y-6 text-slate-800 antialiased">
        
        {/* RESPONSIVE STATS GRID MATRIX */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatsCard
            label="Current Plan"
            value={data.current_plan || "N/A"}
            subtext="Active subscription"
            icon={TrendingUp}
            iconColor="text-indigo-500"
          />

          <StatsCard
            label="Active Users"
            value={data.active_users || 0}
            subtext="Organization users"
            icon={Users}
            iconColor="text-blue-500"
          />

          <StatsCard
            label="Open Tickets"
            value={data.open_tickets || 0}
            subtext="Currently open"
            icon={Ticket}
            iconColor="text-rose-500"
          />

          <StatsCard
            label="Total Tickets"
            value={data.total_tickets || 0}
            subtext="All tickets"
            icon={Ticket}
            iconColor="text-slate-600"
          />
        </div>

        <hr className="border-slate-200/80 my-8" />

      </div>
    </DashboardLayout>
  )
}

export default ClientDashboard