import DashboardLayout from '../../layouts/DashboardLayout'
import StatsCard from '../../components/StatsCard'
import { TrendingUp, DollarSign, Users, Ticket, Star, Settings } from 'lucide-react'


const ClientDashboard = () => {
  return (
    <DashboardLayout 
      title="Dashboard" 
      subtitle="Overview of your organization"
      headerAction={
        <button className="bg-gray-200 text-black px-4 py-2 rounded-md text-sm font-medium hover:bg-gray-300">
          Manage Billing
        </button>
      }
    >
      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-12">
        <StatsCard 
          label="Current Plan" 
          value="Enterprise" 
          subtext="Active subscription" 
          icon={TrendingUp} 
          iconColor="text-blue-500"
        />
        <StatsCard 
          label="Monthly Cost" 
          value="₹4999/mo" 
          subtext="Next billing: Feb 1" 
          icon={DollarSign} 
          iconColor="text-green-500"
        />
        <StatsCard 
          label="Active Users" 
          value="45" 
          subtext="Team members" 
          icon={Users} 
          iconColor="text-blue-500"
        />
        <StatsCard 
          label="Total Tickets" 
          value="1" 
          subtext="This month" 
          icon={Ticket} 
          iconColor="text-black"
        />
      </div>

      <hr className="border-gray-200 mb-10" />

      {/* Content Sections */}
      <div className="space-y-12 max-w-4xl">
        <section>
          <div className="flex items-center gap-3 mb-4">
            <Star className="w-5 h-5 fill-black" />
            <h2 className="text-2xl font-bold">About the support system</h2>
          </div>
          <p className="text-gray-400 leading-relaxed">
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
          <p className="text-gray-400 leading-relaxed">
            Tickets are auto-assigned to agents using a priority-driven logic that considers workload and expertise. 
            Agents can view, manage, and update the status of assigned tickets in real time.
          </p>
        </section>
      </div>
    </DashboardLayout>
  )
}

export default ClientDashboard
