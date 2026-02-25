import React from 'react'
import DashboardLayout from '../../layouts/DashboardLayout'
import StatsCard from '../../components/StatsCard'
import { Ticket, Info, History, CheckCircle, Star, Settings } from 'lucide-react'

const AgentDashboard = () => {
  return (
   <DashboardLayout 
      title="Dashboard" 
      subtitle="Manage your assigned tickets"
      headerAction={
        <div className="bg-gray-200 text-black px-4 py-2 rounded-md text-sm font-semibold">
          02h 33m
        </div>
      }
    >
      {/* Stats Grid - 4 Columns based on image */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-10">
        <StatsCard 
          label="Assigned Tickets" 
          value="2" 
          icon={Ticket} 
          iconColor="text-black"
        />
        <StatsCard 
          label="Open" 
          value="1" 
          icon={Info} 
          iconColor="text-red-500"
        />
        <StatsCard 
          label="In Progress" 
          value="0" 
          icon={History} 
          iconColor="text-orange-500"
        />
        <StatsCard 
          label="Active Time - Month" 
          value="40 hrs" 
          icon={CheckCircle} 
          iconColor="text-green-500"
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
