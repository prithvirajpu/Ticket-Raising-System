import React, { useEffect, useState } from 'react'
import DashboardLayout from '../../layouts/DashboardLayout'
import StatsCard from '../../components/StatsCard'
import api from '../../api/axios'

const ClientManagement = () => {

  const [clients, setClients] = useState([])
  const [totalClients, setTotalClients] = useState(0)
  const [pendingClients, setPendingClients] = useState(0)

  useEffect(() => {
    fetchClients()
  }, [])

  const fetchClients = async () => {
    try {
      const response = await api.get("/auth/admin/clients/", {
        headers: {
          Authorization: `Bearer ${localStorage.getItem("access_token")}`
        }
      })

      setClients(response.data.clients)
      setTotalClients(response.data.total_clients)
      setPendingClients(response.data.pending_clients)

    } catch (error) {
      console.error("Error fetching clients:", error)
    }
  }

  return (
    <DashboardLayout title="Client Management">
      
      {/* Stats Section */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <StatsCard label="Total Clients" value={totalClients} />
        <StatsCard label="Pending Approvals" value={pendingClients} />
        <StatsCard label="Active Clients" value={totalClients - pendingClients} />
      </div>

      {/* Clients Table */}
      <div className="bg-white shadow rounded-lg p-4">
        <table className="w-full border-collapse">
          <thead>
            <tr className="border-b">
              {/* <th className="text-left p-2">Name</th> */}
              <th className="text-left p-2">Email</th>
              <th className="text-left p-2">Phone</th>
              <th className="text-left p-2">Status</th>
            </tr>
          </thead>
          <tbody>
            {clients.map((client) => (
              <tr key={client.id} className="border-b hover:bg-gray-50">
                {/* <td className="p-2">{client.name}</td> */}
                <td className="p-2">{client.email}</td>
                <td className="p-2">{client.phone}</td>
                <td className="p-2">
                  {client.is_active ? (
                    <span className="text-green-600 font-medium">Active</span>
                  ) : (
                    <span className="text-red-600 font-medium">Pending</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

    </DashboardLayout>
  )
}

export default ClientManagement
