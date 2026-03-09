import React, { useEffect, useState } from 'react'
import DashboardLayout from '../../layouts/DashboardLayout'
import StatsCard from '../../components/StatsCard'
import api from '../../api/axios'
import Pagination from '../../components/Pagination'

const ClientManagement = () => {

  const [clients, setClients] = useState([])
  const [totalClients, setTotalClients] = useState(0)
  const [pendingClients, setPendingClients] = useState(0)

  const [currentPage, setCurrentPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [nextPage, setNextPage] = useState(null)
  const [previousPage, setPreviousPage] = useState(null)

  useEffect(() => {
    fetchClients(currentPage)
  }, [currentPage])

  const fetchClients = async (page=1) => {
    try {
      const response = await api.get(`/auth/admin/clients/?page=${page}`, {
        headers: {
          Authorization: `Bearer ${localStorage.getItem("access_token")}`
        }
      })
      const res = response.data.data;
      const paginator = response.data.paginator || {};

      setClients(res.results.clients);
      setTotalClients(res.results.total_clients);
      setPendingClients(res.results.pending_clients);

      setNextPage(paginator.next || null);
      setPreviousPage(paginator.previous || null);
      setTotalPages(Math.ceil(paginator.count / paginator.page_size));

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
              <th className="text-left p-2">Business Type</th>
              <th className="text-left p-2">Status</th>
            </tr>
          </thead>
          <tbody>
            {clients.length===0?(
              <tr>
                <td colSpan='5' className='text-center p-4 text-gray-500'>
                  No clients found
                </td>
              </tr>
            ):( clients.map((client,index) => {
              const pageSize=10
              const serialNumber=(currentPage-1)* pageSize +index+1
              return (
              <tr key={client.id} className="border-b hover:bg-gray-50">
                {/* <td className="p-2">{client.name}</td> */}
                <td className="p-2">{client.email}</td>
                <td className="p-2">{client.phone}</td>
                <td className="p-2">{client.business_type}</td>
                <td className="p-2">
                  {client.is_active ? (
                    <span className="text-green-600 font-medium">Active</span>
                  ) : (
                    <span className="text-red-600 font-medium">Pending</span>
                  )}
                </td>
              </tr>
            )
            })
            )}
          </tbody>
        </table>
      </div>
      {/* Pagination */}
      <Pagination
        currentPage={currentPage}
        totalPages={totalPages}
        onPageChange={setCurrentPage}
        hasNext={!!nextPage}
        hasPrevious={!!previousPage}
      />


    </DashboardLayout>
  )
}

export default ClientManagement
