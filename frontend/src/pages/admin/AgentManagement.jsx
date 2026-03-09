import React, { useEffect, useState } from 'react'
import DashboardLayout from '../../layouts/DashboardLayout'
import StatsCard from '../../components/StatsCard'
import api from '../../api/axios'
import { Link,useNavigate  } from 'react-router-dom'
import Pagination from '../../components/Pagination'
import ConfirmModal from '../../components/modals/ConfirmModal'

const AgentManagement = () => {

  const [agents, setAgents] = useState([])
  const [totalAgents, setTotalAgents] = useState(0)
  const [activeAgents, setActiveAgents] = useState(0)
  const [inactiveAgents, setInactiveAgents] = useState(0)
  const navigate = useNavigate()

  const [currentPage, setCurrentPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [nextPage, setNextPage] = useState(null)
  const [previousPage, setPreviousPage] = useState(null)

  const [modalOpen,setModalOpen]=useState(false)
  const [selectedAgent,setSelectedAgent]=useState(null)
  const [loading,setLoading]=useState(false)

  useEffect(() => {
    fetchAgents(currentPage)
  }, [currentPage])

  const fetchAgents = async (page = 1) => {
    try {
      const response = await api.get(`/auth/admin/agents/?page=${page}`, {
        headers: {
          Authorization: `Bearer ${localStorage.getItem("access")}`
        }
      })
      const res = response.data.data;
      const paginator = response.data.paginator || {};

      setAgents(res.results.agents);
      setTotalAgents(res.results.total_agents);
      setActiveAgents(res.results.active_agents);
      setInactiveAgents(res.results.inactive_agents);

      setNextPage(paginator.next || null);
      setPreviousPage(paginator.previous || null);
      setTotalPages(Math.ceil(paginator.count / paginator.page_size));

    } catch (error) {
      console.error("Error fetching agents:", error)
    }
  }

  const handleConfirm=async()=>{
    if (!selectedAgent)return;
    setLoading(true);
    console.log('is active',selectedAgent.is_active)
    try {
      await api.patch(`/auth/admin/agents/${selectedAgent.id}/status/`,{
        is_active: !selectedAgent.is_active
      })
      fetchAgents(currentPage);
      setModalOpen(false)
    } catch (error) {
      console.error("falid to update",error)
    }finally{
      setLoading(false);
    }
  }
  const handleStatusClick=(agent)=>{
    setSelectedAgent(agent);
    setModalOpen(true);
  }

  return (
   <DashboardLayout title="Agent Management">

  {/* Header Section */}
  <div className="flex justify-between items-center mb-6">
    <div>
      <h2 className="text-2xl font-bold">All Agents</h2>
    </div>

    <Link 
      to='/admin/pending-req' 
      className='bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded-lg shadow-sm transition-all'
    >
      Pending Requests
    </Link>
  </div>

  {/* Stats */}
  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
    <StatsCard label="Total Agents" value={totalAgents} />
    <StatsCard label="Active Agents" value={activeAgents} />
    <StatsCard label="Inactive Agents" value={inactiveAgents} />
  </div>

  {/* Agent Table */}
<div className="bg-white shadow rounded-lg overflow-hidden">
  <table className="w-full border-collapse">
    <thead className="bg-gray-100">
      <tr>
        <th className="p-3 text-left text-sm font-semibold text-gray-600">Index</th>
        <th className="p-3 text-left text-sm font-semibold text-gray-600">Name</th>
        <th className="p-3 text-left text-sm font-semibold text-gray-600">Email</th>
        <th className="p-3 text-left text-sm font-semibold text-gray-600">Phone</th>
        <th className="p-3 text-left text-sm font-semibold text-gray-600">Role</th>
        <th className="p-3 text-left text-sm font-semibold text-gray-600">Status</th>
        <th className="p-3 text-left text-sm font-semibold text-gray-600">Action</th>
      </tr>
    </thead>

    <tbody>
      {agents.length === 0 ? (
        <tr>
          <td colSpan="6" className="text-center p-6 text-gray-500">
            No agents found
          </td>
        </tr>
      ) : (
        agents.map((agent, index) => {
          const pageSize = 10
          const serialNumber =
            (currentPage - 1) * pageSize + index + 1

          return (
            <tr key={agent.id} className="border-t hover:bg-gray-50">

              <td className="p-3 text-sm">{serialNumber}</td>

              <td className="p-3 text-sm font-medium">
                {agent.full_name || agent.email.split('@')[0]}
              </td>

              <td className="p-3 text-sm text-gray-600">
                {agent.email}
              </td>

              <td className="p-3 text-sm text-gray-600">
                {agent.phone}
              </td>

              <td className="p-3 text-sm text-violet-950">
                {agent.role}
              </td>

              <td className="p-3 text-sm">
                {agent.is_active? (
                  <span className="text-green-600 font-medium">Active</span>
                ):(
                  <span className="text-red-600 font-medium">Disabled</span>
                )}
              </td>
              <td className="p-3">
                <button onClick={()=>handleStatusClick(agent)}
                  className={`px-3 py-1 rounded text-white text-sm ${
                    agent.is_active
                      ? "bg-red-500 hover:bg-red-600"
                      : "bg-green-500 hover:bg-green-600"}`}> 
                  {agent.is_active ?"Disable":"Enable"}
                </button>
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

        <ConfirmModal
          isOpen= {modalOpen}
          title={selectedAgent?.is_active? "Disable Agent?": "Enable Agent"}
          message={selectedAgent?.is_active ?"This agent will no longer be able to access the platform"
            :"This agent will regain access to the platform"}
          confirmText={selectedAgent?.is_active? "Disable":"Enable"}
          loadingText='Updating...'
          onConfirm={handleConfirm}
          onCancel={()=>setModalOpen(false)}
        />

</DashboardLayout>
  )
}

export default AgentManagement
