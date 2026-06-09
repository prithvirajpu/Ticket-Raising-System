import React, { useEffect, useState } from 'react'
import DashboardLayout from '../../layouts/DashboardLayout'
import StatsCard from '../../components/StatsCard'
import api from '../../api/axios'
import { Link, useNavigate } from 'react-router-dom'
import Pagination from '../../components/Pagination'
import ConfirmModal from '../../components/modals/ConfirmModal'
import { Users, UserCheck, UserX, UserPlus, Phone, Mail, Shield, CheckCircle2, AlertCircle } from 'lucide-react'

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

  const [modalOpen, setModalOpen] = useState(false)
  const [selectedAgent, setSelectedAgent] = useState(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    fetchAgents(currentPage)
  }, [currentPage])

  const fetchAgents = async (page = 1) => {
    try {
      const response = await api.get(`/admins/agents/?page=${page}`, {
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

  const handleConfirm = async () => {
    if (!selectedAgent) return;
    setLoading(true);
    console.log('is active', selectedAgent.is_active)
    try {
      await api.patch(`/admins/agents/${selectedAgent.id}/status/`, {
        is_active: !selectedAgent.is_active
      })
      fetchAgents(currentPage);
      setModalOpen(false)
    } catch (error) {
      console.error("failed to update", error)
    } finally {
      setLoading(false);
    }
  }

  const handleStatusClick = (agent) => {
    setSelectedAgent(agent);
    setModalOpen(true);
  }

  return (
    <DashboardLayout title="Agent Operations">
      <div className="text-slate-800 antialiased space-y-6">

        {/* HEADER CONTROL PANEL */}
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-white border border-slate-200/80 p-5 rounded-2xl shadow-sm">
          <div>
            <h2 className="text-xl font-bold text-slate-900 tracking-tight">Active Rosters</h2>
            <p className="text-xs text-slate-500 mt-0.5">Provision access keys, manage account lifecycles, and monitor active seat statistics.</p>
          </div>

          <Link
            to='/admin/pending-req'
            className='inline-flex items-center gap-2 bg-slate-950 hover:bg-slate-800 text-white text-sm font-semibold py-2.5 px-4 rounded-xl shadow-xs hover:shadow active:scale-[0.99] transition-all self-stretch sm:self-auto text-center justify-center'
          >
            <UserPlus className="w-4 h-4" />
            <span>Pending Requests</span>
          </Link>
        </div>

        {/* OVERVIEW METRICS PANEL */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <StatsCard 
            label="Total Registered Agents" 
            value={totalAgents} 
            subtext="All onboarded team accounts"
            icon={Users} 
            iconColor="text-slate-400"
          />
          <StatsCard 
            label="Active Operators" 
            value={activeAgents} 
            subtext="Live agents clearing current tickets"
            icon={UserCheck} 
            iconColor="text-emerald-500"
          />
          <StatsCard 
            label="Disabled Seats" 
            value={inactiveAgents} 
            subtext="Suspended access profiles"
            icon={UserX} 
            iconColor="text-rose-500"
          />
        </div>

        {/* DATA CONTAINER MATRICES */}
        <div className="bg-white rounded-2xl border border-slate-200/80 shadow-sm overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left">
              <thead>
                <tr className="bg-slate-50/70 border-b border-slate-200/60 text-[11px] font-bold tracking-wider text-slate-400 uppercase">
                  <th className="p-4 font-semibold w-16">Idx</th>
                  <th className="p-4 font-semibold">Operator Info</th>
                  <th className="p-4 font-semibold">Email Address</th>
                  <th className="p-4 font-semibold">Contact Info</th>
                  <th className="p-4 font-semibold">Security Access Role</th>
                  <th className="p-4 font-semibold">System Access Status</th>
                  <th className="p-4 font-semibold text-right pr-6">Administrative Event</th>
                </tr>
              </thead>

              <tbody className="divide-y divide-slate-100 font-medium text-slate-700 text-sm">
                {agents.length === 0 ? (
                  <tr>
                    <td colSpan="7" className="text-center py-12 px-4 text-slate-400 italic">
                      <div className="flex flex-col items-center justify-center gap-2">
                        <Users className="w-8 h-8 text-slate-300 stroke-[1.5]" />
                        <span>No managed infrastructure operators found matching criteria.</span>
                      </div>
                    </td>
                  </tr>
                ) : (
                  agents.map((agent, index) => {
                    const pageSize = 5
                    const serialNumber = (currentPage - 1) * pageSize + index + 1

                    return (
                      <tr key={agent.id} className="hover:bg-slate-50/40 transition-colors group">
                        <td className="p-4 font-mono text-xs text-slate-400">{serialNumber}</td>
                        <td className="p-4">
                          <span className="font-bold text-slate-900 tracking-tight block">
                            {agent.full_name || agent.email.split('@')[0]}
                          </span>
                        </td>
                        <td className="p-4 text-slate-600 font-medium">
                          <div className="flex items-center gap-1.5">
                            <Mail className="w-3.5 h-3.5 text-slate-400" />
                            <span>{agent.email}</span>
                          </div>
                        </td>
                        <td className="p-4 text-slate-600 font-medium">
                          {agent.phone ? (
                            <div className="flex items-center gap-1.5">
                              <Phone className="w-3.5 h-3.5 text-slate-400" />
                              <span>{agent.phone}</span>
                            </div>
                          ) : (
                            <span className="text-slate-400 italic text-xs">Unspecified</span>
                          )}
                        </td>
                        <td className="p-4">
                          <span className="inline-flex items-center gap-1.5 text-xs text-slate-800 font-semibold bg-slate-100 px-2.5 py-1 rounded-md border border-slate-200/40 uppercase tracking-wider">
                            <Shield className="w-3 h-3 text-slate-500" />
                            {agent.role}
                          </span>
                        </td>
                        <td className="p-4">
                          {agent.is_active ? (
                            <span className="inline-flex items-center gap-1 text-xs text-emerald-700 font-bold bg-emerald-50 px-2.5 py-1 rounded-full border border-emerald-200/40">
                              <CheckCircle2 className="w-3 h-3 text-emerald-500" /> Active
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-xs text-rose-700 font-bold bg-rose-50 px-2.5 py-1 rounded-full border border-rose-200/40">
                              <AlertCircle className="w-3 h-3 text-rose-500" /> Revoked
                            </span>
                          )}
                        </td>
                        <td className="p-4 text-right pr-6">
                          <button 
                            onClick={() => handleStatusClick(agent)}
                            className={`inline-flex items-center justify-center text-xs font-bold px-3 py-1.5 rounded-xl border transition-all active:scale-[0.97] min-w-[85px] shadow-2xs ${
                              agent.is_active
                                ? "bg-white border-rose-200 text-rose-600 hover:bg-rose-50/50 hover:border-rose-300"
                                : "bg-white border-emerald-200 text-emerald-600 hover:bg-emerald-50/50 hover:border-emerald-300"
                            }`}
                          > 
                            {agent.is_active ? "Revoke Access" : "Grant Access"}
                          </button>
                        </td>
                      </tr>
                    )
                  })
                )}
              </tbody>
            </table>
          </div>

          <div className="p-4 bg-slate-50/50 border-t border-slate-100 flex items-center justify-end">
            <Pagination
              currentPage={currentPage}
              totalPages={totalPages}
              onPageChange={setCurrentPage}
              hasNext={!!nextPage}
              hasPrevious={!!previousPage}
            />
          </div>
        </div>

        {/* MODAL WRAPPER LAYER (Fixes z-index sorting placement)
          Force structural dominance over Dashboard Layout frameworks 
        */}
        <div className="relative z-[100]">
          <ConfirmModal
            isOpen={modalOpen}
            title={selectedAgent?.is_active ? "Revoke Access Privileges?" : "Restore Access Privileges?"}
            message={selectedAgent?.is_active 
              ? `Are you sure you want to suspend access rules for ${selectedAgent?.full_name || selectedAgent?.email}? `
              : `Are you sure you want to authorize routing credentials for ${selectedAgent?.full_name || selectedAgent?.email}?`}
            confirmText={selectedAgent?.is_active ? "Revoke Access" : "Authorize Access"}
            loadingText="Reconfiguring clearance levels..."
            onConfirm={handleConfirm}
            onCancel={() => setModalOpen(false)}
          />
        </div>

      </div>
    </DashboardLayout>
  )
}

export default AgentManagement