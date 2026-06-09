import React, { useEffect, useState } from 'react'
import DashboardLayout from '../../layouts/DashboardLayout'
import StatsCard from '../../components/StatsCard'
import api from '../../api/axios'
import Pagination from '../../components/Pagination'
import { Building2, Users, UserCheck, Clock, Mail, Phone, Briefcase, CheckCircle2, AlertCircle } from 'lucide-react'

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
      const response = await api.get(`/admins/clients/?page=${page}`, {
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
    <DashboardLayout title="Client Operations">
      <div className="text-slate-800 antialiased space-y-6">

        {/* HEADER CONTROL PANEL */}
        <div className="bg-white border border-slate-200/80 p-5 rounded-2xl shadow-sm">
          <h2 className="text-xl font-bold text-slate-900 tracking-tight">Corporate Accounts</h2>
          <p className="text-xs text-slate-500 mt-0.5">Monitor organization memberships, track active workspace domains, and manage onboarding configurations.</p>
        </div>
        
        {/* OVERVIEW METRICS PANEL */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <StatsCard 
            label="Total Client Accounts" 
            value={totalClients} 
            subtext="All registered enterprise entities"
            icon={Users} 
            iconColor="text-slate-400"
          />
          <StatsCard 
            label="Pending Approvals" 
            value={pendingClients} 
            subtext="Applications awaiting review"
            icon={Clock} 
            iconColor="text-amber-500"
          />
          <StatsCard 
            label="Active Client Hubs" 
            value={totalClients - pendingClients} 
            subtext="Verified business spaces"
            icon={UserCheck} 
            iconColor="text-emerald-500"
          />
        </div>

        {/* DATA CONTAINER MATRICES */}
        <div className="bg-white rounded-2xl border border-slate-200/80 shadow-sm overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left">
              <thead>
                <tr className="bg-slate-50/70 border-b border-slate-200/60 text-[11px] font-bold tracking-wider text-slate-400 uppercase">
                  <th className="p-4 font-semibold w-16">Idx</th>
                  <th className="p-4 font-semibold">Company Name</th>
                  <th className="p-4 font-semibold">Email Address</th>
                  <th className="p-4 font-semibold">Contact Info</th>
                  <th className="p-4 font-semibold">Business Classification</th>
                  <th className="p-4 font-semibold">System Access Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-medium text-slate-700 text-sm">
                {clients.length === 0 ? (
                  <tr>
                    <td colSpan='6' className='text-center py-12 px-4 text-slate-400 italic'>
                      <div className="flex flex-col items-center justify-center gap-2">
                        <Building2 className="w-8 h-8 text-slate-300 stroke-[1.5]" />
                        <span>No registered enterprise infrastructure environments found.</span>
                      </div>
                    </td>
                  </tr>
                ) : ( 
                  clients.map((client, index) => {
                    const pageSize = 10
                    const serialNumber = (currentPage - 1) * pageSize + index + 1
                    return (
                      <tr key={client.id} className="hover:bg-slate-50/40 transition-colors group">
                        <td className="p-4 font-mono text-xs text-slate-400">{serialNumber}</td>
                        <td className="p-4">
                          <div className="flex items-center gap-2">
                            <div className="p-1 bg-slate-50 group-hover:bg-white rounded border border-slate-100 transition-colors">
                              <Building2 className="w-3.5 h-3.5 text-slate-500" />
                            </div>
                            <span className="font-bold text-slate-900 tracking-tight">
                              {client.client_name || 'N/A'}
                            </span>
                          </div>
                        </td>
                        <td className="p-4 text-slate-600 font-medium">
                          <div className="flex items-center gap-1.5">
                            <Mail className="w-3.5 h-3.5 text-slate-400" />
                            <span>{client.email}</span>
                          </div>
                        </td>
                        <td className="p-4 text-slate-600 font-medium">
                          {client.phone ? (
                            <div className="flex items-center gap-1.5">
                              <Phone className="w-3.5 h-3.5 text-slate-400" />
                              <span>{client.phone}</span>
                            </div>
                          ) : (
                            <span className="text-slate-400 italic text-xs">Unspecified</span>
                          )}
                        </td>
                        <td className="p-4">
                          {client.business_type ? (
                            <span className="inline-flex items-center gap-1.5 text-xs text-slate-800 font-semibold bg-slate-100 px-2.5 py-1 rounded-md border border-slate-200/40 uppercase tracking-wider">
                              <Briefcase className="w-3 h-3 text-slate-500" />
                              {client.business_type}
                            </span>
                          ) : (
                            <span className="text-slate-400 italic text-xs">Not Classified</span>
                          )}
                        </td>
                        <td className="p-4">
                          {client.is_active ? (
                            <span className="inline-flex items-center gap-1 text-xs text-emerald-700 font-bold bg-emerald-50 px-2.5 py-1 rounded-full border border-emerald-200/40">
                              <CheckCircle2 className="w-3 h-3 text-emerald-500" /> Active
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-xs text-amber-700 font-bold bg-amber-50 px-2.5 py-1 rounded-full border border-amber-200/40">
                              <AlertCircle className="w-3 h-3 text-amber-500" /> Pending
                            </span>
                          )}
                        </td>
                      </tr>
                    )
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination Anchor Section */}
          {clients.length > 0 && (
            <div className="p-4 bg-slate-50/50 border-t border-slate-100 flex items-center justify-end">
              <Pagination
                currentPage={currentPage}
                totalPages={totalPages}
                onPageChange={setCurrentPage}
                hasNext={!!nextPage}
                hasPrevious={!!previousPage}
              />
            </div>
          )}
        </div>

      </div>
    </DashboardLayout>
  )
}

export default ClientManagement