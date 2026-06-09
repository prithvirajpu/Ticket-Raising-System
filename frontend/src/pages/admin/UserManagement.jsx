import React, { useEffect, useState } from 'react'
import DashboardLayout from '../../layouts/DashboardLayout'
import StatsCard from '../../components/StatsCard'
import Pagination from '../../components/Pagination'
import { getUserData } from '../../services/ticketService'
import { Users, UserCheck, UserX, Mail, Phone, Building2, CheckCircle2, AlertCircle } from 'lucide-react'

const UserManagement = () => {
  const [users, setUsers] = useState([])
  const [totalUsers, setTotalUsers] = useState(0)
  const [activeUsers, setActiveUsers] = useState(0)
  const [inactiveUsers, setInactiveUsers] = useState(0)

  const [currentPage, setCurrentPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [nextPage, setNextPage] = useState(null)
  const [previousPage, setPreviousPage] = useState(null)

  useEffect(() => {
    fetchUsers(currentPage)
  }, [currentPage])

  const fetchUsers = async (page = 1) => {
    try {
      const res = await getUserData(page)
      console.log(res)

      const data = res.data.data.message
      const paginator = res.data.paginator || {}

      setUsers(data.users)
      setTotalUsers(data.total_users)
      setActiveUsers(data.active_users)
      setInactiveUsers(data.inactive_users)

      setNextPage(paginator.next || null)
      setPreviousPage(paginator.previous || null)
      
      // Kept your fallback pageSize of 5 to preserve correct backend math
      setTotalPages(
        Math.ceil((paginator.count || 0) / (paginator.page_size || 5))
      )
    } catch (error) {
      console.error('Error fetching users:', error)
    }
  }

  return (
    <DashboardLayout title="User Operations">
      <div className="text-slate-800 antialiased space-y-6">

        {/* HEADER CONTROL PANEL */}
        <div className="bg-white border border-slate-200/80 p-5 rounded-2xl shadow-sm">
          <h2 className="text-xl font-bold text-slate-900 tracking-tight">End-User Accounts</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Monitor client-associated end users, trace individual authentication streams, and verify system permissions.
          </p>
        </div>

        {/* OVERVIEW METRICS PANEL */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <StatsCard 
            label="Total Base Users" 
            value={totalUsers} 
            subtext="All registered workspace individuals"
            icon={Users} 
            iconColor="text-slate-400"
          />
          <StatsCard 
            label="Active Accounts" 
            value={activeUsers} 
            subtext="Users with active session grants"
            icon={UserCheck} 
            iconColor="text-emerald-500"
          />
          <StatsCard 
            label="Disabled Accounts" 
            value={inactiveUsers} 
            subtext="Revoked or suspended memberships"
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
                  <th className="p-4 font-semibold">User Identification</th>
                  <th className="p-4 font-semibold">Email Address</th>
                  <th className="p-4 font-semibold">Contact Info</th>
                  <th className="p-4 font-semibold">Associated Workspace</th>
                  <th className="p-4 font-semibold">System Access Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-medium text-slate-700 text-sm">
                {users.length === 0 ? (
                  <tr>
                    <td colSpan="6" className="text-center py-12 px-4 text-slate-400 italic">
                      <div className="flex flex-col items-center justify-center gap-2">
                        <Users className="w-8 h-8 text-slate-300 stroke-[1.5]" />
                        <span>No registered user profiles found in this workspace context.</span>
                      </div>
                    </td>
                  </tr>
                ) : (
                  users.map((user, index) => {
                    const pageSize = 5 // Matched your local calculation sequence
                    const serialNumber = (currentPage - 1) * pageSize + index + 1
                    
                    return (
                      <tr key={user.id} className="hover:bg-slate-50/40 transition-colors group">
                        {/* Index */}
                        <td className="p-4 font-mono text-xs text-slate-400">{serialNumber}</td>
                        
                        {/* User Identity */}
                        <td className="p-4">
                          <div className="flex items-center gap-2">
                            <div className="p-1 bg-slate-50 group-hover:bg-white rounded border border-slate-100 transition-colors">
                              <Users className="w-3.5 h-3.5 text-slate-500" />
                            </div>
                            <span className="font-bold text-slate-900 tracking-tight">
                              {user.name || user.email.split('@')[0]}
                            </span>
                          </div>
                        </td>
                        
                        {/* Email */}
                        <td className="p-4 text-slate-600 font-medium">
                          <div className="flex items-center gap-1.5">
                            <Mail className="w-3.5 h-3.5 text-slate-400" />
                            <span>{user.email}</span>
                          </div>
                        </td>
                        
                        {/* Contact Info */}
                        <td className="p-4 text-slate-600 font-medium">
                          {user.phone ? (
                            <div className="flex items-center gap-1.5">
                              <Phone className="w-3.5 h-3.5 text-slate-400" />
                              <span>{user.phone}</span>
                            </div>
                          ) : (
                            <span className="text-slate-400 italic text-xs">Unspecified</span>
                          )}
                        </td>
                        
                        {/* Associated Client Workspace */}
                        <td className="p-4">
                          <div className="flex items-center gap-1.5 text-xs text-slate-800 font-semibold bg-slate-100 px-2.5 py-1 rounded-md border border-slate-200/40 uppercase tracking-wider inline-flex">
                            <Building2 className="w-3 h-3 text-slate-500" />
                            <span>{user.client_name || 'N/A'}</span>
                          </div>
                        </td>
                        
                        {/* Status Check badge */}
                        <td className="p-4">
                          {user.is_active ? (
                            <span className="inline-flex items-center gap-1 text-xs text-emerald-700 font-bold bg-emerald-50 px-2.5 py-1 rounded-full border border-emerald-200/40">
                              <CheckCircle2 className="w-3 h-3 text-emerald-500" /> Active
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-xs text-rose-700 font-bold bg-rose-50 px-2.5 py-1 rounded-full border border-rose-200/40">
                              <AlertCircle className="w-3 h-3 text-rose-500" /> Disabled
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
          {users.length > 0 && (
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

export default UserManagement