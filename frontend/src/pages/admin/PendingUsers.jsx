import React, { useEffect, useState } from 'react'
import api from '../../api/axios'
import { useNavigate } from 'react-router-dom';
import { notifyError, notifySuccess } from "../../utils/notify";
import DashboardLayout from '../../layouts/DashboardLayout';
import ConfirmModal from '../../components/modals/ConfirmModal';
import Pagination from '../../components/Pagination';
import { UserPlus, Calendar, ShieldCheck, XCircle, Eye, Shield, Users, ArrowLeft } from 'lucide-react';
import Lottie from 'lottie-react';
import emptyQueueAnimation from "../../assets/empty-queue.json";


const PendingUsers = () => {
  const [users, setUsers] = useState([])
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [modalConfig, setModalConfig] = useState({}) 

  const navigate = useNavigate()
  
  const [currentPage, setCurrentPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [nextPage, setNextPage] = useState(null)
  const [previousPage, setPreviousPage] = useState(null)

  const fetchPendingUsers = async (pageNumber = 1) => {
    try {
      const res = await api.get(`/admins/pending-users/?page=${pageNumber}`)
      console.log('the result', res)

      setUsers(res.data.results)
      setTotalPages(Math.ceil(res.data.count / 10))
      setNextPage(res.data.next)
      setPreviousPage(res.data.previous)

    } catch (err) {
      console.log('err', err)
      notifyError('Failed to fetch users')
    }
  }

  useEffect(() => {
    console.log('page changed', currentPage)
    fetchPendingUsers(currentPage)
  }, [currentPage])

  const handleAction = async () => {
    const { type, id, role } = modalConfig
    setLoading(true)
    try {
      let res
      if (type === 'approve') {
        res = await api.post(`/admins/approve/${id}/`, { role })
      } else if (type === 'reject') {
        res = await api.post(`/admins/reject/${id}/`)
      }
      notifySuccess(res?.data?.details || "Action completed successfully")
      if (users.length === 1 && currentPage > 1) {
        setCurrentPage(prev => prev - 1)
      } else {
        fetchPendingUsers(currentPage)
      }
    } catch (err) {
      console.log(err)
      const error = err?.response?.data?.details ||
        err?.response?.data?.error ||
        "Action failed. Please try again."
      notifyError(error)
    } finally {
      setLoading(false)
      setIsModalOpen(false)
    }
  }

  return (
    <DashboardLayout title="Agent Operations">
      <div className="text-slate-800 antialiased space-y-6">
        
        {/* HEADER PANEL CONTROL */}
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-white border border-slate-200/80 p-5 rounded-2xl shadow-sm">
          <div>
            <h2 className="text-xl font-bold text-slate-900 tracking-tight">Pending Registrations</h2>
            <p className="text-xs text-slate-500 mt-0.5">Evaluate incoming team applications, assign baseline security roles, and verify clearance profiles.</p>
          </div>

          <button
            onClick={() => navigate(-1)}
            className="inline-flex items-center gap-2 bg-white border border-slate-200 text-slate-700 hover:bg-slate-50 text-sm font-semibold py-2.5 px-4 rounded-xl shadow-xs transition-all self-stretch sm:self-auto text-center justify-center active:scale-[0.99]"
          >
            <ArrowLeft className="w-4 h-4 text-slate-500" />
            <span>Back to Active Rosters</span>
          </button>
        </div>

        {/* CONTAINER MATRICES */}
        <div className="bg-white rounded-2xl border border-slate-200/80 shadow-sm overflow-hidden p-6">
          {users.length === 0 ? (
            <div className="flex flex-col justify-center items-center min-h-[350px] bg-white rounded-2xl border border-slate-200/80 shadow-sm text-center p-6">
  <div className="w-48 h-48 flex items-center justify-center">
    <Lottie 
      animationData={emptyQueueAnimation} 
      loop={true} 
      className="w-full h-full"
    />
  </div>
  <h3 className="text-base font-bold text-slate-900 mt-2">
    No Data Found
  </h3>
  <p className="text-xs sm:text-sm text-slate-500 mt-1.5 max-w-sm leading-relaxed">
    Adjust your filters or check back later.
  </p>
</div>
          ) : (
            <div className="flex flex-col gap-3">
              {users.map((user, index) => (
                <div 
                  key={user.id} 
                  className="flex flex-col lg:flex-row lg:items-center justify-between p-4 border border-slate-100 rounded-xl bg-white hover:bg-slate-50/40 hover:border-slate-200 transition-all gap-4"
                >
                  {/* Left Side: Info & Role Configurator */}
                  <div className="flex flex-wrap items-center gap-4">
                    <div className="flex items-center gap-3">
                      <span className="font-mono text-xs text-slate-400">
                        {String((currentPage - 1) * 10 + index + 1).padStart(2, '0')}
                      </span>
                      <h3 className="font-bold text-slate-900 tracking-tight text-base">
                        {user.full_name || user.email.split('@')[0]}
                      </h3>
                    </div>

                    <div className="flex items-center gap-1.5 text-xs text-slate-400 font-medium bg-slate-50 border border-slate-200/40 px-2.5 py-1 rounded-md">
                      <Calendar className="w-3.5 h-3.5 text-slate-400" />
                      <span>{new Date(user.applied_at).toLocaleDateString(undefined, { dateStyle: 'medium' })}</span>
                    </div>

                    <div className="flex items-center gap-2">
                      <span className="text-[10px] uppercase tracking-wider font-bold text-slate-400">Assign Role:</span>
                      <div className="relative inline-flex items-center">
                        <select
                          className="text-xs font-bold text-slate-700 border border-slate-200 bg-white hover:bg-slate-50 px-2.5 py-1.5 rounded-lg appearance-none cursor-pointer pr-7 focus:outline-none transition-colors"
                          value={user.selectedRole || "AGENT"}
                          onChange={(e) => {
                            const role = e.target.value
                            setUsers(prev =>
                              prev.map(u =>
                                u.id === user.id ? { ...u, selectedRole: role } : u
                              )
                            )
                          }}
                        >
                          <option value="AGENT">AGENT</option>
                          <option value="TEAM_LEAD">TEAM_LEAD</option>
                          <option value="MANAGER">MANAGER</option>
                        </select>
                        <Shield className="w-3 h-3 text-slate-400 absolute right-2.5 pointer-events-none" />
                      </div>
                    </div>
                  </div>

                  {/* Right Side: Execution Controls */}
                  <div className="flex items-center justify-end gap-2 sm:gap-3 self-end lg:self-auto w-full lg:w-auto">
                    <button
                      className="inline-flex items-center justify-center gap-1.5 text-xs font-bold px-3 py-2 border border-emerald-100 bg-emerald-50/50 hover:bg-emerald-50 text-emerald-600 rounded-xl transition-all active:scale-[0.97] shadow-2xs flex-1 sm:flex-none"
                      onClick={() => {
                        setModalConfig({
                          type: 'approve',
                          id: user.id,
                          role: user.selectedRole || "AGENT"
                        })
                        setIsModalOpen(true)
                      }}
                    >
                      <ShieldCheck className="w-3.5 h-3.5" />
                      Accept
                    </button>

                    <button
                      className="inline-flex items-center justify-center gap-1.5 text-xs font-bold px-3 py-2 border border-rose-100 bg-rose-50/50 hover:bg-rose-50 text-rose-600 rounded-xl transition-all active:scale-[0.97] shadow-2xs flex-1 sm:flex-none"
                      onClick={() => {
                        setModalConfig({ type: 'reject', id: user.id })
                        setIsModalOpen(true)
                      }}
                    >
                      <XCircle className="w-3.5 h-3.5" />
                      Reject
                    </button>

                    <button
                      className="inline-flex items-center justify-center gap-1.5 text-xs font-bold px-3.5 py-2 border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 rounded-xl transition-all active:scale-[0.97] shadow-2xs flex-1 sm:flex-none"
                      onClick={() => navigate(`/admin/agent/${user.id}`)}
                    >
                      <Eye className="w-3.5 h-3.5 text-slate-400" />
                      View 
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Pagination Container */}
          {users.length > 0 && (
            <div className="mt-6 pt-4 border-t border-slate-100 flex items-center justify-end">
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

        {/* MODAL WRAPPER LAYER (Fixes z-index sorting placement) */}
        <div className="relative z-[100]">
          <ConfirmModal
            isOpen={isModalOpen}
            title={modalConfig.type === 'approve' ? "Approve Operator Account?" : "Deny Operator Account?"}
            message={modalConfig.type === 'approve' 
              ? `Are you sure you want to authorize routing privileges with security clearance group "${modalConfig.role}"? They will gain operational portal workspace keys immediately.` 
              : "Are you sure you want to reject this request profile? This pending application metadata tracking reference will be completely closed."}
            confirmText={modalConfig.type === 'approve' ? "Authorize Identity" : "Reject Identity"}
            loadingText="Processing security token updates..."
            onCancel={() => setIsModalOpen(false)}
            onConfirm={handleAction}
            loading={loading}
          />
        </div>
      </div>
    </DashboardLayout>
  )
}

export default PendingUsers