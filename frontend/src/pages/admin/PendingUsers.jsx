import React, { useEffect, useState } from 'react'
import api from '../../api/axios'
import { useNavigate } from 'react-router-dom';
import { notifyError, notifySuccess } from "../../utils/notify";
import DashboardLayout from '../../layouts/DashboardLayout';
import ConfirmModal from '../../components/modals/ConfirmModal';
import Pagination from '../../components/Pagination';

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
            const res = await api.get(`/auth/admin/pending-users/?page=${pageNumber}`)

            setUsers(res.data.results)
            setTotalPages(Math.ceil(res.data.count / 10))
            setNextPage(res.data.next)
            setPreviousPage(res.data.previous)

        } catch (err) {
          console.log('err',err)
            notifyError('Failed to fetch users')
        }
    }

  useEffect(() => {
    console.log('page changed',currentPage)
    fetchPendingUsers(currentPage)
  }, [currentPage])

  const handleAction = async () => {
    const { type, id, role } = modalConfig
    setLoading(true)
    try {
      let res
      if (type === 'approve') {
        res=await api.post(`/auth/admin/approve/${id}/`, { role })
      } else if (type === 'reject') {
        res=await api.post(`/auth/admin/reject/${id}/`)
      }
      notifySuccess(res?.data?.details || "Action completed successfullly")
      if (users.length === 1 && currentPage > 1) {
        setCurrentPage(prev => prev - 1)
        } else {
        fetchPendingUsers(currentPage)
        }
    } catch (err) {
        console.log(err)
        const error=err?.response?.data?.details ||
          err?.response?.data?.error ||
          "Action failed. Please try again."
      notifyError(error)
    } finally {
      setLoading(false)
      setIsModalOpen(false)
    }
  }

  return (
    <DashboardLayout title="Agent Management">
      <div className="bg-white p-6 rounded shadow">
        <div className="mb-6">
          <h2 className="text-2xl font-bold">Pending Requests</h2>
        </div>

        {users.length === 0 ? (
          <p className="text-gray-500 italic">No pending Agents</p>
        ) : (
          <div className="flex flex-col gap-4">
            {users.map((user,index) => (
              <div key={user.id} className="flex items-center justify-between p-4 border rounded-xl bg-white shadow-sm">
                
                {/* Left Side */}
                <div className='flex items-center gap-3'>
                  <h3 className="text-lg font-semibold text-gray-800">
                    {(currentPage - 1) * 10 + index + 1}.{" "}
                    {user.full_name || user.email.split('@')[0]}
                  </h3>
                  <p className="text-sm text-gray-400">
                    {new Date(user.applied_at).toLocaleDateString() || "Jan 1, 2025"}
                  </p>
                        <select
                        className="mt-2 text-xs border rounded p-1 bg-gray-50"
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
                </div>

                {/* Right Side */}
                <div className="flex items-center gap-3">
                  <button
                    className="bg-green-600 hover:bg-green-500 text-white font-bold py-2 px-6 rounded-lg transition-colors"
                    onClick={() => {
                        setModalConfig({
                            type: 'approve',
                            id: user.id,
                            role: user.selectedRole || "AGENT"
                        })
                        setIsModalOpen(true)
                        }}
                  >
                    Accept
                  </button>

                  <button
                    className="bg-red-600 hover:bg-red-500 text-white font-bold py-2 px-6 rounded-lg transition-colors"
                    onClick={() => {
                      setModalConfig({ type: 'reject', id: user.id })
                      setIsModalOpen(true)
                    }}
                  >
                    Reject
                  </button>

                  <button
                    className="border border-gray-300 hover:bg-gray-100 text-gray-700 font-medium py-2 px-6 rounded-lg transition-colors"
                    onClick={() => navigate(`/admin/agent/${user.id}`)}
                  >
                    View
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}


      </div>
        {/* Pagination */}
        <Pagination
          currentPage={currentPage}
          totalPages={totalPages}
          onPageChange={setCurrentPage}
          hasNext={!!nextPage}
          hasPrevious={!!previousPage}
        />

      {/* Confirm Modal */}
      <ConfirmModal
        isOpen={isModalOpen}
        title={modalConfig.type === 'approve' ? "Approve Agent" : "Reject Agent"}
        message={modalConfig.type === 'approve' 
                  ? "Are you sure you want to approve this agent?" 
                  : "Are you sure you want to reject this agent?"}
        confirmText={modalConfig.type === 'approve' ? "Approve" : "Reject"}
        loadingText="Processing..."
        onCancel={() => setIsModalOpen(false)}
        onConfirm={handleAction}
        loading={loading}
      />
    </DashboardLayout>
  )
}

export default PendingUsers