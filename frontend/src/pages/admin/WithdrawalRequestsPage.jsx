import React, { useEffect, useState } from "react";
import DashboardLayout from "../../layouts/DashboardLayout";
import { approveWithdrawal, getWithdrawRequests, rejectWithdrawal } from "../../services/ticketService";
import { notifySuccess } from "../../utils/notify";
import Pagination from "../../components/Pagination";
import { Wallet, Mail, DollarSign, Calendar, CheckCircle2, XCircle, AlertCircle } from 'lucide-react'
import ConfirmModal from "../../components/modals/ConfirmModal";

const WithdrawalRequestsPage = () => {
  const [requests, setRequests] = useState([]);

  // Modal State Control Mechanics
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalLoading, setModalLoading] = useState(false);
  const [modalConfig, setModalConfig] = useState({ id: null, type: "" });

  // Preserved pagination state variables for future dynamic data integration
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [nextPage, setNextPage] = useState(null);
  const [previousPage, setPreviousPage] = useState(null);

  useEffect(() => {
    fetchRequests();
  }, [currentPage]); // Triggers view update smoothly when pagination changes

  const fetchRequests = async () => {
    try {
      const res = await getWithdrawRequests();
      console.log('requests', res);
      setRequests(res.message);
      
      // Note: When your backend transitions to page-by-page slicing payload structures,
      // you can hook into Paginator objects directly here (e.g., setTotalPages(Math.ceil(...)))
    } catch (error) {
      console.log(error);
    }
  };

  // Intercept actions to open the confirmation modal
  const triggerApproveModal = (id) => {
    setModalConfig({ id, type: "APPROVE" });
    setIsModalOpen(true);
  };

  const triggerRejectModal = (id) => {
    setModalConfig({ id, type: "REJECT" });
    setIsModalOpen(true);
  };

  // Executed inside ConfirmModal upon user verification
  const handleModalConfirm = async () => {
    try {
      setModalLoading(true);
      if (modalConfig.type === "APPROVE") {
        await approveWithdrawal(modalConfig.id);
        notifySuccess('Approved successfully');
      } else if (modalConfig.type === "REJECT") {
        await rejectWithdrawal(modalConfig.id);
        notifySuccess('Rejected successfully');
      }
      await fetchRequests(); // Refresh table datasets
    } catch (error) {
      console.error(error);
    } finally {
      setModalLoading(false);
      setIsModalOpen(false);
    }
  };

  return (
    <DashboardLayout title="Financial Operations">
      <div className="text-slate-800 antialiased space-y-6">
        
        {/* HEADER CONTROL PANEL */}
        <div className="bg-white border border-slate-200/80 p-5 rounded-2xl shadow-sm">
          <h2 className="text-xl font-bold text-slate-900 tracking-tight">Withdrawal Requests</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Review workspace balance extractions, trace transaction logs, and manage ledger balances.
          </p>
        </div>

        {/* DATA CONTAINER MATRICES */}
        <div className="bg-white rounded-2xl border border-slate-200/80 shadow-sm overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left">
              <thead>
                <tr className="bg-slate-50/70 border-b border-slate-200/60 text-[11px] font-bold tracking-wider text-slate-400 uppercase">
                  <th className="p-4 font-semibold w-16">Idx</th>
                  <th className="p-4 font-semibold">User</th>
                  <th className="p-4 font-semibold">Role</th>
                  <th className="p-4 font-semibold">Amount</th>
                  <th className="p-4 font-semibold">Status</th>
                  <th className="p-4 font-semibold">Requested At</th>
                  <th className="p-4 font-semibold text-right pr-6">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-medium text-slate-700 text-sm">
                {requests.length > 0 ? (
                  requests.map((item, index) => {
                    // Match the precise sequential row counting algorithm used across your platform
                    const pageSize = 10;
                    const serialNumber = (currentPage - 1) * pageSize + index + 1;

                    return (
                      <tr key={item.id} className="hover:bg-slate-50/40 transition-colors group">
                        
                        {/* Row Index Serial Number */}
                        <td className="p-4 font-mono text-xs text-slate-400">{serialNumber}</td>

                        {/* User */}
                        <td className="p-4 text-slate-600 font-medium">
                          <div className="flex items-center gap-1.5">
                            <Mail className="w-3.5 h-3.5 text-slate-400" />
                            <span className="font-bold text-slate-900 tracking-tight">{item.user_email}</span>
                          </div>
                        </td>

                        {/* Role */}
                        <td className="p-4">
                          <div className="flex items-center gap-1.5 text-xs text-slate-800 font-semibold bg-slate-100 px-2.5 py-1 rounded-md border border-slate-200/40 uppercase tracking-wider inline-flex">
                            <span>{item.user_role}</span>
                          </div>
                        </td>

                        {/* Amount */}
                        <td className="p-4 font-bold text-slate-900 tracking-tight">
                          <div className="flex items-center text-slate-900">
                            <DollarSign className="w-3.5 h-3.5 text-slate-500 mr-0.5" />
                            <span>{item.amount}</span>
                          </div>
                        </td>

                        {/* Status */}
                        <td className="p-4">
                          {item.status === "PENDING" && (
                            <span className="inline-flex items-center gap-1 text-xs text-amber-700 font-bold bg-amber-50 px-2.5 py-1 rounded-full border border-amber-200/40">
                              <AlertCircle className="w-3 h-3 text-amber-500" /> PENDING
                            </span>
                          )}
                          {item.status === "APPROVED" && (
                            <span className="inline-flex items-center gap-1 text-xs text-emerald-700 font-bold bg-emerald-50 px-2.5 py-1 rounded-full border border-emerald-200/40">
                              <CheckCircle2 className="w-3 h-3 text-emerald-500" /> APPROVED
                            </span>
                          )}
                          {item.status !== "PENDING" && item.status !== "APPROVED" && (
                            <span className="inline-flex items-center gap-1 text-xs text-rose-700 font-bold bg-rose-50 px-2.5 py-1 rounded-full border border-rose-200/40">
                              <XCircle className="w-3 h-3 text-rose-500" /> {item.status}
                            </span>
                          )}
                        </td>

                        {/* Requested At */}
                        <td className="p-4 text-slate-500 font-normal text-xs">
                          <div className="flex items-center gap-1.5">
                            <Calendar className="w-3.5 h-3.5 text-slate-400" />
                            <span>{new Date(item.requested_at).toLocaleString()}</span>
                          </div>
                        </td>

                        {/* Action Control Pipelines */}
                        <td className="p-4 text-right pr-6">
                          {item.status === "PENDING" && (
                            <div className="flex items-center justify-end gap-2">
                              <button 
                                onClick={() => triggerApproveModal(item.id)}
                                className="inline-flex items-center justify-center px-3 py-1.5 text-xs font-bold text-emerald-700 bg-white hover:bg-emerald-50/50 border border-emerald-200 rounded-xl transition-all active:scale-[0.97] min-w-[75px] shadow-2xs"
                              >
                                Approve
                              </button>

                              <button 
                                onClick={() => triggerRejectModal(item.id)}
                                className="inline-flex items-center justify-center px-3 py-1.5 text-xs font-bold text-rose-700 bg-white hover:bg-rose-50/50 border border-rose-200 rounded-xl transition-all active:scale-[0.97] min-w-[75px] shadow-2xs"
                              >
                                Reject
                              </button>
                            </div>
                          )}
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan="7" className="text-center py-12 px-4 text-slate-400 italic">
                      <div className="flex flex-col items-center justify-center gap-2">
                        <Wallet className="w-8 h-8 text-slate-300 stroke-[1.5]" />
                        <span>No withdrawal requests found in this ledger scope.</span>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {/* TABLE FOOTER CONTROL PANEL (PAGINATION INTERFACE) */}
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

      </div>

      {/* MODAL WRAPPER LAYER (Fixes z-index stack dominance across layout frameworks) */}
      <div className="relative z-[100]">
        <ConfirmModal
          isOpen={isModalOpen}
          loading={modalLoading}
          title={modalConfig.type === "APPROVE" ? "Approve Withdrawal Request" : "Reject Withdrawal Request"}
          message={
            modalConfig.type === "APPROVE"
              ? "Are you sure you want to approve this financial extraction entry? This execution sequence will authorize balance processing pipelines."
              : "Are you sure you want to reject this withdrawal request? This transaction action will cancel the ledger settlement request."
          }
          confirmText={modalConfig.type === "APPROVE" ? "Approve Request" : "Reject Request"}
          onConfirm={handleModalConfirm}
          onCancel={() => setIsModalOpen(false)}
        />
      </div>
    </DashboardLayout>
  );
};

export default WithdrawalRequestsPage;