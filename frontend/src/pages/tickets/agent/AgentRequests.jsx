import { useEffect, useState } from "react";
import Lottie from 'lottie-react'
import {
  acceptTicket,
  getAgentRequests,
  rejectTicket,
} from "../../../services/ticketService";
import DashboardLayout from "../../../layouts/DashboardLayout";
import { useNavigate } from "react-router-dom";
import { Search, Loader2, ArrowUpDown, ChevronDown } from "lucide-react";
import ConfirmModal from "../../../components/modals/ConfirmModal";
import Pagination from "../../../components/Pagination";
import { notifyError } from "../../../utils/notify";

// Imported locally from your assets folder
import emptyQueueAnimation from "../../../assets/empty-queue.json";

const AgentRequests = () => {
  const [tickets, setTickets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [sort, setSort] = useState("newest");
  const [activeSortBtn, setActiveSortBtn] = useState("newest");

  const [searchTerm, setSearchTerm] = useState("");
  const [searchTimeout, setSearchTimeout] = useState(null);

  const [isModalOpen, setIsModalOpen] = useState(false);
  const [selectedTicketId, setSelectedTicketId] = useState(null);
  const [actionType, setActionType] = useState(null);
  const [modalLoading, setModalLoading] = useState(false);

  const [page, setPage] = useState(1);
  const [pagination, setPagination] = useState({});
  const navigate = useNavigate();

  useEffect(() => {
    fetchRequests(searchTerm, sort, page);
  }, [page]);

  useEffect(() => {
    if (searchTimeout) clearTimeout(searchTimeout);

    const timeout = setTimeout(() => {
      setPage(1); 
    }, 500);

    setSearchTimeout(timeout);
    return () => clearTimeout(timeout);
  }, [searchTerm, sort]);

  const handleTermChange = (e) => {
    setSearchTerm(e.target.value);
  };

  const fetchRequests = async (
    search = "",
    sortType = "newest",
    pageNum = 1,
  ) => {
    setLoading(true);
    try {
      const res = await getAgentRequests({
        search,
        sort: sortType,
        page: pageNum,
      });
      console.log(res.message);
      setTickets(res.message || []);
      setPagination(res.pagination);
      setActiveSortBtn(sortType);
    } catch (error) {
      console.log(error);
    } finally {
      setLoading(false);
    }
  };

  const handleSortChange = (e) => {
    const newSort = e.target.value;
    setSort(newSort);
    setActiveSortBtn(newSort);
  };

  const handleAccept = (id) => {
    setSelectedTicketId(id);
    setActionType("accept");
    setIsModalOpen(true);
  };

  const handleReject = (id) => {
    setSelectedTicketId(id);
    setActionType("reject");
    setIsModalOpen(true);
  };

  const handleConfirmAction = async () => {
    if (!selectedTicketId) return;

    setModalLoading(true);

    try {
      if (actionType === "accept") {
        await acceptTicket(selectedTicketId);
      } else {
        await rejectTicket(selectedTicketId);
      }

      fetchRequests(searchTerm, sort);
    } catch (err) {
      const errMsg =
        err.response?.data?.errors?.details || "something went wrong";
      notifyError(errMsg);
    } finally {
      setModalLoading(false);
      setIsModalOpen(false);
      setSelectedTicketId(null);
      setActionType(null);
    }
  };
  
  const handleCancel = () => {
    setIsModalOpen(false);
    setSelectedTicketId(null);
    setActionType(null);
  };

  return (
    <DashboardLayout>
      <div className="min-h-screen bg-slate-50/50 py-8 px-4 sm:px-6 lg:px-8">
        <div className="max-w-5xl mx-auto flex flex-col min-h-[700px]">
          
          {/* Header & Controls Area */}
          <div className="flex flex-col md:flex-row md:items-center justify-between pb-6 mb-6 border-b border-slate-200/60 gap-4">
            <div>
              <h2 className="text-2xl font-bold tracking-tight text-slate-900">
                 Requests ({pagination.total_items || 0})
              </h2>
              <p className="text-sm text-slate-500 mt-1">Review, accept, or decline</p>
            </div>

            <div className="flex flex-col sm:flex-row items-center gap-3 w-full md:w-auto">
              {/* Search Bar */}
              <div className="relative w-full sm:w-64">
                <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                <input
                  value={searchTerm}
                  onChange={handleTermChange}
                  type="text"
                  placeholder="Filter requests..."
                  className="w-full pl-10 pr-4 py-2 border border-slate-200 rounded-xl text-sm font-medium text-slate-800 placeholder-slate-400 bg-white shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all duration-150"
                />
              </div>

              {/* Sorting Filter */}
              <div className="relative w-full sm:w-auto">
                <ArrowUpDown className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
                <select
                  value={activeSortBtn}
                  onChange={handleSortChange}
                  className="w-full sm:w-auto pl-10 pr-10 py-2 border border-slate-200 rounded-xl text-sm font-semibold text-slate-700 bg-white shadow-sm cursor-pointer focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all duration-150 appearance-none"
                >
                  <option value="newest">Newest First</option>
                  <option value="oldest">Oldest First</option>
                </select>
                <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-3 text-slate-400">
                  <ChevronDown className="h-4 w-4" />
                </div>
              </div>
            </div>
          </div>

          {/* Ticket Request List Viewport */}
          <div className="flex-1 space-y-4">
            {loading ? (
              <div className="flex flex-col justify-center items-center h-64 bg-white rounded-2xl border border-slate-100 shadow-sm text-slate-400 gap-3">
                <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
                <span className="text-sm font-medium">Fetching incoming queue registry...</span>
              </div>
            ) : tickets.length === 0 ? (
              <div className="flex flex-col justify-center items-center min-h-[350px] bg-white rounded-2xl border border-slate-200/80 shadow-sm text-center p-6 transition-all duration-200">
                <div className="w-48 h-48 flex items-center justify-center">
                  <Lottie 
                    animationData={emptyQueueAnimation} 
                    loop={true} 
                    className="w-full h-full"
                  />
                </div>
                <h3 className="text-base font-bold text-slate-900 mt-2">Queue clean</h3>
                <p className="text-xs sm:text-sm text-slate-500 mt-1.5 max-w-sm leading-relaxed">
                  There are currently no new unassigned ticket requests awaiting processing parameters.
                </p>
              </div>
            ) : (
              tickets.map((ticket) => (
                <div
                  key={ticket.ticket_id}
                  className={`group relative p-5 bg-white border rounded-2xl flex flex-col lg:flex-row lg:items-center justify-between gap-4 transition-all duration-200 ${
                    ticket.status === "OPEN"
                      ? "border-blue-500 shadow-sm shadow-blue-500/[0.01]"
                      : "border-slate-200/80 hover:border-slate-300"
                  }`}
                >
                  <div className="flex items-start gap-4 min-w-0">
                    {/* Status Dot Ring */}
                    <div className="mt-1.5 flex-shrink-0 relative flex items-center justify-center">
                      {ticket.status !== "RESOLVED" && (
                        <span className="absolute inline-flex h-2 w-2 rounded-full bg-emerald-400 animate-ping" />
                      )}
                      <span className={`relative inline-flex rounded-full h-2 w-2 ${
                        ticket.status === "RESOLVED" ? "bg-emerald-500" : "bg-emerald-500"
                      }`} />
                    </div>

                    <div className="min-w-0">
                      <h3 className="text-sm sm:text-base font-bold text-slate-900 truncate">
                        {ticket.subject}
                      </h3>
                      <p className="text-slate-500 text-xs sm:text-sm line-clamp-2 leading-relaxed mt-1 max-w-2xl">
                        {ticket.description ||
                          "I am unable to login to my account. Getting an error message...."}
                      </p>
                    </div>
                  </div>

                  {/* Actions Area */}
                  <div className="flex items-center justify-end gap-2.5 border-t lg:border-t-0 pt-3 lg:pt-0 border-slate-100 flex-shrink-0">
                    {ticket.status !== "RESOLVED" ? (
                      <>
                        <button
                          onClick={() => handleReject(ticket.ticket_id)}
                          className="px-4 py-2 border border-red-200 text-red-600 hover:bg-red-50 text-xs sm:text-sm font-semibold rounded-xl transition-all active:scale-[0.98]"
                        >
                          Reject
                        </button>
                        <button
                          onClick={() => handleAccept(ticket.ticket_id)}
                          className="px-5 py-2 bg-blue-600 hover:bg-blue-700 text-white shadow-sm shadow-blue-600/10 text-xs sm:text-sm font-semibold rounded-xl transition-all active:scale-[0.98]"
                        >
                          Accept
                        </button>
                      </>
                    ) : (
                      <span className="inline-flex items-center text-xs font-semibold px-3 py-1 bg-emerald-50 text-emerald-700 border border-emerald-100 rounded-lg">
                        Resolved
                      </span>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>

          {/* Pagination Footer */}
          {!loading && pagination?.total_pages > 1 && (
            <div className="mt-8 border-t border-slate-200/60 pt-6">
              <Pagination
                currentPage={pagination.current_page}
                totalPages={pagination.total_pages}
                hasNext={pagination.has_next}
                hasPrevious={pagination.has_previous}
                onPageChange={(newPage) => setPage(newPage)}
              />
            </div>
          )}
        </div>
      </div>

      <ConfirmModal
        isOpen={isModalOpen}
        title={
          actionType === "accept" ? "Accept Ticket?" : "Reject Ticket (Penalty)?"
        }
        message={
          actionType === "accept"
            ? "Do you want to accept this ticket?"
            : "⚠️ Rejecting this ticket will incur a $10 penalty, which will be deducted from your wallet. Continue?"
        }
        confirmText={actionType === "accept" ? "Accept" : "Reject"}
        loadingText="Processing..."
        onConfirm={handleConfirmAction}
        onCancel={handleCancel}
        loading={modalLoading}
      />
    </DashboardLayout>
  );
};

export default AgentRequests;