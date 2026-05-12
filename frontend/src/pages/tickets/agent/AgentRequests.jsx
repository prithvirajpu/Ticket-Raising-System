import { useEffect, useState } from "react";
import { acceptTicket, getAgentRequests, rejectTicket } from "../../../services/ticketService";
import DashboardLayout from "../../../layouts/DashboardLayout";
import { useNavigate } from "react-router-dom";
import { Search, ChevronDown } from "lucide-react";
import ConfirmModal from "../../../components/modals/ConfirmModal";
import Pagination from '../../../components/Pagination'
import { notifyError } from "../../../utils/notify";

const AgentRequests = () => {
  const [tickets, setTickets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [sort, setSort] = useState('newest');
  const [activeSortBtn, setActiveSortBtn] = useState('newest');

  const [searchTerm,setSearchTerm]=useState('')
  const [searchTimeout, setSearchTimeout] = useState(null);

  const [isModalOpen, setIsModalOpen] = useState(false);
  const [selectedTicketId, setSelectedTicketId] = useState(null);
  const [actionType, setActionType] = useState(null); 
  const [modalLoading, setModalLoading] = useState(false);

  const [page,setPage]=useState(1);
  const [pagination,setPagination]=useState({});
  const navigate = useNavigate();


useEffect(() => {
  fetchRequests(searchTerm, sort, page);
}, [page]);

useEffect(() => {
  if (searchTimeout) clearTimeout(searchTimeout);

  const timeout = setTimeout(() => {
    setPage(1); // ONLY change page
  }, 500);

  setSearchTimeout(timeout);
  return () => clearTimeout(timeout);

}, [searchTerm, sort]);

  const handleTermChange=(e)=>{
    setSearchTerm(e.target.value)
  }

  const fetchRequests = async (search='',sortType = 'newest',pageNum=1) => {
    setLoading(true);
    try {
      const res = await getAgentRequests({search,sort:sortType,page:pageNum});
      console.log(res.message)
      setTickets(res.message || []);
      setPagination(res.pagination)
      setActiveSortBtn(sortType);
    } catch (error) {
      console.log(error)
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
      const errMsg= err.response?.data?.errors?.details ||'something went wrong'
      notifyError(errMsg)
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
      <div className="bg-white min-h-screen">

        {/* Main Content Container */}
        <div className="max-w-4xl mx-auto border border-gray-200 rounded-[2rem] p-10 shadow-sm min-h-[600px] flex flex-col">
          
          {/* Header & Controls */}
          <div className="flex items-center justify-between mb-8">
            <h2 className="text-2xl font-bold text-gray-800">All Tickets ({pagination.total_items || 0})</h2>
            
            <div className="flex items-center gap-4">
              {/* Search Bar */}
              <div className="relative">
                <input 
                value={searchTerm}
                onChange={handleTermChange}
                  type="text" 
                  placeholder="Search..." 
                  className="border border-gray-400 rounded-xl px-4 py-1.5 w-64 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400"
                />
              </div>

              {/* ✅ SAME SORTING DROPDOWN AS AGENTONGOING */}
              <div className="relative">
                <select
                  value={activeSortBtn}
                  onChange={handleSortChange}
                  className="flex items-center gap-2 border border-gray-400 px-4 py-1.5 rounded-xl text-sm font-medium bg-white appearance-none cursor-pointer focus:outline-none focus:ring-1 focus:ring-blue-400"
                >
                  <option value="newest">Newest First</option>
                  <option value="oldest">Oldest First</option>
                </select>
              </div>
            </div>
          </div>

          {/* Ticket List */}
          <div className="space-y-6 flex-1">
            {loading ? (
              <div className="flex justify-center items-center h-40 text-gray-400 italic">Loading requests...</div>
            ) : tickets.length === 0 ? (
              <div className="flex justify-center items-center h-40 text-gray-400 italic">No requests</div>
            ) : (
              tickets.map((ticket) => (
                <div
                  key={ticket.ticket_id}
                  className={`relative p-6 border rounded-[1.5rem] flex justify-between items-center transition-all ${
                    ticket.status === 'OPEN' ? 'border-[#3897f0] border-2' : 'border-gray-300'
                  }`}
                >
                  <div className="flex items-start gap-4">
                    {/* Status Dot */}
                    <div className={`mt-2 w-3.5 h-3.5 rounded-full ${
                      ticket.status === 'RESOLVED' ? 'bg-[#4ade80]' : 'bg-[#d4d44d]'
                    }`} />
                    
                    <div>
                      <h3 className="text-lg font-bold text-gray-900">{ticket.subject}</h3>
                      <p className="text-gray-400 text-sm max-w-md line-clamp-2 leading-relaxed">
                        {ticket.description || "I am unable to login to my account. Getting an error message...."}
                      </p>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-3">
                    {ticket.status !== 'RESOLVED' ? (
                      <>
                        <button
                          onClick={() => handleReject(ticket.ticket_id)}
                          className="bg-red-600 text-white px-8 py-1.5 rounded-xl text-sm font-bold shadow-sm hover:bg-red-700 transition-colors"
                        >
                          Reject
                        </button>
                        <button
                          onClick={() => handleAccept(ticket.ticket_id)}
                          className="bg-green-400 text-black px-8 py-1.5 rounded-xl text-sm font-bold shadow-sm hover:bg-green-500 transition-colors"
                        >
                          Accept
                        </button>
                      </>
                    ) : (
                      <span className="bg-[#00ff00] text-black px-8 py-1.5 rounded-xl text-sm font-bold border border-black/10">
                        Resolved
                      </span>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>

          {pagination?.total_pages > 1 && (
            <Pagination
              currentPage={pagination.current_page}
              totalPages={pagination.total_pages}
              hasNext={pagination.has_next}
              hasPrevious={pagination.has_previous}
              onPageChange={(newPage) => setPage(newPage)}
            />
          )}
        </div>
      </div>
      <ConfirmModal
          isOpen={isModalOpen}
          title={actionType === "accept" ? "Accept Ticket?" : "Reject Ticket?"}
          message={
            actionType === "accept"
              ? "Do you want to accept this ticket?"
              : "Are you sure you want to reject this ticket?"
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
