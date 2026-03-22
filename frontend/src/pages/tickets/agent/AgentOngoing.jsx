import { useEffect, useState } from "react";
import { getOngoingTickets } from "../../../services/ticketService";
import DashboardLayout from "../../../layouts/DashboardLayout";
import { useNavigate } from "react-router-dom";
import { Search, ChevronDown } from "lucide-react";

const AgentOngoing = () => {
  const [tickets, setTickets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [sort, setSort] = useState('newest');
  const [activeSortBtn, setActiveSortBtn] = useState('newest');
  const navigate = useNavigate();

  useEffect(() => {
    fetchTickets(sort);
  }, [sort]);

  const fetchTickets = async (sortType = 'newest') => {
    setLoading(true);
    try {
      const res = await getOngoingTickets(sortType);
       console.log('📦 API Response:', res.message);  // ADD THIS
    console.log('📅 First ticket created_at:', res.message?.[0]?.created_at); 
      setTickets(res.message || []); 
      setActiveSortBtn(sortType);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleSortChange = (e) => {
    const newSort = e.target.value;
    setSort(newSort);
    setActiveSortBtn(newSort);
  };

  return (
    <DashboardLayout>
      <div className="bg-white min-h-screen">
        {/* Main Content Container */}
        <div className="max-w-4xl mx-auto border border-gray-200 rounded-[2rem] p-10 shadow-sm min-h-[600px] flex flex-col">
          
          {/* Header & Controls */}
          <div className="flex items-center justify-between mb-8">
            <h2 className="text-2xl font-bold text-gray-800">My Ongoing Tickets</h2>
            
            <div className="flex items-center gap-4">
              <div className="relative">
                <input 
                  type="text" 
                  placeholder="Search..." 
                  className="border border-gray-400 rounded-xl px-4 py-1.5 w-64 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400"
                />
              </div>

              {/* ✅ WORKING SELECT DROPDOWN - Same Design */}
              <div className="relative">
                <select
                  value={activeSortBtn}
                  onChange={handleSortChange}
                  className="flex items-center gap-2 border border-gray-400 px-4 py-1.5 rounded-xl text-sm font-medium bg-white appearance-none cursor-pointer focus:outline-none focus:ring-1 focus:ring-blue-400"
                >
                  <option value="newest">Newest First</option>
                  <option value="oldest">Oldest First</option>
                </select>
                <ChevronDown size={16} className="absolute right-3 top-1/2 transform -translate-y-1/2 pointer-events-none text-gray-400" />
              </div>
            </div>
          </div>

          {/* Ticket List */}
          <div className="space-y-6 flex-1">
            {loading ? (
              <div className="flex justify-center items-center h-40 text-gray-400 italic">Loading tickets...</div>
            ) : tickets.length === 0 ? (
              <div className="flex justify-center items-center h-40 text-gray-400 italic">No active tickets found</div>
            ) : (
              tickets.map((ticket) => (
                <div
                  key={ticket.id}
                  onClick={() => navigate(`/agent/ticket-detail/${ticket.id}`)}
                  className="group relative p-6 border border-gray-300 rounded-[1.5rem] flex justify-between items-center cursor-pointer hover:border-[#3897f0] hover:shadow-md transition-all"
                >
                  <div className="flex items-start gap-4">
                    {/* Status Dot */}
                    <div className="mt-2 w-3.5 h-3.5 rounded-full bg-[#d4d44d]" />
                    
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="text-lg font-bold text-gray-900 group-hover:text-[#3897f0] transition-colors">
                          {ticket.subject}
                        </h3>
                        <span className="text-xs text-gray-400 font-mono">#{ticket.ticket_code}</span>
                      </div>
                      <p className="text-gray-400 text-sm max-w-md line-clamp-1 leading-relaxed mt-1">
                        {ticket.description || "Currently being processed by you..."}
                      </p>
                    </div>
                  </div>

                  <span className="bg-gray-100 text-gray-600 px-8 py-1.5 rounded-xl text-sm font-bold border border-gray-200">
                    In Progress
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default AgentOngoing;
