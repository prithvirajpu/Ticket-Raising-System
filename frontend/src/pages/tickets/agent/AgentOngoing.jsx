import { useEffect, useState } from "react";
import { getOngoingTickets } from "../../../services/ticketService";
import DashboardLayout from "../../../layouts/DashboardLayout";
import { useNavigate } from "react-router-dom";
import { Search } from "lucide-react";
import Pagination from "../../../components/Pagination";

const AgentOngoing = () => {
  const [tickets, setTickets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [sort, setSort] = useState('newest');
  const [searchTerm, setSearchTerm] = useState(''); // Immediate UI state
  const [debouncedSearch, setDebouncedSearch] = useState(''); // Delayed API state
  const [page, setPage] = useState(1);
  const [pagination, setPagination] = useState({});
  const navigate = useNavigate();

  // 1. Logic for Debouncing the search input
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(searchTerm);
      setPage(1); // Reset to page 1 whenever search criteria changes
    }, 500);

    return () => clearTimeout(timer);
  }, [searchTerm]);

  // 2. Logic for fetching data
  // This triggers when debouncedSearch, sort, OR page changes
  useEffect(() => {
    const fetchTickets = async () => {
      setLoading(true);
      try {
        const res = await getOngoingTickets({ 
          search: debouncedSearch, 
          sort: sort, 
          page: page 
        });
        setTickets(res.message || []);
        setPagination(res.pagination || {});
      } catch (error) {
        console.error("Fetch error:", error);
      } finally {
        setLoading(false);
      }
    };

    fetchTickets();
  }, [debouncedSearch, sort, page]);

  const handleSearchChange = (e) => {
    setSearchTerm(e.target.value);
  };

  const handleSortChange = (e) => {
    setSort(e.target.value);
    setPage(1);
  };

  return (
    <DashboardLayout>
      <div className="bg-white min-h-screen">
        <div className="max-w-4xl mx-auto border border-gray-200 rounded-[2rem] p-10 shadow-sm min-h-[600px] flex flex-col">
          
          {/* Header & Controls */}
          <div className="flex flex-col md:flex-row items-center justify-between mb-8 gap-4">
            <h2 className="text-2xl font-bold text-gray-800">My Ongoing Tickets</h2>
            
            <div className="flex items-center gap-4 w-full md:w-auto">
              <div className="relative flex-1 md:flex-none">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input 
                  value={searchTerm}
                  onChange={handleSearchChange}
                  type="text" 
                  placeholder="Search..." 
                  className="pl-10 border border-gray-400 rounded-xl px-4 py-1.5 w-full md:w-64 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400"
                />
              </div>

              <div className="relative">
                <select
                  value={sort}
                  onChange={handleSortChange}
                  className="border border-gray-400 px-4 py-1.5 rounded-xl text-sm font-medium bg-white cursor-pointer focus:outline-none focus:ring-1 focus:ring-blue-400 appearance-none pr-8"
                >
                  <option value="newest">Newest First</option>
                  <option value="oldest">Oldest First</option>
                </select>
                <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-gray-400">
                  <svg className="fill-current h-4 w-4" viewBox="0 0 20 20"><path d="M9.293 12.95l.707.707L15.657 8l-1.414-1.414L10 10.828 5.757 6.586 4.343 8z"/></svg>
                </div>
              </div>
            </div>
          </div>

          {/* Ticket List */}
          <div className="space-y-6 flex-1">
            {loading ? (
              <div className="flex justify-center items-center h-40 text-gray-400 italic">
                Loading tickets...
              </div>
            ) : tickets.length === 0 ? (
              <div className="flex justify-center items-center h-40 text-gray-400 italic text-center">
                No ongoing tickets found matching "{debouncedSearch}"
              </div>
            ) : (
              tickets.map((ticket) => (
                <div
                  key={ticket.id}
                  onClick={() => navigate(`/agent/ticket-detail/${ticket.id}`)}
                  className="group relative p-6 border border-gray-300 rounded-[1.5rem] flex justify-between items-center cursor-pointer hover:border-[#3897f0] hover:shadow-md transition-all bg-white"
                >
                  <div className="flex items-start gap-4">
                    <div className="mt-2 w-3.5 h-3.5 rounded-full bg-yellow-400 shadow-sm" />
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="text-lg font-bold text-gray-900 group-hover:text-[#3897f0] transition-colors">
                          {ticket.subject}
                        </h3>
                        <span className="text-xs text-gray-400 font-mono">#{ticket.ticket_code}</span>
                      </div>
                      <p className="text-gray-400 text-sm max-w-md line-clamp-1 leading-relaxed mt-1">
                        {ticket.description || "In progress..."}
                      </p>
                    </div>
                  </div>

                  <span className="hidden sm:block bg-gray-50 text-gray-600 px-6 py-1.5 rounded-xl text-sm font-bold border border-gray-200">
                    In Progress
                  </span>
                </div>
              ))
            )}
          </div>

          {/* Pagination */}
          {!loading && pagination?.total_pages > 1 && (
            <div className="mt-8 border-t border-gray-100 pt-6">
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
    </DashboardLayout>
  );
};

export default AgentOngoing;