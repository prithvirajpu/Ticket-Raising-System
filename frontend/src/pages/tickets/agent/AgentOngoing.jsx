import { useEffect, useState } from "react";
import { getOngoingTickets } from "../../../services/ticketService";
import DashboardLayout from "../../../layouts/DashboardLayout";
import { useNavigate } from "react-router-dom";
import { Search, Loader2, ArrowUpDown, Tag, Calendar, ChevronRight } from "lucide-react";
import Pagination from "../../../components/Pagination";
import Lottie from 'lottie-react';
// Note: Make sure to adjust the relative path (../) to point to your assets folder!
import emptyQueueAnimation from "../../../assets/empty-queue.json";

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
      <div className="min-h-screen bg-slate-50/50 py-8 px-4 sm:px-6 lg:px-8">
        <div className="max-w-5xl mx-auto flex flex-col min-h-[700px]">
          
          {/* Header & Controls Area */}
          <div className="flex flex-col md:flex-row md:items-center justify-between pb-6 mb-6 border-b border-slate-200/60 gap-4">
            <div>
              <h2 className="text-2xl font-bold tracking-tight text-slate-900">My Ongoing Tickets</h2>
              <p className="text-sm text-slate-500 mt-1">Manage and resolve queries.</p>
            </div>
            
            <div className="flex flex-col sm:flex-row items-center gap-3 w-full md:w-auto">
              {/* Search Box */}
              <div className="relative w-full sm:w-64">
                <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                <input 
                  value={searchTerm}
                  onChange={handleSearchChange}
                  type="text" 
                  placeholder="Filter tickets..." 
                  className="w-full pl-10 pr-4 py-2 border border-slate-200 rounded-xl text-sm font-medium text-slate-800 placeholder-slate-400 bg-white shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all duration-150"
                />
              </div>

              {/* Sorting Filter */}
              <div className="relative w-full sm:w-auto">
                <ArrowUpDown className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
                <select
                  value={sort}
                  onChange={handleSortChange}
                  className="w-full sm:w-auto pl-10 pr-10 py-2 border border-slate-200 rounded-xl text-sm font-semibold text-slate-700 bg-white shadow-sm cursor-pointer focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all duration-150 appearance-none"
                >
                  <option value="newest">Newest First</option>
                  <option value="oldest">Oldest First</option>
                </select>
                <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-3 text-slate-400">
                  <svg className="fill-current h-4 w-4" viewBox="0 0 20 20">
                    <path d="M9.293 12.95l.707.707L15.657 8l-1.414-1.414L10 10.828 5.757 6.586 4.343 8z"/>
                  </svg>
                </div>
              </div>
            </div>
          </div>

          {/* Ticket List Viewport */}
          <div className="flex-1 space-y-4">
            {loading ? (
              <div className="flex flex-col justify-center items-center h-64 bg-white rounded-2xl border border-slate-100 shadow-sm text-slate-400 gap-3">
                <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
                <span className="text-sm font-medium">Fetching your active ticket registry...</span>
              </div>
            ) : tickets.length === 0 ? (
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
              tickets.map((ticket) => (
                <div
                  key={ticket.id}
                  onClick={() => navigate(`/agent/ticket-detail/${ticket.id}`)}
                  className="group relative p-5 bg-white border border-slate-200/80 rounded-2xl flex flex-col sm:flex-row sm:items-center justify-between gap-4 cursor-pointer hover:border-blue-500 hover:shadow-md hover:shadow-blue-500/[0.02] transition-all duration-200"
                >
                  <div className="flex items-start gap-4 min-w-0">
                    {/* Status indicator ring */}
                    <div className="mt-1 flex-shrink-0 relative flex items-center justify-center">
                      <span className="absolute inline-flex h-2 w-2 rounded-full bg-amber-400 animate-ping" />
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-amber-500" />
                    </div>

                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-[11px] font-semibold font-mono px-2 py-0.5 bg-slate-100 text-slate-600 rounded">
                          #{ticket.ticket_code}
                        </span>
                        <h3 className="text-sm sm:text-base font-bold text-slate-900 group-hover:text-blue-600 transition-colors truncate">
                          {ticket.subject}
                        </h3>
                      </div>
                      
                      <p className="text-slate-500 text-xs sm:text-sm line-clamp-1 leading-relaxed mt-1.5 max-w-2xl">
                        {ticket.description || "In progress..."}
                      </p>
                    </div>
                  </div>

                  {/* Actions & Badge Column */}
                  <div className="flex items-center justify-between sm:justify-end gap-3 border-t sm:border-t-0 pt-3 sm:pt-0 border-slate-100">
                    <span className="inline-flex items-center text-xs font-semibold px-3 py-1 bg-amber-50 text-amber-700 border border-amber-100 rounded-lg">
                      In Progress
                    </span>
                    <div className="p-1 rounded-lg text-slate-400 group-hover:text-blue-500 group-hover:bg-blue-50 transition-all duration-150">
                      <ChevronRight className="w-5 h-5" />
                    </div>
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
    </DashboardLayout>
  );
};

export default AgentOngoing;