import React, { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { getTickets } from '../../../services/ticketService'
import DashboardLayout from '../../../layouts/DashboardLayout'
import { Plus, Search, ChevronDown, ChevronRight, ArrowUpDown } from 'lucide-react'
import Pagination from '../../../components/Pagination'

const TicketsList = () => {
    const [tickets, setTickets] = useState([])
    const [loading, setLoading] = useState(false)

    const [sort, setSort] = useState('newest');
    const [activeSortBtn, setActiveSortBtn] = useState('newest');

    const [searchTerm,setSearchTerm]=useState('')
    const navigate = useNavigate();

    const [page, setPage] = useState(1);
    const [pagination, setPagination] = useState({});


    
// Reset page ONLY if not already 1
useEffect(() => {
    if (page !== 1) {
        setPage(1);
    }
}, [searchTerm, sort]);

// Fetch data
useEffect(() => {
    const timeout = setTimeout(() => {
        fetchTickets(searchTerm, sort, page);
    }, 500);

    return () => clearTimeout(timeout);
}, [searchTerm, sort, page]);

    const handleSearchChange=(e)=>{
        setSearchTerm(e.target.value)
    }
    const fetchTickets = async (search='',sortType='newest',pageNum=1) => {
        setLoading(true)
        try {
            const data = await getTickets({search,sort:sortType,page:pageNum});
            setTickets(data.message || [])
            setPagination(data.pagination || {})
            setActiveSortBtn(sortType)
        } catch (error) {
            console.error(error)
        } finally {
            setLoading(false)
        }
    }
    const handleSortChange=(e)=>{
        const newSort=e.target.value;
        setSort(newSort);
        setActiveSortBtn(newSort);
    }
    const handlePageChange = (newPage) => {
        setPage(newPage);
    };

    const getStatusBadge = (status) => {
        return (
            <span className="px-3 py-1 rounded-full border border-gray-300 text-xs font-medium text-gray-600 bg-white">
                {status.charAt(0).toUpperCase() + status.slice(1).toLowerCase()}
            </span>
        )
    }

    const getIndicatorColor = (status) => {
      if (status === "OPEN") return "bg-yellow-400";
      if (status === "IN_PROGRESS") return "bg-blue-400";
      if (status === "ESCALATED") return "bg-red-500";
      if (status === "RESOLVED") return "bg-green-500";
      if (status === "CLOSED") return "bg-gray-500";
      return "bg-gray-300"; 
    }

    return (
        <DashboardLayout>
            <div className="max-w-5xl mx-auto font-sans">
                {/* Main Container Card */}
                <div className="bg-white border border-gray-200 rounded-3xl p-8 shadow-sm">
                    
                    {/* Top Action Bar */}
                    <div className="flex justify-end mb-8">
                        <button
                            onClick={() => navigate("/user/create-ticket")}
                            className="flex items-center gap-2 bg-black text-white px-5 py-2.5 rounded-xl hover:bg-gray-800 transition-all text-sm font-bold"
                        >
                            <Plus size={18} />
                            Raise New Ticket
                        </button>
                    </div>

                    {/* Filter Bar */}
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-10">
                        <div className="flex items-center gap-4">
                            <h2 className="text-xl font-bold text-gray-800">All Tickets</h2>
                            <div className="relative">
                                <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" size={16} />
                                <input 
                                    value={searchTerm}
                                    onChange={handleSearchChange}
                                    type="text" 
                                    placeholder="Search..." 
                                    className="pl-10 pr-4 py-2 bg-white border border-gray-300 rounded-xl focus:outline-none focus:ring-1 focus:ring-gray-400 w-64 text-sm"
                                />
                            </div>
                        </div>

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

                    {/* Ticket Cards List */}
                    <div className="space-y-4 mb-10">
                        {loading ? (
                            <div className="py-10 text-center text-gray-400">Loading tickets...</div>
                        ) : tickets.map((ticket) => (
                            <div 
                                key={ticket.id}
                                onClick={() => navigate(`/user/tickets/details/${ticket.id}`)}
                                className="group flex items-center justify-between border border-gray-200 rounded-3xl p-6 hover:shadow-md transition-all cursor-pointer bg-white"
                            >
                                <div className="flex items-start gap-5">
                                    {/* Status Indicator Dot */}
                                    <div className={`mt-1.5 w-3.5 h-3.5 rounded-full ${getIndicatorColor(ticket.status)} shadow-sm`} />
                                    
                                    <div>
                                        <h3 className="text-lg font-bold text-gray-900 group-hover:text-blue-600 transition-colors">
                                            {ticket.subject}
                                        </h3>
                                        <p className="text-sm text-gray-400 mt-1 line-clamp-1 max-w-md">
                                            {ticket.description || "No additional details provided..."}
                                        </p>
                                    </div>
                                </div>

                                <div className="flex items-center gap-6">
                                    {ticket.status === 'RESOLVED' && (
                                        <button className="bg-emerald-400 text-black text-[10px] font-bold px-3 py-1.5 rounded-lg uppercase tracking-tight hover:bg-emerald-500 transition-colors">
                                            Review and feedback
                                        </button>
                                    )}
                                    
                                    {getStatusBadge(ticket.status)}
                                    
                                    <span className="text-sm text-gray-400 font-medium">
                                        {new Date(ticket.created_at).toLocaleDateString('en-GB')}
                                    </span>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
            {pagination?.total_pages > 1 && (
                <Pagination
                    currentPage={pagination.current_page || 1}
                    totalPages={pagination.total_pages || 1}
                    hasNext={pagination.has_next}
                    hasPrevious={pagination.has_previous}
                    onPageChange={handlePageChange}
                />
                )}
        </DashboardLayout>
    )
}

export default TicketsList