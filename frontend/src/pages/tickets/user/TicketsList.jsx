import React, { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { getTickets } from '../../../services/ticketService'
import DashboardLayout from '../../../layouts/DashboardLayout'
import { Plus, Search, ChevronDown, ChevronRight, ArrowUpDown, Calendar, MessageSquare, ClipboardList } from 'lucide-react'
import Pagination from '../../../components/Pagination'

const TicketsList = () => {
    const [tickets, setTickets] = useState([])
    const [loading, setLoading] = useState(false)

    const [sort, setSort] = useState('newest');
    const [activeSortBtn, setActiveSortBtn] = useState('newest');

    const [searchTerm, setSearchTerm] = useState('')
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

    const handleSearchChange = (e) => {
        setSearchTerm(e.target.value)
    }

    const fetchTickets = async (search = '', sortType = 'newest', pageNum = 1) => {
        setLoading(true)
        try {
            const data = await getTickets({ search, sort: sortType, page: pageNum });
            console.log("API RESPONSE:", data);
            setTickets(data.message || [])
            setPagination(data.pagination || {})
            setActiveSortBtn(sortType)
        } catch (error) {
            console.error(error)
        } finally {
            setLoading(false)
        }
    }

    const handleSortChange = (e) => {
        const newSort = e.target.value;
        setSort(newSort);
        setActiveSortBtn(newSort);
    }

    const handlePageChange = (newPage) => {
        setPage(newPage);
    };

    const getStatusBadge = (status) => {
        const statusMap = {
            'OPEN': 'text-amber-700 bg-amber-50 border-amber-200/60',
            'IN_PROGRESS': 'text-blue-700 bg-blue-50 border-blue-200/60',
            'ESCALATED': 'text-red-700 bg-red-50 border-red-200/60',
            'RESOLVED': 'text-emerald-700 bg-emerald-50 border-emerald-200/60',
            'CLOSED': 'text-slate-600 bg-slate-100 border-slate-200',
        };
        const styles = statusMap[status.toUpperCase()] || 'text-gray-600 bg-gray-50 border-gray-200';
        
        return (
            <span className={`px-2.5 py-1 rounded-full border text-xs font-bold tracking-tight whitespace-nowrap ${styles}`}>
                {status.charAt(0).toUpperCase() + status.slice(1).toLowerCase()}
            </span>
        )
    }

    const getIndicatorColor = (status) => {
        if (status === "OPEN") return "bg-amber-400";
        if (status === "IN_PROGRESS") return "bg-blue-400";
        if (status === "ESCALATED") return "bg-red-500";
        if (status === "RESOLVED") return "bg-green-500";
        if (status === "CLOSED") return "bg-slate-400";
        return "bg-gray-300"; 
    }

    return (
        <DashboardLayout title="Support Operations">
            <div className="max-w-5xl mx-auto text-slate-800 antialiased space-y-6">
                
                {/* Main Container Card */}
                <div className="bg-white border border-slate-200/80 rounded-2xl p-4 sm:p-6 lg:p-8 shadow-sm">
                    
                    {/* Top Control Panel Info Bar */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 pb-6 mb-6">
                        <div>
                            <h2 className="text-xl font-bold text-slate-900 tracking-tight">Active Tickets</h2>
                            <p className="text-xs text-slate-500 mt-0.5">Manage, track state assignments, and view user resolution updates.</p>
                        </div>
                        <button
                            onClick={() => navigate("/user/create-ticket")}
                            className="flex items-center justify-center gap-2 bg-slate-900 text-white px-4 py-2.5 rounded-xl hover:bg-slate-800 active:scale-[0.98] transition-all text-xs sm:text-sm font-bold shadow-sm w-full sm:w-auto"
                        >
                            <Plus size={16} />
                            Raise New Ticket
                        </button>
                    </div>

                    {/* Filter / Search Bar */}
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 mb-6">
                        <div className="relative w-full md:max-w-md flex-1">
                            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" size={15} />
                            <input 
                                value={searchTerm}
                                onChange={handleSearchChange}
                                type="text" 
                                placeholder="Search ticketing manifests..." 
                                className="pl-10 pr-4 py-2.5 bg-white border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-slate-900/5 focus:border-slate-400 w-full text-sm placeholder-slate-400 transition-all shadow-inner"
                            />
                        </div>

                        <div className="relative w-full md:w-48">
                            <select
                                value={activeSortBtn}
                                onChange={handleSortChange}
                                className="w-full flex items-center justify-between border border-slate-200 pl-4 pr-10 py-2.5 rounded-xl text-sm font-semibold bg-white text-slate-700 appearance-none cursor-pointer focus:outline-none focus:ring-2 focus:ring-slate-900/5 focus:border-slate-400 transition-all"
                            >
                                <option value="newest">Newest First</option>
                                <option value="oldest">Oldest First</option>
                            </select>
                            <ChevronDown className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" size={16} />
                        </div>
                    </div>

                    {/* Ticket Cards List */}
                    <div className="space-y-3">
                        {loading ? (
                            <div className="py-16 text-center text-slate-400 italic text-sm flex flex-col items-center justify-center gap-2">
                                <div className="w-6 h-6 border-2 border-slate-300 border-t-slate-800 rounded-full animate-spin" />
                                <span>Syncing records layout streams...</span>
                            </div>
                        ) : tickets.length === 0 ? (
                            <div className="py-16 text-center text-slate-400 italic text-sm border border-dashed border-slate-200 rounded-2xl flex flex-col items-center justify-center gap-2">
                                <ClipboardList className="w-8 h-8 text-slate-300 stroke-[1.5]" />
                                <span>No ticketing requests match your criteria.</span>
                            </div>
                        ) : (
                            tickets.map((ticket) => (
                                <div 
                                    key={ticket.id}
                                    onClick={() => navigate(`/user/tickets/details/${ticket.id}`)}
                                    className="group flex flex-col md:flex-row md:items-center justify-between border border-slate-200/80 rounded-2xl p-4 sm:p-5 hover:bg-slate-50/40 hover:border-slate-300/80 hover:shadow-sm transition-all cursor-pointer bg-white gap-4"
                                >
                                    {/* Left Core Context Info block */}
                                    <div className="flex items-start gap-3.5 min-w-0 flex-1">
                                        {/* Status Indicator Dot wrapper layout */}
                                        <div className="relative pt-1 flex-shrink-0">
                                            <div className={`w-3 h-3 rounded-full ${getIndicatorColor(ticket.status)} ring-4 ring-white shadow-sm`} />
                                        </div>
                                        
                                        <div className="min-w-0 flex-1">
                                            <h3 className="text-base font-bold text-slate-900 group-hover:text-blue-600 transition-colors tracking-tight truncate pr-2">
                                                {ticket.subject}
                                            </h3>
                                            <p className="text-xs sm:text-sm text-slate-400 mt-0.5 line-clamp-2 max-w-2xl font-medium">
                                                {ticket.description || "No additional parameters provided inside this channel payload..."}
                                            </p>
                                        </div>
                                    </div>

                                    {/* Right Status Actions, Metrics Metadata Indicators */}
                                    <div className="flex items-center justify-between md:justify-end gap-4 border-t border-slate-50 pt-3 md:pt-0 md:border-0 flex-shrink-0">
                                        
                                        {/* Dynamic Review Action Button */}
                                        {ticket.status === 'RESOLVED' && (
                                            <button 
                                                onClick={(e) => {
                                                    e.stopPropagation(); // Avoid triggering parent block navigation handlers
                                                    navigate(`/user/tickets/details/${ticket.id}`); 
                                                }}
                                                className="bg-emerald-500 hover:bg-emerald-600 text-white text-[10px] font-extrabold px-3 py-2 rounded-lg uppercase tracking-wider transition-colors shadow-sm active:scale-95"
                                            >
                                                Feedback
                                            </button>
                                        )}
                                        
                                        <div className="flex items-center gap-3 ml-auto md:ml-0">
                                            {getStatusBadge(ticket.status)}
                                            
                                            <div className="flex items-center gap-1.5 text-xs text-slate-400 font-semibold bg-slate-50 px-2 py-1 rounded-md border border-slate-100 font-mono">
                                                <Calendar size={12} className="text-slate-400" />
                                                <span>{new Date(ticket.created_at).toLocaleDateString('en-GB')}</span>
                                            </div>
                                            
                                            <ChevronRight className="text-slate-300 group-hover:text-slate-500 transition-colors hidden sm:block" size={16} />
                                        </div>
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                </div>

                {/* Outer Layout Pagination Section */}
                {pagination?.total_pages > 1 && (
                    <div className="flex justify-end pt-1">
                        <Pagination
                            currentPage={pagination.current_page || 1}
                            totalPages={pagination.total_pages || 1}
                            hasNext={pagination.has_next}
                            hasPrevious={pagination.has_previous}
                            onPageChange={handlePageChange}
                        />
                    </div>
                )}
            </div>
        </DashboardLayout>
    )
}

export default TicketsList