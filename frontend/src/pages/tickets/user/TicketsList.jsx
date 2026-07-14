import React, { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { getTickets } from '../../../services/ticketService'
import DashboardLayout from '../../../layouts/DashboardLayout'
import { Plus, Search, ChevronDown, ChevronRight, ArrowUpDown, Calendar, Loader2, ClipboardList } from 'lucide-react'
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
            'OPEN': 'text-amber-700 bg-amber-50 border-amber-100',
            'IN_PROGRESS': 'text-blue-700 bg-blue-50 border-blue-100',
            'ESCALATED': 'text-red-700 bg-red-50 border-red-100',
            'RESOLVED': 'text-emerald-700 bg-emerald-50 border-emerald-100',
            'CLOSED': 'text-slate-600 bg-slate-100 border-slate-200',
        };
        const styles = statusMap[status.toUpperCase()] || 'text-gray-600 bg-gray-50 border-gray-200';
        
        return (
            <span className={`px-2.5 py-1 rounded-lg border text-xs font-semibold tracking-tight whitespace-nowrap ${styles}`}>
                {status.charAt(0).toUpperCase() + status.slice(1).toLowerCase()}
            </span>
        )
    }

    const getIndicatorColor = (status) => {
        if (status === "OPEN") return "bg-amber-400";
        if (status === "IN_PROGRESS") return "bg-blue-500";
        if (status === "ESCALATED") return "bg-red-500";
        if (status === "RESOLVED") return "bg-emerald-500";
        if (status === "CLOSED") return "bg-slate-400";
        return "bg-gray-300"; 
    }

    return (
        <DashboardLayout title="Support Operations">
            <div className="min-h-screen bg-slate-50/50 py-8 px-4 sm:px-6 lg:px-8">
                <div className="max-w-5xl mx-auto flex flex-col min-h-[700px]">
                    
                    {/* Header & Controls Area */}
                    <div className="flex flex-col md:flex-row md:items-center justify-between pb-6 mb-6 border-b border-slate-200/60 gap-4">
                        <div>
                            <h2 className="text-2xl font-bold tracking-tight text-slate-900">Active Tickets</h2>
                            <p className="text-sm text-slate-500 mt-1">Manage Tickets.</p>
                        </div>
                        
                        <button
                            onClick={() => navigate("/user/create-ticket")}
                            className="flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-5 py-2.5 rounded-xl transition-all active:scale-[0.98] text-xs sm:text-sm font-semibold shadow-sm shadow-blue-600/10 w-full sm:w-auto self-end md:self-auto"
                        >
                            <Plus size={16} />
                            Raise New Ticket
                        </button>
                    </div>

                    {/* Filter / Search Row */}
                    <div className="flex flex-col sm:flex-row items-center gap-3 w-full mb-6">
                        {/* Search Box */}
                        <div className="relative w-full sm:flex-1">
                            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                            <input 
                                value={searchTerm}
                                onChange={handleSearchChange}
                                type="text" 
                                placeholder="Search ticketing manifests..." 
                                className="w-full pl-10 pr-4 py-2 border border-slate-200 rounded-xl text-sm font-medium text-slate-800 placeholder-slate-400 bg-white shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all duration-150"
                            />
                        </div>

                        {/* Sorting Dropdown */}
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

                    {/* Ticket Cards Viewport */}
                    <div className="flex-1 space-y-4">
                        {loading ? (
                            <div className="flex flex-col justify-center items-center h-64 bg-white rounded-2xl border border-slate-100 shadow-sm text-slate-400 gap-3">
                                <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
                                <span className="text-sm font-medium">Syncing records layout streams...</span>
                            </div>
                        ) : tickets.length === 0 ? (
                            <div className="flex flex-col justify-center items-center h-64 bg-white rounded-2xl border border-slate-100 shadow-sm text-center p-6">
                                <div className="p-3 bg-slate-50 rounded-full text-slate-400 mb-3">
                                    <ClipboardList className="w-6 h-6" />
                                </div>
                                <h3 className="text-sm font-semibold text-slate-900">No manifests found</h3>
                                <p className="text-xs text-slate-500 mt-1 max-w-xs">
                                    No ticketing requests match your filter parameters. Try another keyword.
                                </p>
                            </div>
                        ) : (
                            tickets.map((ticket) => (
                                <div 
                                    key={ticket.id}
                                    onClick={() => navigate(`/user/tickets/details/${ticket.id}`)}
                                    className="group relative p-5 bg-white border border-slate-200/80 rounded-2xl flex flex-col md:flex-row md:items-center justify-between gap-4 cursor-pointer hover:border-blue-500 hover:shadow-md hover:shadow-blue-500/[0.02] transition-all duration-200"
                                >
                                    {/* Left Content Context */}
                                    <div className="flex items-start gap-4 min-w-0 flex-1">
                                        <div className="mt-1.5 flex-shrink-0 relative flex items-center justify-center">
                                            {(ticket.status === "OPEN" || ticket.status === "IN_PROGRESS") && (
                                                <span className={`absolute inline-flex h-2 w-2 rounded-full ${getIndicatorColor(ticket.status)} opacity-45 animate-ping`} />
                                            )}
                                            <span className={`relative inline-flex rounded-full h-2 w-2 ${getIndicatorColor(ticket.status)}`} />
                                        </div>
                                        
                                        <div className="min-w-0 flex-1">
                                            <h3 className="text-sm sm:text-base font-bold text-slate-900 group-hover:text-blue-600 transition-colors truncate">
                                                {ticket.subject}
                                            </h3>
                                            <p className="text-slate-500 text-xs sm:text-sm line-clamp-2 leading-relaxed mt-1 max-w-2xl">
                                                {ticket.description || "No additional parameters provided inside this channel payload..."}
                                            </p>
                                        </div>
                                    </div>

                                    {/* Right Status Actions, Metrics Metadata */}
                                    <div className="flex items-center justify-between md:justify-end gap-3 border-t md:border-t-0 pt-3 md:pt-0 border-slate-100 flex-shrink-0">
                                        {ticket.status === 'RESOLVED' && (
                                            <button 
                                                onClick={(e) => {
                                                    e.stopPropagation();
                                                    navigate(`/user/tickets/details/${ticket.id}`); 
                                                }}
                                                className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-700 text-white text-[11px] font-bold rounded-lg uppercase tracking-wider shadow-sm transition-colors active:scale-95"
                                            >
                                                Feedback
                                            </button>
                                        )}
                                        
                                        <div className="flex items-center gap-3.5 ml-auto md:ml-0">
                                            {getStatusBadge(ticket.status)}
                                            
                                            <div className="inline-flex items-center gap-1.5 text-xs text-slate-500 font-semibold bg-slate-50 border border-slate-200/60 px-2.5 py-1 rounded-lg font-mono">
                                                <Calendar size={13} className="text-slate-400" />
                                                <span>{new Date(ticket.created_at).toLocaleDateString('en-GB')}</span>
                                            </div>
                                            
                                            <div className="p-1 rounded-lg text-slate-400 group-hover:text-blue-500 group-hover:bg-blue-50 transition-all duration-150 hidden sm:block">
                                                <ChevronRight className="w-4 h-4" />
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            ))
                        )}
                    </div>

                    {/* Pagination Footer Section */}
                    {!loading && pagination?.total_pages > 1 && (
                        <div className="mt-8 border-t border-slate-200/60 pt-6">
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
            </div>
        </DashboardLayout>
    )
}

export default TicketsList;