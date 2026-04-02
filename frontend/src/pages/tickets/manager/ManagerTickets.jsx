import React, { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { getManagerTickets } from '../../../services/ticketService'
import { Fingerprint, ChevronRight } from 'lucide-react'
import Loader from '../../../components/modals/Loader'
import DashboardLayout from '../../../layouts/DashboardLayout'

const ManagerTickets = () => {
    const [tickets, setTickets] = useState([])
    const [loading, setLoading] = useState(false)
    const navigate = useNavigate()

    useEffect(() => {
        fetchTickets();
    }, [])

    const fetchTickets = async () => {
        setLoading(true)
        try {
            const res = await getManagerTickets();
            setTickets(res.message || [])
        } catch (error) {
            console.log(error)
        } finally {
            setLoading(false)
        }
    }

    if (loading) return <Loader />

    return (
        <DashboardLayout 
            title="Escalated Tickets" 
            subtitle="Manage and resolve high-priority issues"
        >
            {/* Container for the "Square" layout */}
            <div className="max-w-4xl mx-auto mt-8 px-4">
                <div className="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
                    
                    {/* Header section inside the square */}
                    <div className="p-6 border-b border-gray-100 flex justify-between items-center bg-gray-50/50">
                        <h2 className="text-xl font-bold text-gray-800">Ticket Queue</h2>
                    </div>

                    {/* List section */}
                    <div className="divide-y divide-gray-100">
                        {tickets.length === 0 ? (
                            <div className="text-center py-20 text-gray-500">
                                <p>No tickets available at the moment.</p>
                            </div>
                        ) : (
                            tickets.map((t) => (
                                <div
                                    key={t.id}
                                    onClick={() => navigate(`/manager/tickets/${t.id}`)}
                                    className="group flex items-center justify-between p-5 hover:bg-blue-50/30 transition-all duration-200 cursor-pointer"
                                >
                                    <div className="flex items-center gap-4">
                                        {/* Icon Box */}
                                        <div className="w-12 h-12 rounded-xl bg-blue-50 flex items-center justify-center text-blue-600 group-hover:bg-blue-600 group-hover:text-white transition-all duration-300 shadow-sm">
                                            <Fingerprint size={24} />
                                        </div>

                                        <div>
                                            <span className="block font-semibold text-gray-800 group-hover:text-blue-700 transition-colors">
                                                {t.subject}
                                            </span>
                                            <div className="flex items-center gap-3 mt-1">
                                                <span className="text-xs font-mono font-medium text-gray-400">
                                                    #{t.ticket_code}
                                                </span>
                                                <span className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded ${
                                                    t.priority === 'high' 
                                                    ? 'bg-red-100 text-red-600' 
                                                    : 'bg-orange-100 text-orange-600'
                                                }`}>
                                                    {t.priority}
                                                </span>
                                            </div>
                                        </div>
                                    </div>

                                    {/* Action Arrow */}
                                    <div className="flex items-center gap-2 text-gray-300 group-hover:text-blue-500 transition-all">
                                        <span className="text-xs font-medium opacity-0 group-hover:opacity-100 transition-opacity">View Details</span>
                                        <ChevronRight size={20} className="group-hover:translate-x-1 transition-transform" />
                                    </div>
                                </div>
                            ))
                        )}
                    </div>

                   
                </div>
            </div>
        </DashboardLayout>
    )
}

export default ManagerTickets