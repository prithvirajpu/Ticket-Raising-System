import { useEffect, useState } from "react"
import DashboardLayout from "../../../layouts/DashboardLayout"
import { getClientsWithDocs } from "../../../services/ticketService"
import { useNavigate } from "react-router-dom"
import { ChevronRight } from "lucide-react"

const ClientListPage = () => {
    const [clients, setClients] = useState([])
    const [loading, setLoading] = useState(false)
    const navigate = useNavigate()

    useEffect(() => {
        fetchClients();
    }, [])

    const fetchClients = async () => {
        setLoading(true);
        try {
            const res = await getClientsWithDocs();
            setClients(res.message || []);
        } catch (error) {
            console.log(error)
        } finally {
            setLoading(false)
        }
    }

    return (
        <DashboardLayout
            title="Knowledge Base"
            subtitle="Training documents and resources"
        >
            <div className="max-w-4xl mx-auto mt-10 px-4">
                {/* Unified Square Container */}
                <div className="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
                    
                    {/* Header Section */}
                    <div className="p-6 border-b border-gray-100 bg-gray-50/50 flex justify-between items-center">
                        <h2 className="text-xl font-bold text-gray-800">Clients Documents</h2>
                    </div>

                    {/* List Section with Dividers */}
                    <div className="divide-y divide-gray-100">
                        {clients.length === 0 && !loading ? (
                            <div className="p-20 text-center text-gray-500">
                                No client documents found.
                            </div>
                        ) : (
                            clients.map((client) => (
                                <div
                                    key={client.client_id}
                                    className="group flex items-center justify-between p-5 hover:bg-blue-50/30 transition-all duration-200 cursor-pointer"
                                    onClick={() => navigate(`/manager/client-docs/${client.client_id}`)}
                                >
                                    <div className="flex items-center gap-4">
                                        {/* Visual indicator / Avatar */}
                                        <div className="w-12 h-12 rounded-xl bg-blue-50 flex items-center justify-center text-blue-600 font-bold group-hover:bg-blue-600 group-hover:text-white transition-all duration-300 shadow-sm">
                                            {client.client_name.charAt(0).toUpperCase()}
                                        </div>

                                        <div>
                                            <span className="block font-semibold text-gray-700 group-hover:text-blue-700 transition-colors">
                                                {client.client_name}
                                            </span>
                                            <span className="text-xs text-gray-400">
                                                Click to view knowledge base
                                            </span>
                                        </div>
                                    </div>

                                    {/* Action Arrow */}
                                    <div className="flex items-center gap-2 text-gray-300 group-hover:text-blue-500 transition-all">
                                        <span className="text-xs font-medium opacity-0 group-hover:opacity-100 transition-opacity">View details</span>
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

export default ClientListPage