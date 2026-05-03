import { useEffect, useState } from "react"
import { getAgentFakeTickets } from "../../../services/ticketService"
import Loader from "../../../components/modals/Loader"
import DashboardLayout from "../../../layouts/DashboardLayout"
import { useNavigate } from "react-router-dom"


const AgentFakeTicketsPage  = () => {
    const [tickets,setTickets]=useState([])
    const [loading,setLoading]=useState(true)
    const navigate=useNavigate()

    useEffect(()=>{
        fetchTickets();
    },[])
    const fetchTickets=async()=>{
        try {
            const res= await getAgentFakeTickets();
            setTickets(res.message || [])
        } catch (error) {
            console.log(error)
        } finally{
            setLoading(false)
        }
    }
    if (loading) return <Loader />

  return (
    <DashboardLayout title="Practice Tickets" subtitle="AI Training Mode">
      <div className="max-w-5xl mx-auto p-6">
        <h2 className="text-2xl font-bold mb-6">Your Practice Tickets</h2>

        {tickets.length === 0 ? (
  <div className="flex flex-col items-center justify-center h-[300px] text-center">
    <p className="text-lg font-semibold text-gray-700">No Tickets Found</p>
    <p className="text-sm text-gray-500 mt-2">
      AI practice tickets will appear here once generated.
    </p>
  </div>
) : (
          <div className="space-y-4">
            {tickets.map((t) => (
              <div
                key={t.id}
                onClick={()=>navigate(`/agent/fake-tickets/${t.id}`)}
                className="bg-white border rounded-xl p-5 shadow-sm"
              >
                <h3 className="text-lg font-semibold">{t.subject}</h3>

                <p className="text-sm text-gray-600 mt-2">
                  {t.description}
                </p>

                <div className="flex gap-3 mt-3 text-xs">
                  <span className="bg-blue-100 text-blue-600 px-2 py-1 rounded">
                    {t.priority}
                  </span>
                  <span className="bg-gray-100 px-2 py-1 rounded">
                    {t.issue_type}
                  </span>
                  <span className="bg-green-100 text-green-600 px-2 py-1 rounded">
                    {t.status}
                  </span>
                </div>

                {/* SLA Info */}
                {t.sla && (
                  <div className="mt-3 text-xs text-gray-500">
                    SLA: {t.sla.sla_status} | Deadline:{" "}
                    {t.sla.sla_deadline}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </DashboardLayout>
  )
}

export default AgentFakeTicketsPage 
