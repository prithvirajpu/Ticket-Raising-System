import { useEffect, useState } from "react"
import { getAgentFakeTickets } from "../../../services/ticketService"
import DashboardLayout from "../../../layouts/DashboardLayout"
import { useNavigate } from "react-router-dom"
import Lottie from 'lottie-react';
import emptyQueueAnimation from "../../../assets/empty-queue.json";

const AgentFakeTicketsPage = () => {
  const [tickets, setTickets] = useState([])
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  useEffect(() => {
    const fetchTickets = async () => {
      try {
        const res = await getAgentFakeTickets()
        setTickets(res.message || [])
      } catch (error) {
        console.error("Fetch error:", error)
      } finally {
        setLoading(false)
      }
    }

    fetchTickets()
  }, [])

  return (
    <DashboardLayout title="Your Practice Tickets" subtitle="Agent Training Intelligence">
      <div className="bg-white min-h-screen">
        <div className="max-w-4xl mx-auto border border-gray-200 rounded-[2rem] p-10 shadow-sm min-h-[600px] flex flex-col">

          {/* Ticket List */}
          <div className="space-y-6 flex-1">
            {loading ? (
              <div className="flex justify-center items-center h-40 text-gray-400 italic">
                Loading tickets...
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
              tickets.map((t) => (
                <div
                  key={t.id}
                  onClick={() => navigate(`/agent/fake-tickets/${t.ticket.id}`)}
                  className="group relative p-6 border border-gray-300 rounded-[1.5rem] flex flex-col sm:flex-row sm:justify-between sm:items-center gap-4 cursor-pointer hover:border-[#3897f0] hover:shadow-md transition-all bg-white"
                >
                  <div className="flex items-start gap-4">
                    {/* Status Dot indicator */}
                    <div className="mt-2 w-3.5 h-3.5 rounded-full bg-yellow-400 shadow-sm shrink-0" />
                    
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <h3 className="text-lg font-bold text-gray-900 group-hover:text-[#3897f0] transition-colors">
                          {t.ticket.subject}
                        </h3>
                        {t.ticket.ticket_code && (
                          <span className="text-xs text-gray-400 font-mono">#{t.ticket.ticket_code}</span>
                        )}
                      </div>
                      
                      <p className="text-gray-400 text-sm max-w-md line-clamp-1 leading-relaxed mt-1">
                        {t.ticket.description || "No description provided."}
                      </p>

                      {/* Badges & Meta Metadata */}
                      <div className="flex flex-wrap gap-2 mt-3 text-xs">
                        <span className="bg-blue-100 text-blue-600 px-2 py-0.5 rounded font-medium">
                          {t.ticket.priority}
                        </span>
                        <span className="bg-gray-100 text-gray-600 px-2 py-0.5 rounded font-medium">
                          {t.ticket.issue_type}
                        </span>
                        {/* {t.sla && (
                          <span className="text-gray-500 flex items-center ml-1">
                            SLA: {t.sla.sla_status} | Due: {t.sla.sla_deadline}
                          </span>
                        )} */}
                      </div>
                    </div>
                  </div>

                  {/* Status Side Badge */}
                  <span className="self-start sm:self-auto bg-green-50 text-green-700 px-6 py-1.5 rounded-xl text-sm font-bold border border-green-200 uppercase tracking-wide">
                    {t.training_status || "Practice"}
                  </span>
                </div>
              ))
            )}
          </div>

        </div>
      </div>
    </DashboardLayout>
  )
}

export default AgentFakeTicketsPage