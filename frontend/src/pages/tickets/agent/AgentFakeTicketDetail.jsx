import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import Loader from "../../../components/modals/Loader";
import DashboardLayout from "../../../layouts/DashboardLayout";
import { ArrowLeft, User, Clock, AlertCircle } from "lucide-react";
import { getFakeTicketDetail } from "../../../services/ticketService";
import { getSlaTimer } from "../../../utils/slaTImer";

const AgentFakeTicketDetail = () => {
  const { id } = useParams();
  const navigate = useNavigate();

  const [ticket, setTicket] = useState(null);
  const [loading, setLoading] = useState(true);
  const [timeLeft, setTimeLeft] = useState(null);

  useEffect(() => {
    fetchTicket();
  }, [id]);

  useEffect(() => {
    if (!ticket?.sla?.sla_deadline) return;

    const interval = setInterval(() => {
      setTimeLeft(getSlaTimer(ticket.sla.sla_deadline));
    }, 1000);

    return () => clearInterval(interval);
  }, [ticket?.sla?.sla_deadline]);

  const fetchTicket = async () => {
    try {
      const res = await getFakeTicketDetail(id);
      setTicket(res.message);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <Loader />;

  return (
    <DashboardLayout title="Practice Ticket" subtitle="AI Training Mode">
      <div className="max-w-6xl mx-auto">
        
        {/* Header */}
        <div className="flex items-center gap-4 mb-6">
          <button onClick={() => navigate(-1)} className="p-2 hover:bg-gray-100 rounded-full">
            <ArrowLeft size={20} />
          </button>
          <h1 className="text-xl font-bold">
            Ticket #{ticket.ticket_code}
          </h1>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-12 gap-8">

          {/* LEFT PANEL */}
          <div className="md:col-span-4">
            <div className="border rounded-2xl p-6 space-y-6">

              <h2 className="font-semibold border-b pb-2">Details</h2>

              <div>
                <p className="text-sm text-gray-400">Status</p>
                <p className="font-medium">{ticket.status}</p>
              </div>

              <div>
                <p className="text-sm text-gray-400 flex items-center gap-2">
                  <AlertCircle size={14} /> Priority
                </p>
                <span className="bg-blue-100 px-3 py-1 rounded text-xs">
                  {ticket.priority}
                </span>
              </div>

              <div>
                <p className="text-sm text-gray-400 flex items-center gap-2">
                  <User size={14} /> Customer
                </p>
                <p>User_here</p>
              </div>

              <div>
                <p className="text-sm text-gray-400 flex items-center gap-2">
                  <Clock size={14} /> Created
                </p>
                <p>{new Date(ticket.created_at).toLocaleString()}</p>
              </div>

            </div>
          </div>

          {/* RIGHT PANEL */}
          <div className="md:col-span-8">
            <div className="border rounded-2xl p-6 h-full flex flex-col">

              <div className="flex justify-between mb-4">
                <h2 className="text-lg font-semibold">Conversation</h2>

                {timeLeft && (
                  <div className="text-sm font-mono bg-gray-100 px-3 py-1 rounded">
                    {timeLeft.text}
                  </div>
                )}
              </div>

              <div className="flex-1">
                <div className="bg-blue-600 text-white p-4 rounded-xl max-w-lg">
                  {ticket.description}
                </div>
              </div>

              {/* Practice Mode Note */}
              <div className="mt-6 text-xs text-blue-600 bg-blue-50 p-3 rounded">
                Practice Mode: This is an AI-generated ticket. No real escalation required.
              </div>

            </div>
          </div>

        </div>
      </div>
    </DashboardLayout>
  );
};

export default AgentFakeTicketDetail;