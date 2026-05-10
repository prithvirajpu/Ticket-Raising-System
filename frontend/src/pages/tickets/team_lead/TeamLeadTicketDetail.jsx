import { useEffect, useState } from "react";
import { escalateTicket, getUserTicketDetail, resolveTicket } from "../../../services/ticketService";
import Loader from "../../../components/modals/Loader";
import { useParams, useNavigate } from "react-router-dom";
import { ArrowLeft, Send, Phone, User, Clock, AlertCircle, Calendar } from "lucide-react"; // Using Lucide for icons
import DashboardLayout from "../../../layouts/DashboardLayout";
import ConfirmModal from "../../../components/modals/ConfirmModal";
import { getSlaTimer } from "../../../utils/slaTImer";
import { notifySuccess } from "../../../utils/notify";

const TeamLeadTicketDetail = () => {
    const [ticket, setTicket] = useState(null);
  const [loading, setLoading] = useState(true);
  const [resolveModalOpen,setResolveModalOpen]=useState(false);
  const [resolveLoading,setResolveLoading]=useState(false);
  const [timeLeft,setTimeLeft]=useState(null)

  const [escalateLoading,setEscalateLoading]=useState(false)
  const [escalateModalOpen, setEscalateModalOpen] = useState(false);


  const { id } = useParams();
  const navigate = useNavigate();

  useEffect(()=>{
    if (!ticket?.sla?.sla_deadline) return;
    console.log(ticket?.sla?.sla_deadline)
    const interval=setInterval(()=>{
        setTimeLeft(getSlaTimer(ticket.sla.sla_deadline));
    },1000)
    return ()=>clearInterval(interval);
  },[ticket?.sla?.sla_deadline])

  useEffect(() => {
    fetchTicket();
    setEscalateModalOpen(false);
    setResolveModalOpen(false);
  }, [id]);

  const fetchTicket = async () => {
    try {
      const data = await getUserTicketDetail(id);
      setTicket(data.message);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleEscalateConfirm = async()=>{
    setEscalateLoading(true);
    try {
      await escalateTicket(id);
      await fetchTicket();
      setEscalateModalOpen(false);
      navigate('/team-lead/assigned-tickets')
      notifySuccess('Ticket escalated to the Manager')
      
    } catch (error) {
      console.log(error);
    } finally {
      setEscalateLoading(false);
    }
  }
  const handleCancelEscalate = () => {
      setEscalateModalOpen(false);
    };

  const handleConfirmResolve  = async () => {
    setResolveLoading(true);
    try {
      await resolveTicket(id);
      await fetchTicket();
      notifySuccess('Ticket marked as Resolved')
      setResolveModalOpen(false)
    } catch (error) {
      console.error(error);
    }finally{
        setResolveLoading(false)
    }
  };

    const handleCancelResolve = () => {
    setResolveModalOpen(false);
  };

  if (loading) return <Loader />;
  if (!ticket) return <p className="p-6">Ticket not found</p>;

  return (
     <>
    <DashboardLayout>
    <div className="min-h-screen bg-white ">
      {/* Top Navigation */}
      <div className="flex items-center justify-between mb-8 max-w-6xl mx-auto">
        <div className="flex items-center gap-4">
          <button onClick={() => navigate(-1)} className="hover:bg-gray-100 p-2 rounded-full transition-colors">
            <ArrowLeft size={20} />
          </button>
          <h1 className="text-xl font-bold">Ticket #{ticket.ticket_code || id}</h1>
        </div>
        
        {ticket.status !== "RESOLVED" && (
          <button
            disabled={resolveLoading}
            onClick={()=> setResolveModalOpen(true) }
            className="bg-[#1DB954] hover:bg-green-600 text-white px-6 py-2 rounded-lg font-medium transition-colors"
          >
            Mark as Resolved
          </button>
        )}
      </div>

      <div className="max-w-6xl mx-auto grid grid-cols-1 md:grid-cols-12 gap-8">
        
        {/* Left Side: Ticket Details Card */}
        <div className="md:col-span-4 lg:col-span-3">
          <div className="border border-gray-300 rounded-3xl p-6 space-y-6">
            <h2 className="text-lg font-semibold border-b pb-2">Ticket Details</h2>
            
            {/* Status Section */}
            <div>
              <div className="flex items-center gap-2 text-gray-400 text-sm mb-1">
                <div className="w-4 h-4 rounded-full border border-orange-300 flex items-center justify-center">
                  <div className="w-2 h-2 bg-orange-300 rounded-full" />
                </div>
                Status
              </div>
              <div className="flex items-center gap-2 font-medium">
                <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                {ticket.status || "In progress"}
              </div>
            </div>
            

            {/* Priority Section */}
            <div className="pt-4 border-t">
              <div className="flex items-center gap-2 text-gray-400 text-sm mb-2">
                <AlertCircle size={16} />
                Priority
              </div>
              <span className="bg-pink-500 text-white px-4 py-1 rounded-full text-xs font-bold uppercase tracking-wide">
                {ticket.priority || "high"}
              </span>
            </div>

            {/* Customer Section */}
            <div className="pt-4 border-t">
              <div className="flex items-center gap-2 text-gray-400 text-sm mb-2">
                <User size={16} />
                Customer
              </div>
              <p className="font-medium">{ticket.customer_name || "User_here"}</p>
            </div>

            {/* Created Section */}
            <div className="pt-4 border-t">
              <div className="flex items-center gap-2 text-gray-400 text-sm mb-2">
                <Clock size={16} className="rotate-180" />
                Created
              </div>
              <p className="text-sm font-medium">
                {ticket.created_at ? new Date(ticket.created_at).toLocaleString() : "1/3/2026, 10:30:00 AM"}
              </p>
            </div>
          </div>
        </div>

        {/* Right Side: Conversation Box */}
        <div className="md:col-span-8 lg:col-span-9">
          <div className="border border-gray-300 rounded-3xl h-[600px] flex flex-col overflow-hidden">
            {/* Conversation Header */}
            <div className="p-6 flex justify-between items-start">
              <div>
                <h2 className="text-xl font-semibold">Conversation</h2>
                <p className="text-gray-400 text-sm italic">Chat with the user</p>
              </div>
              <div className={`px-4 py-2 rounded-lg text-lg font-mono font-bold border-2 shadow-sm min-w-[100px] text-center ${
                    timeLeft?.status === "breached"
                        ? "bg-red-50 text-red-600 border-red-300 animate-pulse"
                        : "bg-emerald-50 text-emerald-700 border-emerald-300"
                    }`}>
                    {timeLeft?.text || "No SLA"}
                    </div>

            </div>

            {/* Chat Area */}
            <div className="flex-1 overflow-y-auto p-6 flex flex-col gap-6">
              <div className="self-end max-w-[80%]">
                <div className="flex items-center justify-end gap-2 mb-2">
                  <span className="text-xs text-gray-500 font-bold">User_here</span>
                  <span className="text-[10px] text-gray-400 uppercase tracking-tighter">10:30:00 AM</span>
                </div>
                <div className="flex items-start gap-3">
                  <div className="bg-[#005AB5] text-white p-4 rounded-2xl rounded-tr-none shadow-sm text-sm">
                    {ticket.description || "I am unable to login to my account. Getting an error message."}
                  </div>
                  <div className="w-8 h-8 bg-green-500 rounded-full flex items-center justify-center text-white text-xs font-bold">
                    U
                  </div>
                </div>
              </div>
            </div>

            {/* Message Input Area */}
            <div className="p-6 border-t border-gray-100">
              <div className="flex justify-end gap-2 mb-4">
                {ticket.status !='RESOLVED' && (
                  <button onClick={()=>setEscalateModalOpen(true)} 
                 className="bg-red-600 text-white text-xs px-4 py-1 rounded-lg font-bold">Escalate</button>
                )}
                
                <button className="bg-blue-600 text-white text-xs px-4 py-1 rounded-lg font-bold">Verify</button>
              </div>
              
              <div className="relative flex items-center">
                <input 
                  type="text" 
                  placeholder="Type your message..." 
                  className="w-full bg-gray-100 rounded-2xl py-4 pl-6 pr-24 focus:outline-none focus:ring-1 focus:ring-gray-300"
                />
                <div className="absolute right-4 flex items-center gap-4">
                  <button className="text-green-500 hover:scale-110 transition-transform">
                    <Phone size={24} fill="currentColor" stroke="none" className="rotate-[100deg]" />
                  </button>
                  <button className="text-black hover:translate-x-1 transition-transform">
                    <Send size={24} />
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>
    </DashboardLayout>
    <ConfirmModal
        isOpen={resolveModalOpen}
        title="Resolve Ticket"
        message={`Are you sure you want to mark ticket #${ticket.ticket_code || id} as resolved? This action cannot be undone.`}
        confirmText="Yes, Resolve"
        cancelText="Cancel"
        loadingText="Resolving..."
        loading={resolveLoading}
        onConfirm={handleConfirmResolve}
        onCancel={handleCancelResolve}
      />
      <ConfirmModal
        isOpen={escalateModalOpen}
        title="Escalate Ticket"
        message={`Are you sure you want to escalate ticket #${ticket.ticket_code || id}? This will notify your Manager.`}
        confirmText="Yes, Escalate"
        cancelText="Cancel"
        loadingText="Escalating..."
        loading={escalateLoading}
        onConfirm={handleEscalateConfirm}
        onCancel={handleCancelEscalate}
      />
    </>
  )
}

export default TeamLeadTicketDetail