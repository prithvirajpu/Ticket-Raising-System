import { useParams, useNavigate } from "react-router-dom";
import DashboardLayout from "../../../layouts/DashboardLayout";
import { useEffect, useRef, useState } from "react";
import {
  getTicketTimeline,
  reopenTicket,
  closeTicket,
  getUserTicketDetail,
  sendMessage,
  submitReview,
} from "../../../services/ticketService";
import {
  ArrowLeft,
  Tag,
  Info,
  User,
  Clock,
  RefreshCcw,
  Send,
  Check,
  CheckCheck,
  Paperclip,
} from "lucide-react";
import Loader from "../../../components/modals/Loader";
import ConfirmModal from "../../../components/modals/ConfirmModal";
import ReviewModal from "../../../components/modals/ReviewModal";
import useChat from "../../../hooks/useChat";
import { notifySuccess } from "../../../utils/notify";
import IncomingCallModal from "../../../components/modals/IncomingCallModal";
import OngoingCallModal from "../../../components/modals/OngoingCallModal";
import { useCall } from "../../../auth/CallContext";

const TicketDetail = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [ticket, setTicket] = useState(null);
  const [loading, setLoading] = useState(true);

  const [showCloseModal, setShowCloseModal] = useState(false);
  const [closeLoading, setCloseLoading] = useState(false);

  const [showReviewModal, setShowReviewModal] = useState(false);
  const [reviewLoading, setReviewLoading] = useState(false);

  const [reopenModalOpen, setReopenModalOpen] = useState(false);
  const [reopenLoading, setReopenLoading] = useState(false);

  const [timeline, setTimeline] = useState([]);
  const localStreamRef = useRef(null);

const {
    messages,
    newMessage,
    setNewMessage,
    handleSendMessage,
    messageEndRef,
    handleKeyDown
} = useChat(id, ticket?.current_user_id);

const {
    incomingCall,
    setIncomingCall,
    handleAccept,
    handleReject,
    handleEndCall,
    callState,
    remoteAudioRef
} = useCall();

  const currentUserId = Number(ticket?.current_user_id);

console.log("Modal open?", !!incomingCall);

useEffect(() => {
  console.log("TicketDetail incomingCall:", incomingCall);
}, [incomingCall]);

  useEffect(() => {
    console.log("FULL TICKET:", ticket);
  }, [ticket]);
  const handleConfirmReopen = async () => {
    setReopenLoading(true);
    try {
      await reopenTicket(id);
      const updated = await getUserTicketDetail(id);
      const timelineData = await getTicketTimeline(id);
      setTimeline(timelineData.message);
      setTicket(updated.message);
      setReopenModalOpen(false);
      notifySuccess("Ticket is successfully reopened");
    } catch (error) {
      console.log(error);
    } finally {
      setReopenLoading(false);
    }
  };

  useEffect(() => {
    const fetchTicket = async () => {
      try {
        setLoading(true);
        const data = await getUserTicketDetail(id);
        setTicket(data.message);
        const timelineData = await getTicketTimeline(id);
        setTimeline(timelineData.message);
      } catch (error) {
        console.log(error);
      } finally {
        setLoading(false);
      }
    };
    fetchTicket();
  }, [id]);

  const handleConfirmClose = async () => {
    setCloseLoading(true);
    try {
      const res = await closeTicket(id);
      console.log(res);
      const data = await getUserTicketDetail(id);
      setTicket(data.message);
    } catch (error) {
      console.log(error);
    } finally {
      setCloseLoading(false);
      setShowCloseModal(false);
      setShowReviewModal(true);
    }
  };

  const handleSubmitReview = async (data) => {
    setReviewLoading(true);
    try {
      await submitReview(id, data);
      setShowReviewModal(false);
      notifySuccess("Review sumbitted successfully");
      const updated = await getUserTicketDetail(id);
      setTicket(updated.message);
    } catch (error) {
      console.log(error);
    } finally {
      setReviewLoading(false);
    }
  };

  const formatTime = (t) => {
    if (!t) return "";

    const d = new Date(t);

    if (isNaN(d.getTime())) return "";

    return d.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  if (loading) return <Loader />;
  if (!ticket)
    return <div className="p-10 text-center font-sans">Ticket not found</div>;

  return (
    <DashboardLayout>
      <div className="max-w-7xl mx-auto font-sans">
        {/* Header Actions */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-4">
            <button
              onClick={() => navigate(-1)}
              className="text-gray-800 hover:text-black"
            >
              <ArrowLeft size={24} />
            </button>
            <h1 className="text-2xl font-bold text-gray-900">
              Ticket #{ticket.ticket_code || id.slice(0, 5)}
            </h1>
          </div>
          <div className="flex gap-3">
            {ticket.status === "RESOLVED" && (
              <button
                onClick={() => setReopenModalOpen(true)}
                className="bg-orange-500 hover:bg-orange-600 text-white px-6 py-2 rounded-lg font-medium transition-colors"
              >
                Reopen Ticket
              </button>
            )}

            {ticket.status === "RESOLVED" ? (
              <button
                onClick={() => setShowCloseModal(true)}
                className="px-4 py-2 bg-red-600 text-white text-sm font-bold rounded-lg hover:bg-red-700 transition-colors"
              >
                Close Ticket
              </button>
            ) : null}
          </div>
        </div>

        {/* Combined Unified Grid: 3-column, 6-column, 3-column split */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* 1. LEFT SIDEBAR: Ticket Details (Takes up 3 spaces) */}
          <div className="lg:col-span-3 space-y-6">
            <div className="bg-white border border-gray-200 rounded-3xl p-6 shadow-sm">
              <h2 className="text-lg font-bold text-gray-800 mb-6">
                Ticket Details
              </h2>

              <div className="space-y-6">
                {/* Status */}
                <div className="flex flex-col gap-2">
                  <div className="flex items-center gap-2 text-gray-400 text-sm font-medium">
                    <Tag size={16} /> Status
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-2.5 h-2.5 rounded-full bg-yellow-400" />
                    <span className="text-sm font-bold text-gray-900 uppercase tracking-tight">
                      {ticket.status}
                    </span>
                  </div>
                </div>

                <div className="h-[1px] bg-gray-100" />

                {/* Priority */}
                <div className="flex flex-col gap-2">
                  <div className="flex items-center gap-2 text-gray-400 text-sm font-medium">
                    <Info size={16} /> Priority
                  </div>
                  <div>
                    <span className="px-4 py-1 bg-pink-100 text-pink-600 rounded-full text-[11px] font-bold uppercase tracking-wider">
                      {ticket.priority}
                    </span>
                  </div>
                </div>

                <div className="h-[1px] bg-gray-100" />

                {/* Customer */}
                <div className="flex flex-col gap-2">
                  <div className="flex items-center gap-2 text-gray-400 text-sm font-medium">
                    <User size={16} /> Customer
                  </div>
                  <span className="text-sm font-bold text-gray-900 break-words">
                    {ticket.customer?.name || "User_here"}
                  </span>
                </div>

                <div className="h-[1px] bg-gray-100" />

                {/* Created At */}
                <div className="flex flex-col gap-2">
                  <div className="flex items-center gap-2 text-gray-400 text-sm font-medium">
                    <Clock size={16} /> Created
                  </div>
                  <span className="text-sm font-bold text-gray-900">
                    {new Date(ticket.created_at).toLocaleString()}
                  </span>
                </div>

                <div className="h-[1px] bg-gray-100" />
              </div>
            </div>
          </div>

          {/* 2. MIDDLE PORTION: Chat Section (Takes up 6 spaces) */}
          <div className="lg:col-span-6 flex flex-col h-[700px] bg-white border border-gray-200 rounded-3xl shadow-sm overflow-hidden">
            {/* Conversation Header */}
            <div className="p-6 border-b border-gray-100 flex justify-between items-center">
              <div>
                <h2 className="text-xl font-bold text-gray-800">
                  Conversation
                </h2>
                <p className="text-sm text-gray-400">
                  Chat with the support team
                </p>
              </div>
            </div>

            {/* Messages */}
            <div className="flex-1 overflow-y-auto p-6 space-y-8 bg-gray-50/30">
              {messages.map((msg, index) => {
                const isMe = Number(msg.sender_id) === Number(currentUserId);

                return (
                  <div
                    key={index}
                    className={`flex flex-col ${
                      isMe ? "items-end" : "items-start"
                    } gap-2`}
                  >
                    <div className="flex items-center gap-2 text-[11px] text-gray-400 font-bold uppercase">
                      <span className="font-normal normal-case">
                        {formatTime(msg.created_at)}
                      </span>
                    </div>

                    <div
                      className={`flex gap-3 items-end max-w-[85%] ${
                        isMe ? "flex-row-reverse" : ""
                      }`}
                    >
                      {/* Bubble */}

                      <div
                        className={`relative p-4 rounded-2xl text-sm shadow-sm ${
                          isMe
                            ? "bg-[#3f644b] text-white rounded-tr-none"
                            : "bg-gray-200 text-gray-900 rounded-tl-none"
                        }`}
                      >
                        {msg.message}

{isMe && (
  <span className="absolute bottom-1 right-2">
    {msg.is_seen ? (
      <CheckCheck size={14} className="text-sky-300" />
    ) : (
      <CheckCheck size={14} className="text-gray-400" />
    )}
  </span>
)}
                      </div>
                      {/* Avatar */}
                      <div
                        className={`w-8 h-8 rounded-full flex items-center justify-center text-white text-xs font-bold shrink-0 ${
                          isMe ? "bg-emerald-500" : "bg-gray-500"
                        }`}
                      >
                        {msg.sender_name?.[0]}
                      </div>
                    </div>
                  </div>
                );
              })}

              <div ref={messageEndRef} />
            </div>

            {/* Input */}
            <div className="p-6 border-t border-gray-100 bg-white">
              <div className="relative flex items-center">
                <textarea
                  type="text"
                  value={newMessage}
                  onChange={(e) => setNewMessage(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="Type your message..."
                  className="w-full pl-6 pr-24 py-3 bg-gray-50 border border-gray-200 rounded-2xl focus:outline-none resize-none"
                />

                <div className="absolute right-3 flex items-center gap-2">
                  <button className="p-2 text-gray-400 hover:text-gray-600">
                    <Paperclip size={20} />
                  </button>

                  <button
                    onClick={handleSendMessage}
                    className="p-2 text-gray-900"
                  >
                    <Send size={20} />
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* 3. RIGHT SIDEBAR: Timeline (Takes up 3 spaces) */}
          <div className="lg:col-span-3 bg-white border border-gray-200 rounded-3xl p-6 h-[700px] overflow-y-auto shadow-sm">
            <h2 className="text-lg font-bold text-gray-800 mb-6">Timeline</h2>

            <div className="relative">
              {timeline.map((item, index) => (
                <div key={item.id} className="relative pl-8 pb-8">
                  {/* Vertical Line */}
                  {index !== timeline.length - 1 && (
                    <div className="absolute left-[11px] top-5 w-[2px] h-full bg-gray-200" />
                  )}

                  {/* Dot */}
                  <div className="absolute left-0 top-1 w-6 h-6 rounded-full bg-blue-600 border-4 border-white shadow" />

                  {/* Content */}
                  <div className="space-y-1">
                    <p className="text-sm font-bold text-gray-900">
                      {item.action}
                    </p>

                    <p className="text-xs text-gray-500">{item.description}</p>

                    <p className="text-[11px] text-gray-400">
                      {new Date(item.created_at).toLocaleString()}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
      <ConfirmModal
        isOpen={showCloseModal}
        title="Close Ticket?"
        message={`Are you sure you want to close ticket #${ticket.ticket_code || id.slice(0, 5)}? This action cannot be undone.`}
        confirmText="Close Ticket"
        cancelText="Cancel"
        loadingText="Closing..."
        loading={closeLoading}
        onConfirm={handleConfirmClose}
        onCancel={() => setShowCloseModal(false)}
      />
      <ReviewModal
        isOpen={showReviewModal}
        onClose={() => setShowReviewModal(false)}
        onSubmit={handleSubmitReview}
        loading={reviewLoading}
      />
      <ConfirmModal
        isOpen={reopenModalOpen}
        title="Reopen Ticket?"
        message={`Are you sure you want to reopen ticket #${ticket.ticket_code || id.slice(0, 5)}?`}
        confirmText="Reopen Ticket"
        cancelText="Cancel"
        loadingText="Reopening..."
        loading={reopenLoading}
        onConfirm={handleConfirmReopen}
        onCancel={() => setReopenModalOpen(false)}
      />
      {/* <IncomingCallModal
        isOpen={!!incomingCall}
        callerName={incomingCall?.caller_name}
        onAccept={() => {
          console.log("accepted");
          console.log("INCOMING CALL", incomingCall);
          handleAccept(incomingCall, currentUserId);
        }}
        onReject={() => {
          console.log("rejected");
          handleReject(incomingCall);
          setIncomingCall(null);
        }}
      />
      <OngoingCallModal
        isOpen={callState === "in_call"}
        onEnd={handleEndCall}
      /> */}
      <audio ref={remoteAudioRef} autoPlay playsInline hidden />
    </DashboardLayout>
  );
};

export default TicketDetail;
