import { useEffect, useRef, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import Loader from "../../../components/modals/Loader";
import DashboardLayout from "../../../layouts/DashboardLayout";
import { ArrowLeft, User, Clock, AlertCircle, Send, CheckCheck, HelpCircle } from "lucide-react";
import { getFakeTicketDetail, getTrainingMessages, retryTraining } from "../../../services/ticketService";
import { getSlaTimer } from "../../../utils/slaTImer";
import useTrainingChat from "../../../hooks/useTrainingChat";
import { useAuth } from "../../../auth/AuthContext";

const AgentFakeTicketDetail = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const { userId } = useAuth();
  const currentUserId = userId;

  const {
    messages,startResolve,
    newMessage,
    setMessages,
    setNewMessage,
    sendMessage,
    isResolving,setIsResolving,
    isTyping,
    socketRef,
    evaluation,setEvaluation,
    showRetry,setShowRetry,
  } = useTrainingChat(id, currentUserId);

  const [ticket, setTicket] = useState(null);
  const [loading, setLoading] = useState(true);
  const [evaluating, setEvaluating] = useState(false);
  
  // Localized template container target element
  const chatBottomRef = useRef(null);

  useEffect(() => {
    fetchTicket();
    fetchMessages();
  }, [id, currentUserId]);

  // CRITICAL FIX: Explicitly watch the messages array inside this view context
  useEffect(() => {
    if (!loading && messages.length > 0) {
      // Small timeout ensures the DOM has completed recalculating layout height
      const timer = setTimeout(() => {
        chatBottomRef.current?.scrollIntoView({ behavior: "smooth" });
      }, 100);
      return () => clearTimeout(timer);
    }
  }, [messages, loading]);

  const fetchMessages = async () => {
    try {
      const res = await getTrainingMessages(id);
      const formatted = res.map((msg) => ({
        message: msg.message,
        sender_id: msg.sender_type === "AGENT" ? currentUserId : 0,
        sender_name: msg.sender_type === "AGENT" ? "AGENT" : "AI Customer",
        created_at: msg.created_at,
      }));
      setMessages(formatted);
    } catch (err) {
      console.error("Error fetching messages:", err);
    }
  };

  const fetchTicket = async () => {
    try {
      const res = await getFakeTicketDetail(id);
      setTicket(res.message);
      console.log('detail page ',res.data)
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      if (newMessage.trim()) sendMessage();
    }
  };

const handleRetry = async () => {
    await retryTraining(id);
    setMessages([]);
    setEvaluation(null);
    setShowRetry(false);
    setTicket(prev => ({
        ...prev,
        status: "OPEN",
        training_passed: null,
    }));
};

    const handleResolveTicket= async()=>{
      setShowRetry(false);
      setIsResolving(true);
    socketRef.current.send(
      JSON.stringify({
        type:'resolve_ticket',
      })
    )
  }

const isPassed =
  evaluation?.passed === true || ticket?.training_passed === true;

const isFailed =
  !isPassed &&
  (evaluation?.passed === false || ticket?.training_passed === false);

const isEvaluating =
  isResolving && !evaluation;

const isPending =
  !isResolving && !evaluation && !ticket?.training_passed;

  if (loading) return <Loader />;
  if (!ticket) return <p className="p-6">Ticket not found</p>;

  return (
    <DashboardLayout>
      <div className="min-h-screen bg-white">
        
        {/* Top Navigation / Header */}
        <div className="flex items-center justify-between mb-8 max-w-6xl mx-auto">
          <div className="flex items-center gap-4">
            <button
              onClick={() => navigate(-1)}
              className="hover:bg-gray-100 p-2 rounded-full transition-colors"
            >
              <ArrowLeft size={20} />
            </button>
            <h1 className="text-xl font-bold">
              Ticket #{ticket?.ticket_code || id}
            </h1>
          </div>

        <div className="text-white px-2 py-2 rounded-lg font-medium text-sm">

 {isPending && (
  <button onClick={startResolve} className="bg-green-600 px-4 py-2 rounded-lg">
    Mark as Resolved
  </button>
)}

{isEvaluating && (
  <div className="bg-yellow-100 text-yellow-700 px-4 py-2 rounded-lg">
    Evaluating AI Score...
  </div>
)}

{isFailed && !isEvaluating && (
  <button onClick={handleRetry} className="bg-red-600 px-4 py-2 rounded-lg">
    Retry Training
  </button>
)}

{isPassed && (
  <div className="bg-green-100 text-green-700 px-4 py-2 rounded-lg">
    Certified ✓
  </div>
)}
</div>
          
        </div>

        {/* Master Content Layout Grid */}
        <div className="max-w-6xl mx-auto grid grid-cols-1 md:grid-cols-12 gap-8">
          
          {/* LEFT PANEL: Ticket Details Card */}
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
                <div className="flex items-center gap-2 font-medium capitalize">
                  <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                  {ticket?.status || "In progress"}
                </div>
              </div>

              {/* Priority Section */}
              <div className="pt-4 border-t">
                <div className="flex items-center gap-2 text-gray-400 text-sm mb-2">
                  <AlertCircle size={16} />
                  Priority
                </div>
                <span className="bg-pink-500 text-white px-4 py-1 rounded-full text-xs font-bold uppercase tracking-wide">
                  {ticket?.priority || "High"}
                </span>
              </div>

              {/* Customer Section */}
              <div className="pt-4 border-t">
                <div className="flex items-center gap-2 text-gray-400 text-sm mb-2">
                  <User size={16} />
                  Customer
                </div>
                <p className="font-medium">{"User_here"}</p>
              </div>

              {/* Created Section */}
              <div className="pt-4 border-t">
                <div className="flex items-center gap-2 text-gray-400 text-sm mb-2">
                  <Clock size={16} className="rotate-180" />
                  Created
                </div>
                <p className="text-sm font-medium">
                  {ticket?.created_at
                    ? new Date(ticket.created_at).toLocaleString()
                    : "1/3/2026, 10:30:00 AM"}
                </p>
              </div>
            </div>
          </div>

          {/* RIGHT PANEL: Conversation Box */}
          <div className="md:col-span-8 lg:col-span-9">
            <div className="border border-gray-300 rounded-3xl h-[640px] flex flex-col overflow-hidden">
              
              {/* Conversation Header */}
              <div className="p-6 pb-4 flex justify-between items-start border-b border-gray-100">
                <div>
                  <h2 className="text-xl font-semibold">Conversation</h2>
                  <p className="text-gray-400 text-sm italic">Simulated training interaction</p>
                </div>
              </div>

              {/* Streamlined Single-Line Ticket Subject Banner */}
              <div className="mx-6 mt-4 flex items-center gap-2 bg-yellow-50 border border-yellow-200 rounded-xl px-4 py-2 text-sm">
                <HelpCircle size={16} className="text-yellow-600 shrink-0" />
                <span className="font-semibold text-gray-800 shrink-0">Issue:</span>
                <p className="text-gray-700 truncate">{ticket?.subject}</p>
              </div>

              {/* Chat Timeline Area */}
              <div className="flex-1 overflow-y-auto p-6 flex flex-col gap-6">
                
                {/* Dynamic Message Logs Map */}
                {messages.map((msg, index) => {
                  const senderId = Number(msg?.sender_id ?? msg?.sender ?? 0);
                  const isMe = senderId === currentUserId || msg?.is_agent === true;

                  return (
                    <div
                      key={index}
                      className={`flex flex-col ${isMe ? "items-end" : "items-start"} gap-2`}
                    >
                      <div className="flex items-center gap-2 text-xs text-gray-500 font-bold">
                        <span className="text-[10px] text-gray-400">
                          {msg?.created_at
                            ? new Date(msg.created_at).toLocaleTimeString()
                            : new Date().toLocaleTimeString()}
                        </span>
                      </div>

                      <div className={`flex items-end gap-3 max-w-[80%] ${isMe ? "flex-row-reverse" : ""}`}>
                        <div
                          className={`relative p-4 rounded-2xl text-sm shadow-sm ${
                            isMe
                              ? "bg-[#3f644b] text-white rounded-tr-none"
                              : "bg-gray-200 text-gray-900 rounded-tl-none"
                          }`}
                        >
                          <p className={isMe ? "pr-4" : ""}>{msg?.message}</p>

                          {isMe && (
                            <span className="absolute bottom-1 right-2">
                              <CheckCheck size={14} className="text-sky-300" />
                            </span>
                          )}
                        </div>

                        <div className="w-8 h-8 rounded-full bg-gray-500 flex items-center justify-center text-white text-xs font-bold shrink-0">
                          {msg?.sender_name?.[0] || (isMe ? "A" : "C")}
                        </div>
                      </div>
                    </div>
                  );
                })}
{isTyping && (
  <div className="flex items-end gap-3 max-w-[80%] animate-fade-in">
    {/* Customer Avatar Circle */}
    <div className="w-8 h-8 rounded-full bg-gray-400 flex items-center justify-center text-white text-xs font-bold shrink-0 shadow-sm">
      C
    </div>

    {/* The Bubble Context */}
    <div className="flex flex-col gap-1 items-start">
      {/* Sender Label */}
      <span className="text-[11px] text-gray-500 font-semibold pl-1">AI Customer</span>
      
      {/* WhatsApp Style Animated Bubble */}
      <div className="bg-gray-200 text-gray-900 rounded-2xl rounded-tl-none px-4 py-3 shadow-sm flex items-center min-w-[64px] justify-center h-9">
        <div className="flex items-center gap-1.5 h-2">
          <span className="w-2 h-2 bg-gray-500 rounded-full animate-[bounce_1.4s_infinite_0ms] ease-in-out" />
          <span className="w-2 h-2 bg-gray-500 rounded-full animate-[bounce_1.4s_infinite_180ms] ease-in-out" />
          <span className="w-2 h-2 bg-gray-500 rounded-full animate-[bounce_1.4s_infinite_360ms] ease-in-out" />
        </div>
      </div>
    </div>
  </div>
)}
                <div ref={chatBottomRef} />
              </div>


              {/* Message Input & Guidelines Overlay Footer */}
              <div className="p-6 pb-8 border-t border-gray-100 bg-white">
                <div className="relative flex items-center mb-2">
                  <textarea
                    rows={1}
                    value={newMessage}
                    onChange={(e) => setNewMessage(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder="Type your simulated response..."
                    className="w-full bg-gray-100 rounded-2xl py-4 pl-6 pr-16 focus:outline-none resize-none shadow-inner"
                  />
                  <div className="absolute right-4 flex items-center gap-4">
                    <button
                      onClick={sendMessage}
                      className="text-black hover:translate-x-1 transition-transform"
                    >
                      <Send size={20} />
                    </button>
                  </div>
                </div>
              </div>

            </div>
          </div>

        </div>
      </div>

      {evaluation && (
  <div className="p-4 border rounded-xl bg-gray-50 mt-4">
    <h3 className="font-bold text-lg">QA Evaluation Result</h3>

    <p>Score: {evaluation.score}</p>

    <p>
      Status:{" "}
      <span className={evaluation.passed ? "text-green-600" : "text-red-600"}>
        {evaluation.passed ? "PASSED" : "FAILED"}
      </span>
    </p>

    <p className="text-sm text-gray-600 mt-2">
      {evaluation.feedback}
    </p>
  </div>
)}
    </DashboardLayout>
  );
};

export default AgentFakeTicketDetail;