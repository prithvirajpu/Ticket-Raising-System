import { useState } from "react";
import { sendClientNotification } from "../../services/ticketService";
import { notifyError, notifySuccess } from "../../utils/notify";
import { X, Send, Loader2 } from "lucide-react";

export default function NotifyClientModal({ ticket, isOpen, onClose }) {
  const [subject, setSubject] = useState("");
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);

  // If the modal isn't open, don't render anything
  if (!isOpen) return null;

  const handleSend = async () => {
    if (!subject.trim()) {
      notifyError("Subject is required");
      return;
    }

    if (!message.trim()) {
      notifyError("Message is required");
      return;
    }

    try {
      setLoading(true);

      await sendClientNotification(
        ticket.id,
        subject,
        message
      );

      notifySuccess("Notification sent successfully.");
      setSubject("");
      setMessage("");
      onClose();
    } catch (err) {
      console.error(err);
      notifyError(
        err?.response?.data?.errors?.details ||
          "Failed to send notification."
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4 animate-fade-in">
      {/* Modal Container */}
      <div 
        className="bg-white rounded-2xl shadow-xl w-full max-w-lg overflow-hidden flex flex-col transform transition-all"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
          <div>
            <h2 className="text-lg font-semibold text-gray-900">Notify Client Admin</h2>
            <p className="text-xs text-gray-500">Send an update regarding Ticket #{ticket?.ticket_code || ticket?.id}</p>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-gray-400 hover:text-gray-600 hover:bg-gray-100 transition-colors"
          >
            <X size={20} />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-4">
          <div>
            <label className="block text-xs font-semibold text-gray-700 uppercase tracking-wider mb-1">
              Subject
            </label>
            <input
              type="text"
              className="w-full border border-gray-300 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all"
              placeholder="e.g. Critical Update Regarding System Outage"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-gray-700 uppercase tracking-wider mb-1">
              Message
            </label>
            <textarea
              rows={5}
              className="w-full border border-gray-300 rounded-xl p-4 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all resize-none"
              placeholder="Enter your message details here..."
              value={message}
              onChange={(e) => setMessage(e.target.value)}
            />
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-6 py-4 bg-gray-50 border-t border-gray-100">
          <button
            onClick={onClose}
            disabled={loading}
            className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-xl hover:bg-gray-50 transition-colors disabled:opacity-50"
          >
            Cancel
          </button>

          <button
            disabled={loading}
            onClick={handleSend}
            className="flex items-center gap-2 px-5 py-2 text-sm font-medium text-white bg-blue-600 rounded-xl hover:bg-blue-700 focus:ring-2 focus:ring-blue-500/20 transition-all disabled:opacity-50"
          >
            {loading ? (
              <>
                <Loader2 size={16} className="animate-spin" />
                Sending...
              </>
            ) : (
              <>
                <Send size={16} />
                Send Notification
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}