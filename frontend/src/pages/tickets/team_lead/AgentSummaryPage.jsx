import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import Loader from "../../../components/modals/Loader";
import DashboardLayout from "../../../layouts/DashboardLayout";
import { generateAgentSummary, generateFakeTickets, submitAgentSummary } from "../../../services/ticketService";
import { 
  Check, X, Send, Edit3, ArrowLeft, Sparkles, 
  FileText, Calendar, Hash, User 
} from "lucide-react";
import ConfirmModal from "../../../components/modals/ConfirmModal";
import { notifySuccess } from "../../../utils/notify";

const AgentSummaryPage = () => {
  const { summary_id } = useParams();
  const navigate = useNavigate();
  
  // States
  const [data, setData] = useState(""); // The "saved" version displayed
  const [editedData, setEditedData] = useState(""); // The version in the textarea
  const [loading, setLoading] = useState(true);
  const [isEditing, setIsEditing] = useState(false);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [saving, setSaving] = useState(false);

  // Fetch AI-generated summary
  useEffect(() => {
    fetchAgentSummary();
  }, [summary_id]);

  const fetchAgentSummary = async () => {
    try {
      setLoading(true);
      const res = await generateAgentSummary(summary_id);
      // Assuming res.message contains the summary text
      const content = res.message || "";
      setData(content);
      setEditedData(content);
    } catch (error) {
      console.error("Error fetching summary:", error);
    } finally {
      setLoading(false);
    }
  };

  // Save changes locally (Update the view without hitting DB yet)
  const handleSave = () => {
    setData(editedData);
    setIsEditing(false);
  };

  // Cancel editing (Reset textarea to last saved state)
  const handleCancel = () => {
    setEditedData(data);
    setIsEditing(false);
  };

  // Submit final summary to backend
  const handleSubmit = async () => {
    try {
      setSaving(true);
      const finalData= isEditing?editedData:data;
      await submitAgentSummary(summary_id, { summary: finalData });
      await generateFakeTickets(finalData)
      setData(finalData)
      setIsEditing(false)
      setIsModalOpen(false);
      notifySuccess('Summary submitted and Tickets generated.')
    } catch (err) {
      console.error(err);
    } finally {
      setSaving(false);
    }
  };

  if (loading || saving) return <Loader />;

  return (
    <DashboardLayout title="Knowledge Base" subtitle="Agent Training Intelligence">
      <div className="max-w-5xl mx-auto mt-6 px-6 pb-20">
        
        {/* Top Navigation */}
        <div className="flex items-center justify-between mb-8">
          <button
            onClick={() => navigate(-1)}
            className="group flex items-center gap-2 text-sm font-medium text-gray-500 hover:text-blue-600 transition-colors"
          >
            <ArrowLeft size={16} className="group-hover:-translate-x-1 transition-transform" />
            Back to Training List
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Main Content Area */}
          <div className="lg:col-span-2">
            <div className="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
              
              {/* Card Header */}
              <div className="bg-gradient-to-r from-blue-600 to-indigo-700 px-8 py-4 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Sparkles className="text-blue-200" size={18} />
                  <span className="text-white text-sm font-semibold tracking-wide uppercase">AI Agent Analysis</span>
                </div>
                {!isEditing && (
                  <button
                    onClick={() => setIsEditing(true)}
                    className="flex items-center gap-2 px-3 py-1.5 bg-white/10 hover:bg-white/20 text-white text-xs font-bold rounded-lg transition backdrop-blur-sm border border-white/20"
                  >
                    <Edit3 size={14} /> Edit Summary
                  </button>
                )}
              </div>

              <div className="p-8 md:p-12">
                <div className="flex items-center justify-between mb-8">
                  <h1 className="text-3xl font-extrabold text-gray-900 leading-tight">
                    Training Executive Summary
                  </h1>
                  {isEditing && (
                    <div className="flex gap-2">
                      <button
                        onClick={handleCancel}
                        className="flex items-center gap-1.5 px-3 py-2 text-gray-700 hover:text-gray-700 hover:bg-gray-100 rounded-lg text-sm font-medium transition"
                      > Cancel
                      </button>
                      <button
                        onClick={handleSave}
                        className="flex items-center gap-1.5 px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg text-sm font-bold shadow-sm transition"
                      >
                         Save 
                      </button>
                    </div>
                  )}
                </div>

                {isEditing ? (
                  <div className="relative group">
                    <textarea
                      value={editedData}
                      onChange={(e) => setEditedData(e.target.value)}
                      className="w-full h-[500px] p-6 border-2 border-blue-100 rounded-2xl text-[15px] text-gray-700 leading-relaxed focus:border-blue-500 focus:ring-4 focus:ring-blue-50/50 outline-none transition-all resize-none shadow-inner bg-gray-50/30"
                      placeholder="Refine the agent summary..."
                    />
                    <div className="absolute top-4 right-4 text-[10px] font-bold text-blue-400 uppercase tracking-widest bg-white px-2 py-1 rounded border border-blue-100">
                      Editor Mode
                    </div>
                  </div>
                ) : (
                  <div className="prose prose-blue max-w-none space-y-5">
                    {data.split('\n').filter(line => line.trim() !== '').map((line, index) => {
                      const trimmed = line.trim();
                      // Header Rendering
                      if (trimmed.startsWith('#') || (trimmed.startsWith('**') && trimmed.endsWith('**'))) {
                        return (
                          <h3 key={index} className="text-lg font-bold text-gray-900 pt-4 mb-2 border-b pb-2 flex items-center gap-2">
                            <div className="w-1 h-4 bg-blue-500 rounded-full" />
                            {trimmed.replace(/[*#]/g, '')}
                          </h3>
                        );
                      }
                      // List Item Rendering
                      if (trimmed.startsWith('-') || trimmed.startsWith('•') || trimmed.startsWith('* ')) {
                        return (
                          <div key={index} className="ml-4 flex gap-3 text-gray-600">
                            <span className="text-blue-500 font-bold">•</span>
                            <span className="text-[15px] leading-relaxed">{trimmed.replace(/^[-•*]\s?/, '')}</span>
                          </div>
                        );
                      }
                      // Paragraph Rendering
                      return (
                        <p key={index} className="text-[15px] text-gray-600 leading-relaxed">
                          {trimmed}
                        </p>
                      );
                    })}
                  </div>
                )}
                
                {/* Action Button */}
                <div className="mt-10 pt-8 border-t border-gray-100">
                  <button
                    onClick={() => setIsModalOpen(true)}
                    disabled={saving}
                    className={`w-full md:w-auto flex items-center justify-center gap-2 px-8 py-3 rounded-xl text-sm font-bold transition shadow-lg shadow-blue-200/50 ${
                      saving || isEditing 
                      ? "bg-gray-100 text-gray-400 cursor-not-allowed shadow-none" 
                      : "bg-blue-600 hover:bg-blue-700 text-white active:scale-95"
                    }`}
                  >
                    <Send size={18} />
                    Submit Agent Summary & Generate tickets
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Sidebar Metadata */}
          <div className="lg:col-span-1 space-y-6">
            <div className="bg-gray-50 border border-gray-200 rounded-2xl p-6 sticky top-6">
              <h4 className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-6">Summary Metadata</h4>
              <div className="space-y-5">
                
                <div className="flex items-start gap-4">
                  <div className="p-2 bg-white rounded-lg border border-gray-100 shadow-sm">
                    <Calendar size={16} className="text-blue-500" />
                  </div>
                  <div>
                    <p className="text-xs text-gray-500 font-medium">Generation Date</p>
                    <p className="text-sm font-semibold text-gray-800">
                      {new Date().toLocaleDateString(undefined, { dateStyle: 'medium' })}
                    </p>
                  </div>
                </div>
              </div>
              
              <div className="mt-8 pt-6 border-t border-gray-200">
                <div className="bg-blue-50 rounded-xl p-4 border border-blue-100">
                  <p className="text-[11px] text-blue-700 leading-snug">
                    <strong>Note:</strong> This agent summary is AI-generated based on recent ticket performance. Review carefully before submitting to the training team.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Confirm Submit Modal */}
      <ConfirmModal
        isOpen={isModalOpen}
        title="Submit Agent Summary?"
        message="Are you sure you want to submit this summary and generate fake tickets? This will notify the training department for review."
        confirmText="Yes, Submit"
        loading={saving}
        onConfirm={handleSubmit}
        onCancel={() => setIsModalOpen(false)}
      />
    </DashboardLayout>
  );
};

export default AgentSummaryPage;