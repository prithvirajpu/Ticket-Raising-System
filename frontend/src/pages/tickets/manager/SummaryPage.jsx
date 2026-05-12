import { useLocation, useNavigate } from 'react-router-dom';
import DashboardLayout from '../../../layouts/DashboardLayout';
import { FileText, ArrowLeft, Calendar, User, Hash, Sparkles, Edit3, X, Check, Send } from 'lucide-react';
import { useState } from 'react';
import { summarySubmit } from '../../../services/ticketService';
import ConfirmModal from '../../../components/modals/ConfirmModal'; // Ensure this path is correct
import { notifySuccess } from '../../../utils/notify';

const SummaryPage = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { summary, client_id, docId } = location.state || {};
  const [isEditing, setIsEditing] = useState(false);
  const [editedSummary, setEditedSummary] = useState(summary || "");
  const [savedSummary, setSavedSummary] = useState(summary || "");
  const [loading, setLoading] = useState(false);
  const [isModalOpen, setIsModalOpen] = useState(false); // State for Modal

  const handleSave = () => {
    setSavedSummary(editedSummary);
    setIsEditing(false);
  };

  const handleSubmit = async () => {
    try {
      setLoading(true);
      await summarySubmit(docId, { summary: savedSummary });
      setIsModalOpen(false); 
      navigate(`/manager/client-docs/${client_id}`)
      notifySuccess('Summary Successfully submitted ')
    } catch (err) {
      console.error(err);
      alert("Failed to submit");
    } finally {
      setLoading(false);
    }
  };

  if (!savedSummary) {
    return (
      <DashboardLayout title="Document Summary">
        <div className="flex flex-col items-center justify-center min-h-[60vh] text-center">
          <div className="w-20 h-20 bg-gray-50 rounded-full flex items-center justify-center mb-6">
            <FileText className="w-10 h-10 text-gray-300" />
          </div>
          <h2 className="text-xl font-bold text-gray-900 mb-2">No Summary Available</h2>
          <p className="text-gray-500 mb-8 max-w-xs">We couldn't find the summary data for this specific document.</p>
          <button 
            onClick={() => navigate(-1)}
            className="flex items-center gap-2 px-6 py-2.5 bg-white border border-gray-200 rounded-lg hover:bg-gray-50 transition shadow-sm font-medium"
          >
            <ArrowLeft size={18} /> Back to Documents
          </button>
        </div>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout title="Knowledge Base" subtitle="AI Document Intelligence">

      <div className="max-w-5xl mx-auto mt-6 px-6 pb-20">
        <div className="flex items-center justify-between mb-8">
          <button
            onClick={() => navigate(-1)}
            className="group flex items-center gap-2 text-sm font-medium text-gray-500 hover:text-blue-600 transition-colors"
          >
            <ArrowLeft size={16} className="group-hover:-translate-x-1 transition-transform" />
            Back to Client Documents
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <div className="lg:col-span-2">
            <div className="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
              <div className="bg-gradient-to-r from-blue-600 to-indigo-700 px-8 py-4 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Sparkles className="text-blue-200" size={18} />
                  <span className="text-white text-sm font-semibold tracking-wide uppercase">AI Insight Report</span>
                </div>
                {!isEditing && (
                  <button
                    onClick={() => setIsEditing(true)}
                    className="flex items-center gap-2 px-3 py-1.5 bg-white/10 hover:bg-white/20 text-white text-xs font-bold rounded-lg transition backdrop-blur-sm border border-white/20"
                  >
                    <Edit3 size={14} /> Edit Report
                  </button>
                )}
              </div>

              <div className="p-8 md:p-12">
                <div className="flex items-center justify-between mb-8">
                  <h1 className="text-3xl font-extrabold text-gray-900 leading-tight">
                    Executive Summary
                  </h1>
                  {isEditing && (
                    <div className="flex gap-2">
                      <button
                        onClick={() => {
                          setEditedSummary(savedSummary);
                          setIsEditing(false);
                        }}
                        className="flex items-center gap-1.5 px-3 py-2 text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded-lg text-sm font-medium transition"
                      >
                       Cancel
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
                      value={editedSummary}
                      onChange={(e) => setEditedSummary(e.target.value)}
                      className="w-full h-[500px] p-6 border-2 border-blue-100 rounded-2xl text-[15px] text-gray-700 leading-relaxed focus:border-blue-500 focus:ring-4 focus:ring-blue-50/50 outline-none transition-all resize-none shadow-inner bg-gray-50/30"
                      placeholder="Start editing the summary..."
                    />
                    <div className="absolute top-4 right-4 text-[10px] font-bold text-blue-400 uppercase tracking-widest bg-white px-2 py-1 rounded border border-blue-100">
                      Editor Mode
                    </div>
                  </div>
                ) : (
                  <div className="prose prose-blue max-w-none space-y-5">
                    {savedSummary
                      .split('\n')
                      .filter((line) => line.trim() !== '')
                      .map((line, index) => {
                        const trimmed = line.trim();
                        if (trimmed.startsWith('#') || (trimmed.startsWith('**') && trimmed.endsWith('**'))) {
                          return (
                            <h3 key={index} className="text-lg font-bold text-gray-900 pt-4 mb-2 border-b pb-2 flex items-center gap-2">
                              <div className="w-1 h-4 bg-blue-500 rounded-full" />
                              {trimmed.replace(/[*#]/g, '')}
                            </h3>
                          );
                        }
                        if (trimmed.startsWith('-') || trimmed.startsWith('•') || trimmed.startsWith('* ')) {
                          return (
                            <div key={index} className="ml-4 flex gap-3 text-gray-600">
                              <span className="text-blue-500 font-bold">•</span>
                              <span className="text-[15px] leading-relaxed">{trimmed.replace(/^[-•*]\s?/, '')}</span>
                            </div>
                          );
                        }
                        return (
                          <p key={index} className="text-[15px] text-gray-600 leading-relaxed">
                            {trimmed}
                          </p>
                        );
                      })}
                  </div>
                )}
                
                <div className="mt-10 pt-8 border-t border-gray-100">
                   <button
                    onClick={() => setIsModalOpen(true)} // Opens Modal instead of direct submit
                    disabled={loading || isEditing}
                    className={`w-full md:w-auto flex items-center justify-center gap-2 px-8 py-3 rounded-xl text-sm font-bold transition shadow-lg shadow-blue-200/50 ${
                      loading || isEditing 
                      ? "bg-gray-100 text-gray-400 cursor-not-allowed shadow-none" 
                      : "bg-blue-600 hover:bg-blue-700 text-white active:scale-95"
                    }`}
                  >
                    <Send size={18} />
                    Submit to Team Lead
                  </button>
                </div>
              </div>
            </div>
          </div>

          <div className="lg:col-span-1 space-y-6">
            <div className="bg-gray-50 border border-gray-200 rounded-2xl p-6 sticky top-6">
              <h4 className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-6">Metadata Details</h4>
              <div className="space-y-5">
                <div className="flex items-start gap-4">
                  <div className="p-2 bg-white rounded-lg border border-gray-100 shadow-sm">
                    <User size={16} className="text-blue-500" />
                  </div>
                  <div>
                    <p className="text-xs text-gray-500 font-medium">Client Reference</p>
                    <p className="text-sm font-semibold text-gray-800">{client_id ? `Client #${client_id}` : 'Not Assigned'}</p>
                  </div>
                </div>
                <div className="flex items-start gap-4">
                  <div className="p-2 bg-white rounded-lg border border-gray-100 shadow-sm">
                    <Hash size={16} className="text-blue-500" />
                  </div>
                  <div>
                    <p className="text-xs text-gray-500 font-medium">Document ID</p>
                    <p className="text-sm font-mono text-gray-700 bg-gray-100 px-1.5 rounded">{docId || 'N/A'}</p>
                  </div>
                </div>
                <div className="flex items-start gap-4">
                  <div className="p-2 bg-white rounded-lg border border-gray-100 shadow-sm">
                    <Calendar size={16} className="text-blue-500" />
                  </div>
                  <div>
                    <p className="text-xs text-gray-500 font-medium">Analysis Date</p>
                    <p className="text-sm font-semibold text-gray-800">
                      {new Date().toLocaleDateString(undefined, { dateStyle: 'medium' })}
                    </p>
                  </div>
                </div>
              </div>
              <div className="mt-8 pt-6 border-t border-gray-200">
                <div className="bg-blue-50 rounded-xl p-4 border border-blue-100">
                  <p className="text-[11px] text-blue-700 leading-snug">
                    <strong>Note:</strong> This summary was automatically generated. Please cross-reference with the original document for critical accuracy.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <ConfirmModal
        isOpen={isModalOpen}
        title="Submit to Team Lead?"
        message="Are you sure you want to submit this summary? This will notify your Team Lead for review."
        confirmText="Yes, Submit"
        loading={loading}
        onConfirm={handleSubmit}
        onCancel={() => setIsModalOpen(false)}
      />
    </DashboardLayout>
  );
};

export default SummaryPage;