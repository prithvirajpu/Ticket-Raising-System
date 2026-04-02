import { useLocation, useNavigate } from 'react-router-dom';
import DashboardLayout from '../../../layouts/DashboardLayout';
import { FileText, ArrowLeft, Calendar, User, Hash, Download, Sparkles } from 'lucide-react';

const SummaryPage = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { summary, client_id, docId } = location.state || {};

  if (!summary) {
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
        
        {/* Navigation & Actions Row */}
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
          
          {/* LEFT: Main Summary Content */}
          <div className="lg:col-span-2 space-y-6">
            <div className="bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
              {/* Decorative AI Header */}
              <div className="bg-gradient-to-r from-blue-600 to-indigo-700 px-8 py-4 flex items-center gap-3">
                <Sparkles className="text-blue-200" size={18} />
                <span className="text-white text-sm font-semibold tracking-wide uppercase">AI Insight Report</span>
              </div>

              <div className="p-8 md:p-12">
                <h1 className="text-3xl font-extrabold text-gray-900 mb-8 leading-tight">
                  Executive Summary
                </h1>
                
                <div className="prose prose-blue max-w-none">
                  {summary.split('\n').map((line, index) => {
                    const trimmed = line.trim();
                    if (!trimmed) return <div key={index} className="h-6" />;

                    // Enhanced Heading Detection
                    if ((trimmed.startsWith('**') && trimmed.endsWith('**')) || trimmed.startsWith('#')) {
                      return (
                        <h3 key={index} className="text-lg font-bold text-gray-900 mt-8 mb-4 flex items-center gap-2 border-b border-gray-100 pb-2">
                          <div className="w-1.5 h-1.5 bg-blue-500 rounded-full" />
                          {trimmed.replace(/[*#]/g, '')}
                        </h3>
                      );
                    }

                    // Handle Bullet Points if any exist in data
                    if (trimmed.startsWith('-') || trimmed.startsWith('•')) {
                        return (
                            <li key={index} className="ml-4 mb-2 text-gray-600 list-none flex gap-3">
                                <span className="text-blue-400">•</span> {trimmed.substring(1)}
                            </li>
                        )
                    }

                    return (
                      <p key={index} className="text-[16px] text-gray-600 leading-relaxed mb-4">
                        {trimmed}
                      </p>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>

          {/* RIGHT: Document Meta Sidebar */}
          <div className="lg:col-span-1 space-y-6">
            <div className="bg-gray-50 border border-gray-200 rounded-2xl p-6">
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
                    <p className="text-sm font-semibold text-gray-800">{new Date().toLocaleDateString(undefined, { dateStyle: 'medium' })}</p>
                  </div>
                </div>
              </div>

              <div className="mt-8 pt-6 border-t border-gray-200">
                <div className="bg-blue-50 rounded-xl p-4 border border-blue-100">
                  <p className="text-[11px] text-blue-700 leading-snug">
                    <strong>Note:</strong> This summary was automatically generated by AI. Please cross-reference with the original document for legal or critical accuracy.
                  </p>
                </div>
              </div>
            </div>
          </div>

        </div>
      </div>
    </DashboardLayout>
  );
};

export default SummaryPage;