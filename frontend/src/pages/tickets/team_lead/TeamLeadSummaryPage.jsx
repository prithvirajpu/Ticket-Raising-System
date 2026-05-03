import { useEffect, useState } from "react";
import { getTeamLeadSummaries } from "../../../services/ticketService";
import Loader from "../../../components/modals/Loader";
import DashboardLayout from "../../../layouts/DashboardLayout";
import { useNavigate } from "react-router-dom";
import { 
  FileText, 
  Sparkles, 
  Zap, 
  ChevronRight, 
  Calendar, 
  Info, 
  Target, 
  CheckCircle2, 
  AlertCircle 
} from "lucide-react";

const TeamLeadSummaryPage = () => {
  const [summaries, setSummaries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [generatingId, setGeneratingId] = useState(null);
  const navigate = useNavigate();

  const fetchSummaries = async () => {
    try {
      setLoading(true);
      const res = await getTeamLeadSummaries();
      setSummaries(res.message || []);
    } catch (error) {
      console.error("Error fetching summaries:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSummaries();
  }, []);

  const handleGenerate = (summaryId) => {
    setGeneratingId(summaryId);
    setTimeout(() => {
      navigate(`/agent-summary/${summaryId}`);
    }, 600);
  };

  if (loading || generatingId) {
    return (
      <DashboardLayout title="Assigned Summaries">
        <div className="flex flex-col items-center justify-center min-h-[60vh]">
          <Loader />
          <p className="text-gray-500 font-medium mt-4 animate-pulse">
            {generatingId ? "Optimizing Agent Training Module..." : "Loading assigned summaries..."}
          </p>
        </div>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout 
      title="Knowledge Base" 
      subtitle="Team Lead Review & Agent Conversion"
    >
      <div className="max-w-6xl mx-auto px-6 py-8">
        
        {summaries.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-24 bg-white rounded-2xl border border-gray-200 shadow-sm">
            <div className="bg-gray-50 w-16 h-16 rounded-full flex items-center justify-center mb-4">
              <FileText className="text-gray-300" size={32} />
            </div>
            <h3 className="text-gray-900 font-bold text-lg">All caught up!</h3>
            <p className="text-gray-500">No new summaries require your attention.</p>
          </div>
        ) : (
          <div className="space-y-16">
            {summaries.map((item) => (
              <div key={item.id} className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-start">
                
                {/* Main Content: Document Summary with Advanced Parsing */}
                <div className="lg:col-span-2 bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
                  <div className="bg-gradient-to-r from-blue-600 to-indigo-700 px-6 py-4 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Sparkles className="text-blue-200" size={18} />
                      <span className="text-white text-sm font-semibold tracking-wide uppercase">AI Insight Report</span>
                    </div>
                    
                    <button
                      onClick={() => handleGenerate(item.id)}
                      className="group flex items-center gap-2 px-4 py-2 bg-white text-blue-700 hover:bg-blue-50 rounded-xl text-xs font-bold transition-all shadow-lg active:scale-95"
                    >
                      <Zap size={14} className="fill-blue-700" />
                      Generate Agent Version
                      <ChevronRight size={14} className="group-hover:translate-x-0.5 transition-transform" />
                    </button>
                  </div>

                  <div className="p-8 md:p-10">
                    <h3 className="text-2xl font-black text-gray-900 mb-8 border-b border-gray-50 pb-4">Executive Briefing</h3>
                    
                    <div className="space-y-6">
                      {item.summary.split('\n').filter(l => l.trim() !== '').map((line, idx) => {
                        const trimmed = line.trim();

                        // 1. Detect Headings (starts with # or wrapped in **)
                        if (trimmed.startsWith('#') || (trimmed.startsWith('**') && trimmed.endsWith('**'))) {
                          return (
                            <div key={idx} className="flex items-center gap-3 pt-4 pb-2 border-b border-gray-50">
                              <div className="p-1.5 bg-blue-50 rounded-lg">
                                <Target size={18} className="text-blue-600" />
                              </div>
                              <h4 className="text-lg font-bold text-gray-900 uppercase tracking-tight">
                                {trimmed.replace(/[*#]/g, '')}
                              </h4>
                            </div>
                          );
                        }

                        // 2. Detect Lists (- or • or *)
                        if (trimmed.startsWith('-') || trimmed.startsWith('•') || trimmed.startsWith('* ')) {
                          return (
                            <div key={idx} className="ml-2 flex items-start gap-3 group">
                              <div className="mt-1 flex-shrink-0">
                                <CheckCircle2 size={16} className="text-green-500" />
                              </div>
                              <span className="text-[15px] text-gray-600 leading-relaxed">
                                {trimmed.replace(/^[-•*]\s?/, '')}
                              </span>
                            </div>
                          );
                        }

                        // 3. Detect "Note" or "Important" sections
                        if (trimmed.toLowerCase().includes('note:') || trimmed.toLowerCase().includes('important:')) {
                            return (
                              <div key={idx} className="flex gap-3 p-4 bg-blue-50/50 border border-blue-100 rounded-xl my-4">
                                <AlertCircle size={18} className="text-blue-600 flex-shrink-0" />
                                <p className="text-[14px] text-blue-900 leading-relaxed italic">
                                  {trimmed}
                                </p>
                              </div>
                            );
                        }

                        // 4. Default Paragraph
                        return (
                          <div key={idx} className="flex gap-3">
                            <div className="mt-2.5 w-1 h-1 bg-gray-300 rounded-full flex-shrink-0 hidden md:block" />
                            <p className="text-[15px] text-gray-600 leading-relaxed">
                              {trimmed}
                            </p>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>

                {/* Sidebar: Metadata */}
                <div className="lg:col-span-1 space-y-4">
                  <div className="bg-gray-50 border border-gray-200 rounded-2xl p-6 sticky top-6">
                    <h4 className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-6">Review Metadata</h4>
                    
                    <div className="space-y-5">
                      <div className="flex items-start gap-4">
                        <div className="p-2 bg-white rounded-lg border border-gray-100 shadow-sm">
                          <Calendar size={16} className="text-blue-500" />
                        </div>
                        <div>
                          <p className="text-xs text-gray-500 font-medium">Arrival Date</p>
                          <p className="text-sm font-semibold text-gray-800">
                            {new Date().toLocaleDateString(undefined, { dateStyle: 'medium' })}
                          </p>
                        </div>
                      </div>
                    </div>

                    <div className="mt-8 pt-6 border-t border-gray-200">
                      <div className="bg-amber-50 rounded-xl p-4 border border-amber-100">
                        <p className="text-[11px] text-amber-800 leading-snug">
                          <strong>Compliance Note:</strong> Ensure all AI-generated points align with the latest standard operating procedures before publishing.
                        </p>
                      </div>
                    </div>
                  </div>
                </div>

              </div>
            ))}
          </div>
        )}
      </div>
    </DashboardLayout>
  );
};

export default TeamLeadSummaryPage;