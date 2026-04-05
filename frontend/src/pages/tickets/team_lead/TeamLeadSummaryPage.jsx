import { useEffect, useState } from "react";
import { getTeamLeadSummaries } from "../../../services/ticketService";
import Loader from "../../../components/modals/Loader";
import DashboardLayout from "../../../layouts/DashboardLayout";
import { useNavigate } from "react-router-dom";
import { FileText, User, Hash, Zap, ChevronRight, Quote } from "lucide-react";

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
    // Mimic the loading transition from ClientDocumentsPage
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
      title="Team Lead Dashboard" 
      subtitle="Review document insights and prepare agent versions"
    >
      <div className="max-w-5xl mx-auto px-6 py-8">

        {summaries.length === 0 ? (
          <div className="text-center py-24 bg-white rounded-[2rem] border-2 border-dashed border-gray-100">
            <div className="bg-gray-50 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
              <FileText className="text-gray-300" size={32} />
            </div>
            <h3 className="text-gray-900 font-bold text-lg">All caught up!</h3>
            <p className="text-gray-500">No new summaries require your attention.</p>
          </div>
        ) : (
          <div className="space-y-8">
            {summaries.map((item) => (
              <div 
                key={item.id} 
                className="bg-white border border-gray-200 rounded-[2rem] overflow-hidden shadow-sm hover:shadow-md transition-all duration-300 border-l-4 border-l-blue-600"
              >
                <div className="p-8">

                  {/* Full Readable Summary */}
                  <div className="relative mb-8">
                    <Quote className="absolute -top-2 -left-2 text-blue-50 opacity-20 w-12 h-12" />
                    <h3 className="text-xl font-black text-gray-900 mb-4 relative z-10">Document Summary</h3>
                    <div className="bg-gray-50/50 rounded-2xl p-6 border border-gray-100">
                      <p className="text-gray-700 text-[15px] leading-relaxed whitespace-pre-line font-medium">
                        {item.summary}
                      </p>
                    </div>
                  </div>

                  {/* Action Footer */}
                  <div className="flex items-center justify-between pt-4">
                    <p className="text-xs text-gray-400 font-medium italic">
                      Review this summary before converting to Agent Version
                    </p>
                    <button
                      onClick={() => handleGenerate(item.id)}
                      className="group flex items-center gap-3 px-8 py-4 bg-blue-600 hover:bg-blue-700 text-white rounded-2xl text-sm font-black transition-all shadow-xl shadow-blue-200 active:scale-95"
                    >
                      <Zap size={18} className="fill-white" />
                      Generate Agent Version
                      <ChevronRight size={18} className="group-hover:translate-x-1 transition-transform" />
                    </button>
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