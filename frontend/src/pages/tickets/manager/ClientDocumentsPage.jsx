import { useEffect, useState, useCallback } from "react";
import DashboardLayout from "../../../layouts/DashboardLayout";
import { getClientDocs, summarizeAllDocuments } from "../../../services/ticketService";
import { useNavigate, useParams } from "react-router-dom";
import { FileText, ExternalLink, AlertCircle, Loader2, ChevronRight } from "lucide-react";
import Loader from "../../../components/modals/Loader";

const ClientDocumentsPage = () => {
  const { client_id } = useParams();
  const navigate = useNavigate();

  const [docs, setDocs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("guidelines");
  const [summarizing, setSummarizing] = useState(false);

  useEffect(() => {
    if (!client_id) {
      setLoading(false);
      return;
    }
    fetchDocs();
  }, [client_id]);

  const fetchDocs = async () => {
    setLoading(true);
    try {
      const res = await getClientDocs(client_id);
      const data = res?.message || res?.data?.message || res?.data || [];
      setDocs(Array.isArray(data) ? data : []);
    } catch (err) {
      console.error("Failed to fetch documents:", err);
    } finally {
      setLoading(false);
    }
  };

  const currentDoc = docs[0];

  const handleSummarizeAll = useCallback(async () => {
    if (!currentDoc?.id) {
      alert("Document ID is missing.");
      return;
    }

    try {
      setSummarizing(true);
      console.log(`Starting summarization for doc ID: ${currentDoc.id}`);

      const res = await summarizeAllDocuments(currentDoc.id);
      
      const summary = res?.message || res?.summary || res?.data?.message || "No summary received.";

      navigate('/summary', {
        state: { 
          summary, 
          client_id, 
          docId: currentDoc.id 
        }
      });
    } catch (error) {
      console.error("Summarization error:", error);
      const msg = error.response?.data?.details || error.message || "Failed to generate summary";
      alert(`Summarization Failed: ${msg}`);
    } finally {
      setSummarizing(false);
    }
  }, [currentDoc, navigate, client_id]);

  if (loading) {
    return (
      <DashboardLayout title="Knowledge Base">
        <div className="flex flex-col items-center justify-center min-h-[60vh]">
          <Loader/>
          <p className="text-gray-500 font-medium">Retrieving secure documents...</p>
        </div>
      </DashboardLayout>
    );
  }

  if (!currentDoc) {
    return (
      <DashboardLayout title="Knowledge Base">
        <div className="text-center py-20 bg-white rounded-3xl border border-dashed border-gray-200">
          <AlertCircle className="w-12 h-12 text-gray-300 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-gray-700">No Documents Found</h3>
          <p className="text-gray-500">This client hasn't uploaded any resources yet.</p>
        </div>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout 
      title="Client Knowledge Base" 
      subtitle={`Managing assets for Client #${client_id}`}
    >
      <div className="max-w-6xl mx-auto px-4 py-6">
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
          
          {/* Sidebar */}
          <div className="lg:col-span-1 space-y-2">
            <h3 className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-4 ml-2">Resources</h3>
            
            {[
              { id: "guidelines", label: "Guidelines", icon: FileText, url: currentDoc.guidelines_doc },
              { id: "faq", label: "FAQ Support", icon: FileText, url: currentDoc.faq_doc },
              { id: "extra", label: "Additional Info", icon: FileText, url: currentDoc.extra_doc },
            ].map((item) => (
              item.url && (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`w-full flex items-center justify-between p-4 rounded-2xl transition-all duration-200 ${
                    activeTab === item.id 
                    ? "bg-blue-600 text-white shadow-lg shadow-blue-100" 
                    : "bg-white text-gray-600 hover:bg-gray-50 border border-gray-100"
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <item.icon className={`w-5 h-5 ${activeTab === item.id ? "text-white" : "text-blue-500"}`} />
                    <span className="font-semibold text-sm">{item.label}</span>
                  </div>
                  <ChevronRight className={`w-4 h-4 opacity-50 ${activeTab === item.id ? "block" : "hidden"}`} />
                </button>
              )
            ))}

            <div className="mt-8 p-5 bg-gradient-to-br from-gray-900 to-gray-800 rounded-2xl text-white">
              <p className="text-xs opacity-60 mb-2">Direct Access</p>
              <a 
                href={currentDoc[`${activeTab}_doc`]} 
                target="_blank" 
                rel="noreferrer"
                className="flex items-center justify-between group"
              >
                <span className="text-sm font-bold">Open Full PDF</span>
                <ExternalLink className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
              </a>
            </div>
          </div>

          {/* Viewer */}
          <div className="lg:col-span-3">
            <div className="bg-white border border-gray-100 rounded-[2rem] shadow-sm overflow-hidden h-[800px] flex flex-col">
              <div className="p-6 border-b border-gray-50 flex justify-between items-center">
                <h2 className="text-xl font-bold text-gray-800 capitalize">
                  {activeTab.replace('_', ' ')} Viewer
                </h2>

                <button
                  onClick={handleSummarizeAll}
                  disabled={summarizing}
                  className="px-5 py-2.5 bg-green-600 hover:bg-green-700 text-white rounded-xl text-sm font-semibold flex items-center gap-2 transition disabled:opacity-50"
                >
                  {summarizing ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Summarizing...
                    </>
                  ) : (
                    "📋 Summarize All Documents"
                  )}
                </button>
              </div>
              
              <div className="flex-1 bg-gray-50 p-4">
                <iframe
                  src={currentDoc[`${activeTab}_doc`]}
                  width="100%"
                  height="100%"
                  title="Doc Viewer"
                  className="rounded-xl border border-gray-200 shadow-inner bg-white"
                />
              </div>
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default ClientDocumentsPage;