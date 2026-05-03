import { useEffect, useState } from 'react'
import { 
  Sparkles, 
  FileText, 
  Calendar, 
  Target, 
  CheckCircle2, 
  AlertCircle 
} from 'lucide-react';
import DashboardLayout from '../../../layouts/DashboardLayout'
import { getAgentSummary } from '../../../services/ticketService';
import Loader from '../../../components/modals/Loader';

const AgentSummary = () => {
    const [summary, setSummary] = useState('');
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        fetchSummary();
    }, [])

    const fetchSummary = async () => {
        try {
            setLoading(true);
            const res = await getAgentSummary();
            setSummary(res.summary || "")
        } catch (error) {
            console.error('Error fetching summary:', error);
        } finally {
            setLoading(false)
        }
    }

    if (loading) {
        return (
            <DashboardLayout title="Knowledge Base" subtitle="AI Document Intelligence">
                <div className="flex flex-col items-center justify-center min-h-[60vh]">
                    <Loader />
                    <p className="text-gray-500 font-medium mt-4 animate-pulse">Syncing performance insights...</p>
                </div>
            </DashboardLayout>
        );
    }

    if (!summary) {
        return (
            <DashboardLayout title="Agent Summary">
                <div className="flex flex-col items-center justify-center py-24 bg-white rounded-2xl border border-gray-200 shadow-sm mx-6 mt-8">
                    <div className="bg-gray-50 w-16 h-16 rounded-full flex items-center justify-center mb-4">
                        <FileText className="text-gray-300" size={32} />
                    </div>
                    <h3 className="text-gray-900 font-bold text-lg">No Summary Available</h3>
                    <p className="text-gray-500">We couldn't find any performance data for you at this time.</p>
                </div>
            </DashboardLayout>
        );
    }

    return (
        <DashboardLayout title="Knowledge Base" subtitle="AI Document Intelligence">
            <div className="max-w-6xl mx-auto px-6 py-8">
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-start">
                    
                    {/* Main Content: Document Summary with Advanced Parsing */}
                    <div className="lg:col-span-2 bg-white border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
                        <div className="bg-gradient-to-r from-blue-600 to-indigo-700 px-6 py-4 flex items-center justify-between">
                            <div className="flex items-center gap-3">
                                <Sparkles className="text-blue-200" size={18} />
                                <span className="text-white text-sm font-semibold tracking-wide uppercase">Personal Performance Report</span>
                            </div>
                        </div>

                        <div className="p-8 md:p-10">
                            <h3 className="text-2xl font-black text-gray-900 mb-8 border-b border-gray-50 pb-4">Executive Briefing</h3>
                            
                            <div className="space-y-6">
                                {summary.split('\n').filter(l => l.trim() !== '').map((line, idx) => {
                                    const trimmed = line.trim();

                                    // 1. Detect Headings (starts with # or wrapped in **)
                                    if (trimmed.startsWith('#') || (trimmed.startsWith('**') && (trimmed.endsWith('**') || trimmed.endsWith('**.')))) {
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
                                                <span className="text-[15px] text-gray-600 leading-relaxed font-medium">
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
                                                <p className="text-[14px] text-blue-900 leading-relaxed italic font-medium">
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
                        <div className="bg-gray-50 border border-gray-200 rounded-2xl p-6 sticky top-6 shadow-sm">
                            <h4 className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-6">Report Metadata</h4>
                            
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
                                    <p className="text-[11px] text-blue-800 leading-snug">
                                        <strong>Pro-Tip:</strong> Review these insights to identify trends in your workflow and areas where AI suggests optimization.
                                    </p>
                                </div>
                            </div>
                        </div>
                    </div>

                </div>
            </div>
        </DashboardLayout>
    )
}

export default AgentSummary;