import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import DashboardLayout from "../../layouts/DashboardLayout"; 
import api from "../../api/axios";

const AgentDetail = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [agent, setAgent] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchAgent = async () => {
    try {
      const res = await api.get(`/admins/agent/${id}/`);
      setAgent(res.data.data);
    } catch (err) {
      console.error(err);
      alert("Failed to load agent details");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAgent();
  }, [id]);

  if (loading) {
    return (
      <DashboardLayout title="Agent Details">
        <div className="flex flex-col justify-center items-center h-96 space-y-4">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
          <p className="text-slate-500 font-medium">Fetching agent profile...</p>
        </div>
      </DashboardLayout>
    );
  }

  if (!agent) {
    return (
      <DashboardLayout title="Agent Details">
        <div className="flex justify-center items-center h-96">
          <div className="text-center">
            <p className="text-xl text-slate-400 font-semibold">Agent not found</p>
            <button onClick={() => navigate(-1)} className="mt-4 text-indigo-600 hover:underline">Go Back</button>
          </div>
        </div>
      </DashboardLayout>
    );
  }

  const statusStyles = {
    APPROVED: "bg-emerald-100 text-emerald-700 border-emerald-200",
    PENDING: "bg-amber-100 text-amber-700 border-amber-200",
    REJECTED: "bg-rose-100 text-rose-700 border-rose-200",
  };

  return (
    <DashboardLayout
      title="Agent Application"
      headerAction={
        <button
          onClick={() => navigate(-1)}
          className="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 text-slate-700 rounded-xl hover:bg-slate-50 transition-all shadow-sm font-medium"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 19l-7-7m0 0l7-7m-7 7h18" /></svg>
          Back to List
        </button>
      }
    >
      <div className="max-w-6xl mx-auto space-y-6 pb-12">
        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          
          {/* Left Column: Profile Card */}
          <div className="lg:col-span-1 space-y-6">
            <div className="bg-white rounded-3xl p-8 border border-slate-200 shadow-sm flex flex-col items-center text-center">
              <div className="w-24 h-24 bg-gradient-to-tr from-indigo-500 to-purple-500 rounded-2xl flex items-center justify-center text-white text-3xl font-bold shadow-lg mb-4">
                {agent.full_name?.[0] || agent.email?.[0]?.toUpperCase()}
              </div>
              <h2 className="text-2xl font-bold text-slate-900 leading-tight">
                {agent.full_name || agent.email.split('@')[0]}
              </h2>
              <p className="text-slate-500 text-sm mb-6">{agent.email}</p>
              
              <div className={`px-4 py-1.5 rounded-full text-xs font-bold border uppercase tracking-wider ${statusStyles[agent.status] || "bg-gray-100 text-gray-600"}`}>
                {agent.status}
              </div>

              <div className="w-full border-t border-slate-100 mt-8 pt-8 space-y-4 text-left">
                <div>
                  <label className="text-[10px] uppercase tracking-widest font-bold text-slate-400">Phone Number</label>
                  <p className="text-slate-800 font-semibold">{agent.phone || "N/A"}</p>
                </div>
                {agent.reviewed_at && (
                  <div>
                    <label className="text-[10px] uppercase tracking-widest font-bold text-slate-400">Decision Date</label>
                    <p className="text-slate-800 font-semibold">{new Date(agent.reviewed_at).toLocaleDateString(undefined, { dateStyle: 'medium' })}</p>
                  </div>
                )}
              </div>
            </div>

            {/* Resume Quick Action */}
            {agent.resume && (
              <a
                href={agent.resume}
                target="_blank"
                rel="noopener noreferrer"
                className="group flex items-center justify-between p-4 bg-indigo-600 rounded-2xl text-white hover:bg-indigo-700 transition-all shadow-md shadow-indigo-100"
              >
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-white/20 rounded-lg">
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
                  </div>
                  <span className="font-bold">Main Resume</span>
                </div>
                <svg className="w-5 h-5 opacity-50 group-hover:opacity-100 group-hover:translate-x-1 transition-all" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M14 5l7 7m0 0l-7 7m7-7H3" /></svg>
              </a>
            )}
          </div>

          {/* Right Column: Information Bento */}
          <div className="lg:col-span-2 space-y-6">
            
            {/* Skills Card */}
            <div className="bg-white rounded-3xl p-8 border border-slate-200 shadow-sm">
              <div className="flex items-center gap-2 mb-6 text-indigo-600">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
                <h3 className="text-sm font-bold uppercase tracking-widest">Expertise & Skills</h3>
              </div>
              <p className="text-slate-700 leading-relaxed bg-slate-50 p-6 rounded-2xl border border-slate-100 italic">
                "{agent.skills}"
              </p>
            </div>

            {/* Certificates Grid */}
            <div className="bg-white rounded-3xl p-8 border border-slate-200 shadow-sm">
              <div className="flex items-center justify-between mb-8">
                <div className="flex items-center gap-2 text-indigo-600">
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4M7.835 4.697a3.42 3.42 0 001.946-.806 3.42 3.42 0 014.438 0 3.42 3.42 0 001.946.806 3.42 3.42 0 013.138 3.138 3.42 3.42 0 00.806 1.946 3.42 3.42 0 010 4.438 3.42 3.42 0 00-.806 1.946 3.42 3.42 0 01-3.138 3.138 3.42 3.42 0 00-1.946.806 3.42 3.42 0 01-4.438 0 3.42 3.42 0 00-1.946-.806 3.42 3.42 0 01-3.138-3.138 3.42 3.42 0 00-.806-1.946 3.42 3.42 0 010-4.438 3.42 3.42 0 00.806-1.946 3.42 3.42 0 013.138-3.138z" /></svg>
                  <h3 className="text-sm font-bold uppercase tracking-widest">Documented Certifications</h3>
                </div>
                <span className="text-xs bg-slate-100 text-slate-500 px-3 py-1 rounded-full font-bold">
                  {agent.certificates?.length || 0} TOTAL
                </span>
              </div>

              {agent.certificates?.length > 0 ? (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  {agent.certificates.map((url, index) => {
                    const correctUrl = url.replace('/image/upload', '/raw/upload');
                    return (
                      <a
                        key={index}
                        href={correctUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="group flex items-center gap-4 p-4 border border-slate-100 bg-slate-50/50 rounded-2xl hover:border-indigo-200 hover:bg-white hover:shadow-md transition-all"
                      >
                        <div className="w-12 h-12 bg-white rounded-xl flex items-center justify-center text-2xl shadow-sm border border-slate-100 group-hover:scale-110 transition-transform">
                          📜
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-bold text-slate-900 truncate">Certification {index + 1}</p>
                          <p className="text-[11px] text-slate-500 uppercase tracking-tight">Verified Document</p>
                        </div>
                        <svg className="w-4 h-4 text-slate-300 group-hover:text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" /></svg>
                      </a>
                    );
                  })}
                </div>
              ) : (
                <div className="text-center py-12 border-2 border-dashed border-slate-100 rounded-3xl">
                   <p className="text-slate-400 text-sm">No certifications uploaded</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default AgentDetail;