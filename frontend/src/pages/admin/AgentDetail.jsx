import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import DashboardLayout from "../../layouts/DashboardLayout"; 
import api from "../../api/axios";
import { ArrowLeft, Mail, Phone, Calendar, FileText, Award, Zap, ExternalLink, Loader2, AlertCircle } from 'lucide-react';

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
      <DashboardLayout title="Agent Identity Profiles">
        <div className="flex flex-col justify-center items-center h-96 space-y-4 antialiased">
          <Loader2 className="h-10 w-10 animate-spin text-slate-950 stroke-[1.5]" />
          <p className="text-slate-500 font-medium text-sm tracking-wide">Syncing matrix infrastructure logs...</p>
        </div>
      </DashboardLayout>
    );
  }

  if (!agent) {
    return (
      <DashboardLayout title="Agent Identity Profiles">
        <div className="flex justify-center items-center h-96 antialiased">
          <div className="text-center space-y-4 max-w-sm bg-white p-6 rounded-2xl border border-slate-200 shadow-xs">
            <AlertCircle className="w-10 h-10 text-rose-500 mx-auto" />
            <div>
              <p className="text-lg font-bold text-slate-900 tracking-tight">Identity Record Missing</p>
              <p className="text-xs text-slate-500 mt-1">The specified operator identity record key could not be verified or retrieved.</p>
            </div>
            <button 
              onClick={() => navigate(-1)} 
              className="inline-flex items-center gap-1.5 text-xs font-bold text-slate-950 bg-slate-100 hover:bg-slate-200/80 px-4 py-2 rounded-xl transition-colors"
            >
              <ArrowLeft className="w-3.5 h-3.5" /> Return to Rosters
            </button>
          </div>
        </div>
      </DashboardLayout>
    );
  }

  const statusStyles = {
    APPROVED: "bg-emerald-50 text-emerald-700 border-emerald-200/50",
    PENDING: "bg-amber-50 text-amber-700 border-amber-200/50",
    REJECTED: "bg-rose-50 text-rose-700 border-rose-200/50",
  };

  return (
    <DashboardLayout
      title="Verification Details"
      headerAction={
        <button
          onClick={() => navigate(-1)}
          className="inline-flex items-center gap-2 px-4 py-2.5 bg-white border border-slate-200 text-slate-700 rounded-xl hover:bg-slate-50 active:scale-[0.99] transition-all shadow-xs text-xs font-bold"
        >
          <ArrowLeft className="w-3.5 h-3.5 text-slate-500" />
          <span>Back to Rosters</span>
        </button>
      }
    >
      <div className="max-w-6xl mx-auto space-y-6 pb-12 text-slate-800 antialiased">
        
        {/* MAIN STRUCTURAL BENTO BOX GRID */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          
          {/* PROFILE INSIGHT DECK */}
          <div className="lg:col-span-1 space-y-4">
            <div className="bg-white rounded-2xl p-6 border border-slate-200/80 shadow-sm flex flex-col items-center text-center">
              
              {/* GRADIENT IDENTICON MARKER */}
              <div className="w-20 h-20 bg-gradient-to-tr from-slate-900 to-slate-800 rounded-2xl flex items-center justify-center text-white text-2xl font-black shadow-md mb-4 tracking-tight">
                {agent.full_name?.[0] || agent.email?.[0]?.toUpperCase()}
              </div>

              <h2 className="text-xl font-bold text-slate-900 tracking-tight leading-tight">
                {agent.full_name || agent.email.split('@')[0]}
              </h2>
              <p className="text-slate-400 text-xs font-medium mt-1 mb-5">{agent.email}</p>
              
              {/* SYSTEM CLEARANCE INDICATOR BAR */}
              <div className={`px-3 py-1 rounded-full text-[10px] font-extrabold border uppercase tracking-widest ${statusStyles[agent.status] || "bg-slate-50 text-slate-500 border-slate-200"}`}>
                {agent.status}
              </div>

              {/* DETAILS FIELDS CONTAINER */}
              <div className="w-full border-t border-slate-100 mt-6 pt-5 space-y-4 text-left">
                <div>
                  <label className="inline-flex items-center gap-1.5 text-[10px] uppercase tracking-wider font-bold text-slate-400 mb-1">
                    <Phone className="w-3 h-3" /> Contact Sequence
                  </label>
                  <p className="text-slate-800 font-semibold text-sm">{agent.phone || "Unspecified"}</p>
                </div>
              </div>
            </div>

            {/* CURRICULUM VITAE ANCHOR DISPATCHER */}
            {agent.resume && (
              <a
                href={agent.resume}
                target="_blank"
                rel="noopener noreferrer"
                className="group flex items-center justify-between p-4 bg-slate-950 rounded-2xl text-white hover:bg-slate-800 active:scale-[0.99] transition-all shadow-xs"
              >
                <div className="flex items-center gap-3">
                  <div className="p-2.5 bg-white/10 rounded-xl">
                    <FileText className="w-4 h-4 text-white" />
                  </div>
                  <div>
                    <span className="font-bold text-sm block">Curriculum Vitae</span>
                    <span className="text-[10px] text-slate-400 font-medium block mt-0.5">Primary Dossier Link</span>
                  </div>
                </div>
                <ExternalLink className="w-4 h-4 text-slate-500 group-hover:text-white transition-colors mr-1" />
              </a>
            )}
          </div>

          {/* ATTRIBUTES METRIC SUBPANELS */}
          <div className="lg:col-span-2 space-y-4">
            
            {/* SPECIALIZED CAPABILITIES SHEET */}
            <div className="bg-white rounded-2xl p-6 border border-slate-200/80 shadow-sm">
              <div className="flex items-center gap-2 mb-4 text-slate-900">
                <div className="p-1.5 bg-slate-50 border border-slate-100 rounded-lg">
                  <Zap className="w-4 h-4 text-slate-500" />
                </div>
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500">Functional Capabilities & Matrix Expertise</h3>
              </div>
              <p className="text-slate-700 leading-relaxed bg-slate-50/60 p-5 rounded-xl border border-slate-200/40 text-sm font-medium italic">
                "{agent.skills}"
              </p>
            </div>

            {/* ACCREDITATIONS & CREDENTIALS SUB-MATRIX */}
            <div className="bg-white rounded-2xl p-6 border border-slate-200/80 shadow-sm">
              <div className="flex items-center justify-between mb-5">
                <div className="flex items-center gap-2 text-slate-900">
                  <div className="p-1.5 bg-slate-50 border border-slate-100 rounded-lg">
                    <Award className="w-4 h-4 text-slate-500" />
                  </div>
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500">Accredited Certifications</h3>
                </div>
                <span className="text-[10px] bg-slate-100 text-slate-600 px-2.5 py-0.5 rounded-md border border-slate-200/30 font-bold tracking-wider">
                  {agent.certificates?.length || 0} DEPLOYED
                </span>
              </div>

              {agent.certificates?.length > 0 ? (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {agent.certificates.map((url, index) => {
                    const correctUrl = url.replace('/image/upload', '/raw/upload');
                    return (
                      <a
                        key={index}
                        href={correctUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="group flex items-center gap-4 p-3.5 border border-slate-200/60 bg-white rounded-xl hover:border-slate-300 hover:bg-slate-50/40 hover:shadow-2xs transition-all"
                      >
                        <div className="w-10 h-10 bg-slate-50 border border-slate-100 rounded-xl flex items-center justify-center text-lg shadow-2xs group-hover:scale-105 transition-transform">
                          📜
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-xs font-bold text-slate-900 truncate">Certificate Asset {index + 1}</p>
                          <p className="text-[10px] text-slate-400 uppercase tracking-wider font-semibold mt-0.5">Verified Link</p>
                        </div>
                        <ExternalLink className="w-3.5 h-3.5 text-slate-300 group-hover:text-slate-950 transition-colors" />
                      </a>
                    );
                  })}
                </div>
              ) : (
                <div className="text-center py-10 border border-dashed border-slate-200 rounded-xl">
                  <p className="text-slate-400 text-xs font-medium">No verified credentials uploaded to this profile layout.</p>
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