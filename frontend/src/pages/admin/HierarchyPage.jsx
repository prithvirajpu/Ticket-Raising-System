import React, { useState, useEffect } from "react";
import api from "../../api/axios";
import { assignHierarchy, getAllUsers, getHierarchy } from "../../services/ticketService";
import { notifyError, notifySuccess } from "../../utils/notify";
import { 
  Building2, 
  ShieldAlert, 
  Users, 
  Headphones,
  ChevronDown, 
  UserPlus,
  Network,
  Briefcase
} from "lucide-react";

const HierarchyPage = () => {
  const [users, setUsers] = useState([]);
  const [hierarchy, setHierarchy] = useState(null);
  const [form, setForm] = useState({  
    user_id: "",
    manager_id: "",
    team_lead_id: ""
  });
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchUsers();
    fetchHierarchy();
  }, []);

  const fetchUsers = async () => {
    try {
      const res = await getAllUsers();
      setUsers(res.users);
    } catch (error) {
      console.log(error);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      setLoading(true);
      const res = await assignHierarchy(form);
      notifySuccess(res.data.message);
      await fetchHierarchy();
      setForm({ user_id: "", manager_id: "", team_lead_id: "" });
      fetchUsers();
    } catch (err) {
      console.log(err);
      notifyError(err?.response?.data?.errors?.details || 'failed in the assign area')
    } finally {
      setLoading(false);
    }
  };

  const fetchHierarchy = async () => {
    const res = await getHierarchy();
    setHierarchy(res.data);
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start text-slate-800 antialiased">
      
      {/* LEFT SIDE: DESIGNER ASSIGN FORM (4 Columns) */}
      <div className="lg:col-span-5 bg-white rounded-2xl border border-slate-200/80 p-6 shadow-sm">
        <div className="flex items-center gap-3 border-b border-slate-100 pb-4 mb-6">
          <div className="p-2.5 bg-slate-50 rounded-xl border border-slate-200/60 text-slate-800 shadow-sm">
            <UserPlus className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-bold text-slate-900 tracking-tight">Assign Hierarchy</h2>
            <p className="text-xs text-slate-500">Link operational accounts to internal reporting structures</p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label className="block mb-1.5 text-[11px] font-bold text-slate-500 tracking-wider uppercase">
              Target Associate
            </label>
            <div className="relative group">
              <select
                className="w-full border border-slate-200 rounded-xl p-3 pl-3.5 text-sm bg-white hover:border-slate-300 focus:ring-4 focus:ring-slate-950/5 focus:border-slate-950 outline-none appearance-none pr-10 transition-all cursor-pointer font-medium text-slate-800 shadow-xs"
                value={form.user_id}
                onChange={(e) => setForm({ ...form, user_id: e.target.value })}
                required
              >
                <option value="" className="text-slate-400">Select reporting account</option>
                {users.map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.email} ({u.role})
                  </option>
                ))}
              </select>
              <ChevronDown className="w-4 h-4 text-slate-400 group-hover:text-slate-600 absolute right-3.5 top-1/2 -translate-y-1/2 pointer-events-none transition-colors" />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block mb-1.5 text-[11px] font-bold text-slate-500 tracking-wider uppercase">
                Reporting Manager
              </label>
              <div className="relative group">
                <select
                  className="w-full border border-slate-200 rounded-xl p-3 pl-3.5 text-sm bg-white hover:border-slate-300 focus:ring-4 focus:ring-slate-950/5 focus:border-slate-950 outline-none appearance-none pr-10 transition-all cursor-pointer font-medium text-slate-800 shadow-xs"
                  value={form.manager_id}
                  onChange={(e) => setForm({ ...form, manager_id: e.target.value })}
                >
                  <option value="" className="text-slate-400">Assign Manager</option>
                  {users
                    .filter((u) => u.role === "MANAGER")
                    .map((u) => (
                      <option key={u.id} value={u.id}>
                        {u.email}
                      </option>
                    ))}
                </select>
                <ChevronDown className="w-4 h-4 text-slate-400 group-hover:text-slate-600 absolute right-3.5 top-1/2 -translate-y-1/2 pointer-events-none transition-colors" />
              </div>
            </div>

            <div>
              <label className="block mb-1.5 text-[11px] font-bold text-slate-500 tracking-wider uppercase">
                Team Lead
              </label>
              <div className="relative group">
                <select
                  className="w-full border border-slate-200 rounded-xl p-3 pl-3.5 text-sm bg-white hover:border-slate-300 focus:ring-4 focus:ring-slate-950/5 focus:border-slate-950 outline-none appearance-none pr-10 transition-all cursor-pointer font-medium text-slate-800 shadow-xs"
                  value={form.team_lead_id}
                  onChange={(e) => setForm({ ...form, team_lead_id: e.target.value })}
                >
                  <option value="" className="text-slate-400">Assign Team Lead</option>
                  {users
                    .filter((u) => u.role === "TEAM_LEAD")
                    .map((u) => (
                      <option key={u.id} value={u.id}>
                        {u.email}
                      </option>
                    ))}
                </select>
                <ChevronDown className="w-4 h-4 text-slate-400 group-hover:text-slate-600 absolute right-3.5 top-1/2 -translate-y-1/2 pointer-events-none transition-colors" />
              </div>
            </div>
          </div>

          <div className="pt-2">
            <button
              type="submit"
              disabled={loading}
              className="w-full bg-slate-950 text-white py-3 px-4 rounded-xl text-sm font-semibold hover:bg-slate-800 active:scale-[0.99] shadow-sm hover:shadow transition-all disabled:bg-slate-100 disabled:text-slate-400 disabled:pointer-events-none"
            >
              {loading ? 'Committing Changes...' : 'Assign Hierarchy Matrix'}
            </button>
          </div>
        </form>
      </div>

      {/* RIGHT SIDE: TREE VISUALIZATION (7 Columns) */}
      <div className="lg:col-span-7 h-full">
        {hierarchy ? (
          <div className="bg-white rounded-2xl border border-slate-200/80 p-6 shadow-sm h-full flex flex-col">
            <div className="flex items-center gap-3 border-b border-slate-100 pb-4 mb-8">
              <div className="p-2.5 bg-slate-50 rounded-xl border border-slate-200/60 text-slate-800 shadow-sm">
                <Network className="w-5 h-5" />
              </div>
              <div>
                <h2 className="text-base font-bold text-slate-900 tracking-tight">Current Client Hierarchy</h2>
                <p className="text-xs text-slate-500">Live configuration of organizational reporting layers</p>
              </div>
            </div>

            <div className="flex flex-col items-center flex-grow justify-center py-4">
              {/* CLIENT NODE */}
              <div className="bg-slate-950 text-white px-5 py-3 rounded-xl shadow-md border border-slate-900 flex items-center gap-3.5 min-w-[260px] transform transition-transform hover:scale-[1.01]">
                <div className="p-2 bg-white/10 rounded-lg border border-white/5">
                  <Building2 className="w-4 h-4 text-slate-100" />
                </div>
                <div>
                  <p className="text-[10px] uppercase font-bold tracking-wider text-slate-400 leading-none mb-1">Corporate Tenant</p>
                  <h4 className="text-sm font-bold text-white tracking-tight">{hierarchy.client.company_name}</h4>
                </div>
              </div>

              <div className="h-8 w-px bg-slate-200" />

              {/* MANAGER NODE */}
              {hierarchy.manager && (
                <>
                  <div className="bg-white border border-slate-200 shadow-xs px-5 py-3 rounded-xl flex items-center gap-3.5 min-w-[260px] transform transition-transform hover:scale-[1.01]">
                    <div className="p-2 bg-rose-50 text-rose-600 rounded-lg border border-rose-100/60">
                      <ShieldAlert className="w-4 h-4" />
                    </div>
                    <div>
                      <p className="text-[10px] uppercase font-bold tracking-wider text-slate-400 leading-none mb-1">Manager Layer</p>
                      <h4 className="text-sm font-semibold text-slate-900 tracking-tight">{hierarchy.manager.email}</h4>
                    </div>
                  </div>
                  <div className="h-8 w-px bg-slate-200" />
                </>
              )}

              {/* TEAM LEAD NODE */}
              {hierarchy.team_lead && (
                <>
                  <div className="bg-white border border-slate-200 shadow-xs px-5 py-3 rounded-xl flex items-center gap-3.5 min-w-[260px] transform transition-transform hover:scale-[1.01]">
                    <div className="p-2 bg-amber-50 text-amber-600 rounded-lg border border-amber-100/60">
                      <Users className="w-4 h-4" />
                    </div>
                    <div>
                      <p className="text-[10px] uppercase font-bold tracking-wider text-slate-400 leading-none mb-1">Team Lead Layer</p>
                      <h4 className="text-sm font-semibold text-slate-900 tracking-tight">{hierarchy.team_lead.email}</h4>
                    </div>
                  </div>
                  <div className="h-8 w-px bg-slate-200" />
                </>
              )}

              {/* AGENTS SECTION */}
              <div className="w-full pt-1">
                <div className="text-center mb-4">
                  <span className="text-[10px] uppercase font-bold tracking-wider text-slate-500 bg-slate-50 border border-slate-200 px-3 py-1 rounded-full shadow-xs">
                    Assigned Operating Agents ({hierarchy.agents.length})
                  </span>
                </div>
                
                <div className="flex flex-wrap justify-center gap-2.5 max-w-xl mx-auto">
                  {hierarchy.agents.map(agent => (
                    <div
                      key={agent.id}
                      className="bg-slate-50/50 hover:bg-slate-50 border border-slate-200/80 hover:border-slate-300 rounded-xl px-3.5 py-2.5 flex items-center gap-2.5 min-w-[190px] transition-all group"
                    >
                      <div className="p-1.5 bg-white border border-slate-200/80 rounded-lg text-emerald-600 shadow-xs group-hover:scale-105 transition-transform">
                        <Headphones className="w-3.5 h-3.5" />
                      </div>
                      <span className="text-xs font-semibold text-slate-700 truncate max-w-[130px]">
                        {agent.email}
                      </span>
                    </div>
                  ))}
                  {hierarchy.agents.length === 0 && (
                    <p className="text-xs text-slate-400 italic py-2">No front-line operators currently mapped onto this flow layer.</p>
                  )}
                </div>
              </div>

            </div>
          </div>
        ) : (
          <div className="bg-white rounded-2xl border border-dashed border-slate-200 p-8 text-center text-sm text-slate-400 italic h-full flex flex-col items-center justify-center min-h-[350px]">
            <Briefcase className="w-8 h-8 text-slate-300 mb-2.5 stroke-[1.5]" />
            <span>No reporting structure mapped yet. Link records using the deployment tool left.</span>
          </div>
        )}
      </div>

    </div>
  );
};

export default HierarchyPage;