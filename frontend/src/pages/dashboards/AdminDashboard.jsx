import React, { useEffect, useState } from "react";
import DashboardLayout from "../../layouts/DashboardLayout";
import Loader from "../../components/modals/Loader";
import { getAdminDashboard } from "../../services/ticketService";
import { Ticket, Users, Wallet, Clock, ChevronDown } from "lucide-react";
import {
  ResponsiveContainer, PieChart, Pie, Cell, Tooltip,
  Legend, LineChart, Line, CartesianGrid, XAxis, YAxis
} from "recharts";

// A more elegant, modern color palette
const COLORS = ["#4f46e5", "#f59e0b", "#10b981", "#ef4444"];

const AdminDashboard = () => {
  const [dashboard, setDashboard] = useState(null);
  const [period, setPeriod] = useState("7d");

  useEffect(() => {
    fetchDashboard();
  }, [period]);

  const fetchDashboard = async () => {
    const res = await getAdminDashboard(period);
    console.log(res.reports);
    setDashboard(res);
  };

  if (!dashboard) return <Loader />;

  const pieData = dashboard.reports.ticket_status.labels.map((label, index) => ({
    name: label,
    value: dashboard.reports.ticket_status.datasets[0].data[index],
  }));

  const lineData = dashboard.reports.ticket_trend.labels.map((label, index) => ({
    day: label,
    tickets: dashboard.reports.ticket_trend.datasets[0].data[index],
  }));

  return (
    <DashboardLayout title="Admin Dashboard">
      {/* HEADER / FILTER */}
      <div className="flex justify-end mb-8">
        <div className="relative inline-block w-48">
          <select
            value={period}
            onChange={(e) => setPeriod(e.target.value)}
            className="w-full appearance-none bg-white border border-slate-200 text-slate-700 px-4 py-2.5 pr-10 rounded-xl text-sm font-medium shadow-sm transition-all hover:border-slate-300 focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
          >
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
            <option value="12m">Last 12 Months</option>
          </select>
          <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-3 text-slate-500">
            <ChevronDown size={16} />
          </div>
        </div>
      </div>

      <div className="space-y-8">
        {/* KPI CARDS */}
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
          {/* Total Tickets */}
          <div className="bg-white rounded-2xl border border-slate-100 p-6 shadow-sm transition-all hover:shadow-md">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Tickets</p>
                <h2 className="text-3xl font-bold mt-2 text-slate-900 tracking-tight">
                  {dashboard.tickets.total}
                </h2>
              </div>
              <div className="p-3 bg-blue-50 text-blue-600 rounded-xl">
                <Ticket size={24} />
              </div>
            </div>
          </div>

          {/* Users */}
          <div className="bg-white rounded-2xl border border-slate-100 p-6 shadow-sm transition-all hover:shadow-md">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Users</p>
                <h2 className="text-3xl font-bold mt-2 text-slate-900 tracking-tight">
                  {dashboard.users.total}
                </h2>
              </div>
              <div className="p-3 bg-emerald-50 text-emerald-600 rounded-xl">
                <Users size={24} />
              </div>
            </div>
          </div>

          {/* Wallet Balance */}
          <div className="bg-white rounded-2xl border border-slate-100 p-6 shadow-sm transition-all hover:shadow-md">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Wallet Balance</p>
                <h2 className="text-3xl font-bold mt-2 text-slate-900 tracking-tight">
                  ${dashboard.wallet.wallet_balance}
                </h2>
              </div>
              <div className="p-3 bg-indigo-50 text-indigo-600 rounded-xl">
                <Wallet size={24} />
              </div>
            </div>
          </div>

          {/* Pending Withdrawals */}
          <div className="bg-white rounded-2xl border border-slate-100 p-6 shadow-sm transition-all hover:shadow-md">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Pending Withdrawals</p>
                <h2 className="text-3xl font-bold mt-2 text-slate-900 tracking-tight">
                  {dashboard.wallet.pending_withdrawals}
                </h2>
              </div>
              <div className="p-3 bg-amber-50 text-amber-600 rounded-xl">
                <Clock size={24} />
              </div>
            </div>
          </div>
        </div>

        {/* CHARTS */}
        <div className="grid xl:grid-cols-2 gap-8">
          {/* PIE CHART */}
          <div className="bg-white rounded-2xl border border-slate-100 shadow-sm p-6">
            <h2 className="text-base font-semibold text-slate-900 mb-6">Ticket Status Breakdown</h2>
            <ResponsiveContainer width="100%" height={320}>
              <PieChart>
                <Pie
                  data={pieData}
                  dataKey="value"
                  nameKey="name"
                  outerRadius={100}
                  innerRadius={60} // Turned into an elegant donut chart
                  paddingAngle={4}
                >
                  {pieData.map((entry, index) => (
                    <Cell key={index} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: '#fff', borderRadius: '12px', border: '1px solid #f1f5f9', shadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
                />
                <Legend iconType="circle" wrapperStyle={{ paddingTop: '10px', fontSize: '14px' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>

          {/* LINE CHART */}
          <div className="bg-white rounded-2xl border border-slate-100 shadow-sm p-6">
            <h2 className="text-base font-semibold text-slate-900 mb-6">Ticket Trend</h2>
            <ResponsiveContainer width="100%" height={320}>
              <LineChart data={lineData} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
                <XAxis dataKey="day" stroke="#94a3b8" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="#94a3b8" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#fff', borderRadius: '12px', border: '1px solid #f1f5f9' }}
                />
                <Line
                  type="monotone"
                  dataKey="tickets"
                  stroke="#4f46e5"
                  strokeWidth={3}
                  dot={{ r: 4, strokeWidth: 2 }}
                  activeDot={{ r: 6 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* DETAILS SECTION */}
        <div className="grid xl:grid-cols-2 gap-8">
          {/* User Distribution */}
          <div className="bg-white rounded-2xl border border-slate-100 shadow-sm p-6">
            <h2 className="text-base font-semibold text-slate-900 mb-4">User Distribution</h2>
            <div className="divide-y divide-slate-100">
              {[
                { label: "Customers", value: dashboard.users.customers },
                { label: "Clients", value: dashboard.users.clients },
                { label: "Agents", value: dashboard.users.agents },
                { label: "Team Leads", value: dashboard.users.team_leads },
                { label: "Managers", value: dashboard.users.managers },
              ].map((item, idx) => (
                <div key={idx} className="flex justify-between items-center py-3.5 hover:bg-slate-50/50 px-2 rounded-xl transition-colors">
                  <span className="text-sm font-medium text-slate-600">{item.label}</span>
                  <span className="text-sm font-semibold text-slate-900 bg-slate-100 px-3 py-1 rounded-full">{item.value}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Wallet Summary */}
          <div className="bg-white rounded-2xl border border-slate-100 shadow-sm p-6">
            <h2 className="text-base font-semibold text-slate-900 mb-4">Wallet Summary</h2>
            <div className="divide-y divide-slate-100">
              <div className="flex justify-between items-center py-3.5 hover:bg-slate-50/50 px-2 rounded-xl transition-colors">
                <span className="text-sm font-medium text-slate-600">Total Wallet Balance</span>
                <span className="text-sm font-bold text-emerald-600">${dashboard.wallet.wallet_balance}</span>
              </div>
              <div className="flex justify-between items-center py-3.5 hover:bg-slate-50/50 px-2 rounded-xl transition-colors">
                <span className="text-sm font-medium text-slate-600">Pending Withdrawals</span>
                <span className="text-sm font-semibold text-amber-600">{dashboard.wallet.pending_withdrawals}</span>
              </div>
              <div className="flex justify-between items-center py-3.5 hover:bg-slate-50/50 px-2 rounded-xl transition-colors">
                <span className="text-sm font-medium text-slate-600">Approved Withdrawals</span>
                <span className="text-sm font-semibold text-slate-900 bg-slate-100 px-3 py-1 rounded-full">{dashboard.wallet.approved_withdrawals}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default AdminDashboard;