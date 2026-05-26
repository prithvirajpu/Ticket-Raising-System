import React, { useState, useEffect } from "react";
import api from "../../api/axios";
import { assignHierarchy, getAllUsers } from "../../services/ticketService";
import { notifySuccess } from "../../utils/notify";

const HierarchyPage = () => {
  const [users, setUsers] = useState([]);
  const [form, setForm] = useState({  
    user_id: "",
    manager_id: "",
    team_lead_id: ""
  });
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      const res = await getAllUsers()
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
      setForm({ user_id: "", manager_id: "", team_lead_id: "" });
      fetchUsers();
    } catch (err) {
      console.log(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-white rounded-2xl shadow p-6">
      <div className="border-b pb-3 mb-5">
        <h2 className="text-lg font-bold text-gray-900">Assign Hierarchy</h2>
        <p className="text-xs text-gray-500">Link users to their respective reporting authorities</p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Main Target User - Full Width */}
        <div>
          <label className="block mb-1.5 text-xs font-semibold text-gray-700">Target User</label>
          <select
            className="w-full border border-gray-200 rounded-lg p-2.5 text-sm bg-white focus:ring-2 focus:ring-black/5 focus:border-black outline-none"
            value={form.user_id}
            onChange={(e) => setForm({ ...form, user_id: e.target.value })}
            required
          >
            <option value="">Select User</option>
            {users.map((u) => (
              <option key={u.id} value={u.id}>
                {u.email} ({u.role})
              </option>
            ))}
          </select>
        </div>

        {/* Dynamic 2-Column Grid for Authorities */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="block mb-1.5 text-xs font-semibold text-gray-700">Manager</label>
            <select
              className="w-full border border-gray-200 rounded-lg p-2.5 text-sm bg-white focus:ring-2 focus:ring-black/5 focus:border-black outline-none"
              value={form.manager_id}
              onChange={(e) => setForm({ ...form, manager_id: e.target.value })}
            >
              <option value="">Select Manager</option>
              {users
                .filter((u) => u.role === "MANAGER")
                .map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.email}
                  </option>
                ))}
            </select>
          </div>

          <div>
            <label className="block mb-1.5 text-xs font-semibold text-gray-700">Team Lead</label>
            <select
              className="w-full border border-gray-200 rounded-lg p-2.5 text-sm bg-white focus:ring-2 focus:ring-black/5 focus:border-black outline-none"
              value={form.team_lead_id}
              onChange={(e) => setForm({ ...form, team_lead_id: e.target.value })}
            >
              <option value="">Select Team Lead</option>
              {users
                .filter((u) => u.role === "TEAM_LEAD")
                .map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.email}
                  </option>
                ))}
            </select>
          </div>
        </div>

        <div className="pt-2">
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-black text-white py-2.5 rounded-lg text-sm font-medium hover:bg-gray-800 transition-colors disabled:bg-gray-400"
          >
            {loading ? 'Assigning...' : 'Assign Hierarchy'}
          </button>
        </div>
      </form>
    </div>
  );
};

export default HierarchyPage;