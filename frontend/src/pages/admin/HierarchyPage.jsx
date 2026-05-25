import React, { useState, useEffect } from "react";
import api from "../../api/axios";
import { assignHierarchy } from "../../services/ticketService";

const HierarchyPage = () => {
  const [users, setUsers] = useState([]);
  const [form, setForm] = useState({
    user_id: "",
    manager_id: "",
    team_lead_id: ""
  });

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    const res = await api.get("/admins/users/all/");
    setUsers(res.data.data.users);
  };

  const handleSubmit = async () => {
    try {
      const res = await assignHierarchy(form);
      alert(res.data.message);
      fetchUsers();
    } catch (err) {
      console.log(err);
    }
  };

  return (
    <div className="p-6">
      <h2 className="text-xl font-bold mb-4">Assign Hierarchy</h2>

      {/* USER SELECT */}
      <select
        className="border p-2 mb-2 w-full"
        onChange={(e) =>
          setForm({ ...form, user_id: e.target.value })
        }
      >
        <option>Select User</option>
        {users.map((u) => (
          <option key={u.id} value={u.id}>
            {u.email} ({u.role})
          </option>
        ))}
      </select>

      {/* MANAGER */}
      <select
        className="border p-2 mb-2 w-full"
        onChange={(e) =>
          setForm({ ...form, manager_id: e.target.value })
        }
      >
        <option>Select Manager</option>
        {users
          .filter((u) => u.role === "MANAGER")
          .map((u) => (
            <option key={u.id} value={u.id}>
              {u.email}
            </option>
          ))}
      </select>

      {/* TEAM LEAD */}
      <select
        className="border p-2 mb-2 w-full"
        onChange={(e) =>
          setForm({ ...form, team_lead_id: e.target.value })
        }
      >
        <option>Select Team Lead</option>
        {users
          .filter((u) => u.role === "TEAM_LEAD")
          .map((u) => (
            <option key={u.id} value={u.id}>
              {u.email}
            </option>
          ))}
      </select>

      <button
        onClick={handleSubmit}
        className="bg-blue-600 text-white px-4 py-2 rounded"
      >
        Assign
      </button>
    </div>
  );
};

export default HierarchyPage;