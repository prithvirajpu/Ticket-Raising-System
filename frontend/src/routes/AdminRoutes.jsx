import { Route } from "react-router-dom";
import ProtectedRoute from "../auth/ProtectedRoute";

import AdminDashboard from "../pages/dashboards/AdminDashboard";
import AgentDetail from "../pages/admin/AgentDetail";
import AgentManagement from "../pages/admin/AgentManagement";
import ClientManagement from "../pages/admin/ClientManagement";
import PendingUsers from "../pages/admin/PendingUsers";
import SlaRules from "../pages/admin/SlaRules";
import UserManagement from "../pages/admin/UserManagement";
import HierarchyPage from "../pages/admin/HierarchyPage";
import WithdrawalRequestsPage from "../pages/admin/WithdrawalRequestsPage";

const adminRoutes = (
  <>
    <Route path="/admin/dashboard" element={<ProtectedRoute role={["ADMIN"]}><AdminDashboard /></ProtectedRoute>} />

    <Route path="/admin/agent/:id" element={<ProtectedRoute role={["ADMIN"]}><AgentDetail /></ProtectedRoute>} />

    <Route path="/admin/agent-manage" element={<ProtectedRoute role={["ADMIN"]}><AgentManagement /></ProtectedRoute>} />

    <Route path="/admin/client-manage" element={<ProtectedRoute role={["ADMIN"]}><ClientManagement /></ProtectedRoute>} />

    <Route path="/admin/pending-req" element={<ProtectedRoute role={["ADMIN"]}><PendingUsers /></ProtectedRoute>} />

    <Route path="/admin/sla" element={<ProtectedRoute role={["ADMIN"]}><SlaRules /></ProtectedRoute>} />

    <Route path="/admin/user-manage" element={<ProtectedRoute role={["ADMIN"]}><UserManagement /></ProtectedRoute>} />

    <Route path="/admin/hierarchy" element={<ProtectedRoute role={["ADMIN"]}><HierarchyPage /></ProtectedRoute>} />

    <Route path="/admin/wallet-system" element={<ProtectedRoute role={["ADMIN"]}><WithdrawalRequestsPage /></ProtectedRoute>} />
  </>
);

export default adminRoutes;