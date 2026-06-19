import { Route } from "react-router-dom";
import ProtectedRoute from "../auth/ProtectedRoute";

import AgentDashboard from "../pages/dashboards/AgentDashboard";
import AgentRequests from "../pages/tickets/agent/AgentRequests";
import AgentOngoing from "../pages/tickets/agent/AgentOngoing";
import AgentTicketDetail from "../pages/tickets/agent/AgentTicketDetail";
import AgentSummary from "../pages/tickets/agent/AgentSummary";
import AgentFakeTicketsPage from "../pages/tickets/agent/AgentFakeTicketsPage";
import AgentFakeTicketDetail from "../pages/tickets/agent/AgentFakeTicketDetail";

const agentRoutes = (
  <>
    <Route path="/agent/dashboard" element={<ProtectedRoute role={["AGENT"]}><AgentDashboard /></ProtectedRoute>} />

    <Route path="/agents/requests" element={<ProtectedRoute role={["AGENT"]}><AgentRequests /></ProtectedRoute>} />

    <Route path="/agent/assigned-tickets" element={<ProtectedRoute role={["AGENT"]}><AgentOngoing /></ProtectedRoute>} />

    <Route path="/agent/ticket-detail/:id" element={<ProtectedRoute role={["AGENT"]}><AgentTicketDetail /></ProtectedRoute>} />

    <Route path="/agent/summary" element={<ProtectedRoute role={["AGENT"]}><AgentSummary /></ProtectedRoute>} />

    <Route path="/agent/practice" element={<ProtectedRoute role={["AGENT"]}><AgentFakeTicketsPage /></ProtectedRoute>} />

    <Route path="/agent/fake-tickets/:id" element={<ProtectedRoute role={["AGENT"]}><AgentFakeTicketDetail /></ProtectedRoute>} />
  </>
);

export default agentRoutes;