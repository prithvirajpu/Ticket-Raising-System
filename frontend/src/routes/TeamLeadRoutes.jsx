import { Route } from "react-router-dom";
import ProtectedRoute from "../auth/ProtectedRoute";

import TeamLeadDashboard from "../pages/dashboards/TeamLeadDashboard";
import TeamLeadTickets from "../pages/tickets/team_lead/TeamLeadTickets";
import TeamLeadTicketDetail from "../pages/tickets/team_lead/TeamLeadTicketDetail";
import TeamLeadSummaryPage from "../pages/tickets/team_lead/TeamLeadSummaryPage";
import AgentSummaryPage from "../pages/tickets/team_lead/AgentSummaryPage";

const teamLeadRoutes = (
  <>
    <Route path="/team-lead/dashboard" element={<ProtectedRoute role={["TEAM_LEAD"]}><TeamLeadDashboard /></ProtectedRoute>} />

    <Route path="/team-lead/assigned-tickets" element={<ProtectedRoute role={["TEAM_LEAD"]}><TeamLeadTickets /></ProtectedRoute>} />

    <Route path="/team-lead/tickets/:id" element={<ProtectedRoute role={["TEAM_LEAD"]}><TeamLeadTicketDetail /></ProtectedRoute>} />

    <Route path="/team-lead/summaries" element={<ProtectedRoute role={["TEAM_LEAD"]}><TeamLeadSummaryPage /></ProtectedRoute>} />

    <Route path="/agent-summary/:summary_id" element={<ProtectedRoute role={["TEAM_LEAD"]}><AgentSummaryPage /></ProtectedRoute>} />
  </>
);

export default teamLeadRoutes;