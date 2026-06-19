import { Route } from "react-router-dom";
import ProtectedRoute from "../auth/ProtectedRoute";

import ProfilePage from "../pages/tickets/user/ProfilePage";
import AboutTRS from "../pages/tickets/AboutTRS";
import NotificationsPage from "../components/NotificationsPage";
import VerifyTicketPage from "../pages/tickets/agent/VerifyTicketPage";

const roles = [
  "USER",
  "AGENT",
  "TEAM_LEAD",
  "MANAGER",
  "CLIENT",
  "ADMIN",
];

const commonRoutes = (
  <>
    <Route path="/profile" element={<ProtectedRoute role={roles}><ProfilePage /></ProtectedRoute>} />

    <Route path="/about" element={<ProtectedRoute role={roles}><AboutTRS /></ProtectedRoute>} />

    <Route path="/notifications" element={<ProtectedRoute role={roles}><NotificationsPage /></ProtectedRoute>} />

    <Route path="/tickets/:id/verify" element={<ProtectedRoute role={["AGENT","MANAGER","TEAM_LEAD"]}><VerifyTicketPage /></ProtectedRoute>} />
  </>
);

export default commonRoutes;