import { Route } from "react-router-dom";
import ProtectedRoute from "../auth/ProtectedRoute";

import UserDashboard from "../pages/dashboards/UserDashboard";
import CreateTicket from "../pages/tickets/user/CreateTicket";
import TicketsList from "../pages/tickets/user/TicketsList";
import TicketDetail from "../pages/tickets/user/TicketDetail";

const userRoutes = (
  <>
    <Route path="/user/dashboard" element={<ProtectedRoute role={["USER"]}><UserDashboard /></ProtectedRoute>} />

    <Route path="/user/create-ticket" element={<ProtectedRoute role={["USER"]}><CreateTicket /></ProtectedRoute>} />

    <Route path="/user/tickets" element={<ProtectedRoute role={["USER"]}><TicketsList /></ProtectedRoute>} />

    <Route path="/user/tickets/details/:id" element={<ProtectedRoute role={["USER"]}><TicketDetail /></ProtectedRoute>} />
  </>
);

export default userRoutes;