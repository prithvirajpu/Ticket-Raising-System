import { Route } from "react-router-dom";
import ProtectedRoute from "../auth/ProtectedRoute";

import ManagerDashboard from "../pages/dashboards/ManagerDashboard";
import ManagerTickets from "../pages/tickets/manager/ManagerTickets";
import ManagerTicketDetail from "../pages/tickets/manager/ManagerTicketDetail";
import ClientListPage from "../pages/tickets/manager/ClientListPage";
import ClientDocumentsPage from "../pages/tickets/manager/ClientDocumentsPage";
import SummaryPage from "../pages/tickets/manager/SummaryPage";

const managerRoutes = (
  <>
    <Route path="/manager/dashboard" element={<ProtectedRoute role={["MANAGER"]}><ManagerDashboard /></ProtectedRoute>} />

    <Route path="/tickets/manager/tickets" element={<ProtectedRoute role={["MANAGER"]}><ManagerTickets /></ProtectedRoute>} />

    <Route path="/manager/tickets/:id" element={<ProtectedRoute role={["MANAGER"]}><ManagerTicketDetail /></ProtectedRoute>} />

    <Route path="/manager/clients" element={<ProtectedRoute role={["MANAGER"]}><ClientListPage /></ProtectedRoute>} />

    <Route path="/manager/client-docs/:client_id" element={<ProtectedRoute role={["MANAGER"]}><ClientDocumentsPage /></ProtectedRoute>} />

    <Route path="/summary" element={<ProtectedRoute role={["MANAGER"]}><SummaryPage /></ProtectedRoute>} />
  </>
);

export default managerRoutes;