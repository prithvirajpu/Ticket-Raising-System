import { Route } from "react-router-dom";
import ProtectedRoute from "../auth/ProtectedRoute";

import ClientDashboard from "../pages/dashboards/ClientDashboard";
import UploadFile from "../pages/tickets/client/UploadFile";
import SubscriptionPlans from "../pages/tickets/client/SubscriptionPlans";
import IntegrationGuide from "../pages/tickets/client/IntegrationGuide";
import SubscriptionSuccess from "../pages/tickets/client/SubscriptionSuccess";
import SubscriptionFailed from "../pages/tickets/client/SubscriptionFailed";

const clientRoutes = (
  <>
    <Route path="/client/dashboard" element={<ProtectedRoute role={["CLIENT"]}><ClientDashboard /></ProtectedRoute>} />

    <Route path="/client/upload" element={<ProtectedRoute role={["CLIENT"]}><UploadFile /></ProtectedRoute>} />

    <Route path="/client/plans" element={<ProtectedRoute role={["CLIENT"]}><SubscriptionPlans /></ProtectedRoute>} />

    <Route path="/client/guideline" element={<ProtectedRoute role={["CLIENT"]}><IntegrationGuide /></ProtectedRoute>} />

    <Route path="/subscription-success" element={<ProtectedRoute role={["CLIENT"]}><SubscriptionSuccess /></ProtectedRoute>} />

    <Route path="/subscription-cancel" element={<ProtectedRoute role={["CLIENT"]}><SubscriptionFailed /></ProtectedRoute>} />
  </>
);

export default clientRoutes;