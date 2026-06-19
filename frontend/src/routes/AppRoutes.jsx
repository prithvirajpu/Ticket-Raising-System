import { Routes } from "react-router-dom";

import publicRoutes from "./PublicRoutes";
import adminRoutes from "./AdminRoutes";
import clientRoutes from "./ClientRoutes";
import managerRoutes from "./ManagerRoutes";
import teamLeadRoutes from "./TeamLeadRoutes";
import agentRoutes from "./AgentRoutes";
import userRoutes from "./UserRoutes";
import commonRoutes from "./CommonRoutes";

const AppRoutes = () => {
  return (
    <Routes>
      {publicRoutes}
      {adminRoutes}
      {clientRoutes}
      {managerRoutes}
      {teamLeadRoutes}
      {agentRoutes}
      {userRoutes}
      {commonRoutes}
    </Routes>
  );
};

export default AppRoutes;