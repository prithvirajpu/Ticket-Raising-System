import { Navigate } from "react-router-dom";
import { useAuth } from './AuthContext';

const ProtectedRoute = ({ children, role }) => {
  const { userRole, loading, profileCompleted, approvalStatus } = useAuth();
  if (loading) return null;

  if (!userRole) return <Navigate to='/' replace />;
  if (role && !role.includes(userRole)) return <Navigate to='/unauthorized' replace />;

  if (!profileCompleted) {
    if (userRole === "CLIENT") return <Navigate to="/client/complete-profile" replace />;
    if (userRole === "AGENT") return <Navigate to="/agent/complete-profile" replace />;
  }

  if (userRole === "AGENT" && profileCompleted && approvalStatus !== "APPROVED") {
    return <Navigate to="/" replace />;
  }

  return children;
};

export default ProtectedRoute;