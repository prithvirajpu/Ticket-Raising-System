import { Navigate } from "react-router-dom";
import { useAuth } from "./AuthContext"
import { redirectByRole } from "./roleRedirect";

const PublicRoute = ({children}) => {
    const {userRole,isAuthenticated}=useAuth();
    if (isAuthenticated){
        return <Navigate to={redirectByRole(userRole)}  replace />
    }
  return children
}

export default PublicRoute
