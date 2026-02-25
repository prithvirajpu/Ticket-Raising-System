import { Navigate } from "react-router-dom"
import {useAuth} from './AuthContext'

const ProtectedRoute = ({children,role}) => {
    const {userRole}=useAuth();

    if (!userRole) return <Navigate to='/' replace/>
    if(role && !role.includes(userRole))
        return <Navigate to='/unauthorized' replace />

  return children
}

export default ProtectedRoute
