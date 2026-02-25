import {BrowserRouter,Routes,Route} from 'react-router-dom'
import { AuthProvider } from './auth/AuthContext'
import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import Login from './pages/Login'
import ProtectedRoute from './auth/ProtectedRoute'
import AdminDashboard from './pages/dashboards/AdminDashboard'
import AgentDashboard from './pages/dashboards/AgentDashboard'
import ClientDashboard from './pages/dashboards/ClientDashboard'
import Unauthorized from './pages/Unauthorized'
import StaffSignup from './pages/signup/StaffSignup'
import ClientSignup from './pages/signup/ClientSignup'
import VerifyOtp from './pages/signup/VerifyOtp'
import ForgotPassword from './pages/signup/ForgotPassword'
import ResetPassword from './pages/signup/ResetPassword'
import AgentDetail from './pages/admin/AgentDetail'
import CompleteProfile from './pages/signup/CompleteProfile'
import AgentCompleteProfile from './pages/signup/AgentCompleteProfile '
import UserDashboard from './pages/dashboards/UserDashboard'
import AgentManagement from './pages/admin/AgentManagement';
import ClientManagement from './pages/admin/ClientManagement';
import PendingUsers from './pages/admin/PendingUsers';



const App = () => {
  return (
    <AuthProvider>
        <BrowserRouter>
        <ToastContainer position="top-right" autoClose={2500} hideProgressBar newestOnTop 
        closeOnClick pauseOnHover draggable={false} theme="light" toastStyle={{
            borderRadius: "10px",
            fontSize: "14px",
            padding: "12px",
            width: "300px", }}/>

        <Routes>
            <Route path='/signup' element={<StaffSignup/>}/>
            <Route path='/verify-otp' element={<VerifyOtp />} />
            <Route path='/forgot-password' element={<ForgotPassword/>}/>
            <Route path='/reset-password' element={<ResetPassword/>}/>
            <Route path='/client-signup' element={<ClientSignup/>}/>
            <Route path='/client/complete-profile' element={<CompleteProfile/>}/>
            <Route path='/agent/complete-profile' element={<AgentCompleteProfile/>}/>
            <Route path='/' element={<Login/>} />
            <Route path='/unauthorized' element={<Unauthorized/>} />
            <Route path='/admin/dashboard' element={<ProtectedRoute role={['ADMIN']}>
                <AdminDashboard />
            </ProtectedRoute>} />
            <Route path='/client/dashboard' element={<ProtectedRoute role={['CLIENT']}>
                <ClientDashboard />
            </ProtectedRoute>} />
            <Route path='/agent/dashboard' element={<ProtectedRoute role={['AGENT']}>
                <AgentDashboard />
            </ProtectedRoute>} />
            <Route path='/team-lead/dashboard' element={<ProtectedRoute role={['TEAM_LEAD']}>
                <AgentDashboard />
            </ProtectedRoute>} />
            <Route path='/manager/dashboard' element={<ProtectedRoute role={['MANAGER']}>
                <AgentDashboard />
            </ProtectedRoute>} />
            <Route path='/user/dashboard' element={<ProtectedRoute role={['USER']}>
                <UserDashboard />
            </ProtectedRoute>} />
            <Route path='/admin/agent/:id' element={<ProtectedRoute role={['ADMIN']}>
                 <AgentDetail />
            </ProtectedRoute>} />
            <Route path='/admin/agent-manage' element={<ProtectedRoute role={['ADMIN']}>
                 <AgentManagement />
            </ProtectedRoute>} />
            <Route path='/admin/client-manage' element={<ProtectedRoute role={['ADMIN']}>
                 <ClientManagement />
            </ProtectedRoute>} />
            <Route path='/admin/pending-req' element={<ProtectedRoute role={['ADMIN']}>
                 <PendingUsers />
            </ProtectedRoute>} />
           
        </Routes>
        </BrowserRouter>
    </AuthProvider>
  )
}

export default App
