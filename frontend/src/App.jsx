import {BrowserRouter,Routes,Route} from 'react-router-dom'
import { AuthProvider } from './auth/AuthContext'
import {CallProvider} from './auth/CallContext'
import { ToastContainer } from "react-toastify"
import "react-toastify/dist/ReactToastify.css"
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
import AgentCompleteProfile from './pages/signup/AgentCompleteProfile'
import UserDashboard from './pages/dashboards/UserDashboard'
import AgentManagement from './pages/admin/AgentManagement';
import ClientManagement from './pages/admin/ClientManagement';
import PendingUsers from './pages/admin/PendingUsers';
import PublicRoute from './auth/PublicRoute';
import CreateTicket from './pages/tickets/user/CreateTicket';
import TicketsList from './pages/tickets/user/TicketsList';
import TicketDetail from './pages/tickets/user/TicketDetail';
import AgentRequests from './pages/tickets/agent/AgentRequests';
import AgentOngoing from './pages/tickets/agent/AgentOngoing';
import AgentTicketDetail from './pages/tickets/agent/AgentTicketDetail';
import ManagerDashboard from './pages/dashboards/ManagerDashboard';
import ProfilePage from './pages/tickets/user/ProfilePage';
import TeamLeadTickets from './pages/tickets/team_lead/TeamLeadTickets ';
import TeamLeadTicketDetail from './pages/tickets/team_lead/TeamLeadTicketDetail';
import ManagerTickets from './pages/tickets/manager/ManagerTickets';
import ManagerTicketDetail from './pages/tickets/manager/ManagerTicketDetail';
import UploadFile from './pages/tickets/client/UploadFile';
import ClientListPage from './pages/tickets/manager/ClientListPage';
import ClientDocumentsPage from './pages/tickets/manager/ClientDocumentsPage';
import SummaryPage from './pages/tickets/manager/SummaryPage';
import TeamLeadSummaryPage from './pages/tickets/team_lead/TeamLeadSummaryPage';
import AgentSummaryPage from './pages/tickets/team_lead/AgentSummaryPage';
import AgentSummary from './pages/tickets/agent/AgentSummary';
import TeamLeadDashboard from './pages/dashboards/TeamLeadDashboard';
import AgentFakeTicketsPage from './pages/tickets/agent/AgentFakeTicketsPage ';
import AgentFakeTicketDetail from './pages/tickets/agent/AgentFakeTicketDetail';
import SSOLoading from './auth/SSOLoading';
import VerifyTicketPage from './pages/tickets/agent/VerifyTicketPage'
import SubscriptionPlans from './pages/tickets/client/SubscriptionPlans'
import SlaRules from './pages/admin/SlaRules'
import UserManagement from './pages/admin/UserManagement'
import HierarchyPage from './pages/admin/HierarchyPage'
import CallAudio from './auth/CallAudio'
import GlobalCallModal from './auth/GlobalCallModal'
import NotificationProvider from './auth/NotificationProvider'
import NotificationsPage from './components/NotificationsPage'
import SSOErrorPage from './auth/SSOErrorPage'
import IntegrationGuide from './pages/tickets/client/IntegrationGuide'
import AboutTRS from './pages/tickets/AboutTRS'
import SubscriptionSuccess from './pages/tickets/client/SubscriptionSuccess'
import SubscriptionFailed from './pages/tickets/client/SubscriptionFailed'


const App = () => {
  return (
    <AuthProvider>
        <CallProvider>
            <NotificationProvider>
            <CallAudio/>
            <GlobalCallModal/>
        <BrowserRouter>
        <ToastContainer position="top-right" autoClose={2500} hideProgressBar newestOnTop 
        closeOnClick pauseOnHover draggable={false} theme="light" toastStyle={{
            borderRadius: "10px",
            fontSize: "14px",
            padding: "12px",
            width: "300px", }}/>

        <Routes>
            <Route path='/sso-loading' element={<SSOLoading />} />
            <Route path='/sso-error' element={<SSOErrorPage />} />
            <Route path='/signup' element={<StaffSignup/>}/>
            <Route path='/verify-otp' element={<VerifyOtp />} />
            <Route path='/forgot-password' element={<ForgotPassword/>}/>
            <Route path='/reset-password' element={<ResetPassword/>}/>
            <Route path='/client-signup' element={<ClientSignup/>}/>
            <Route path='/client/complete-profile' element={<CompleteProfile/>}/>
            <Route path='/agent/complete-profile' element={<AgentCompleteProfile/>}/>
            <Route path='/' element={<PublicRoute><Login/></PublicRoute>}/>
            <Route path='/unauthorized' element={<Unauthorized/>} />
            <Route path='/profile' element={<ProtectedRoute role={['USER','AGENT','TEAM_LEAD','MANAGER','CLIENT','ADMIN']}>
                <ProfilePage />
            </ProtectedRoute>} />
            <Route path='/about' element={<ProtectedRoute role={['USER','AGENT','TEAM_LEAD','MANAGER','CLIENT','ADMIN']}>
                <AboutTRS />
            </ProtectedRoute>} />

            <Route path='/admin/dashboard' element={<ProtectedRoute role={['ADMIN']}>
                <AdminDashboard />
            </ProtectedRoute>} />
            <Route path='/client/dashboard' element={<ProtectedRoute role={['CLIENT']}>
                <ClientDashboard />
            </ProtectedRoute>} />
            <Route path='/client/upload' element={<ProtectedRoute role={['CLIENT']}>
                <UploadFile />
            </ProtectedRoute>} />
            <Route path='/client/plans' element={<ProtectedRoute role={['CLIENT']}>
                <SubscriptionPlans />
            </ProtectedRoute>} />
            <Route path='/subscription-success' element={<ProtectedRoute role={['CLIENT']}>
                <SubscriptionSuccess />
            </ProtectedRoute>} />
            <Route path='/subscription-cancel' element={<ProtectedRoute role={['CLIENT']}>
                <SubscriptionFailed />
            </ProtectedRoute>} />
            <Route path='/client/guideline' element={<ProtectedRoute role={['CLIENT']}>
                <IntegrationGuide />
            </ProtectedRoute>} />
            <Route path='/agent/dashboard' element={<ProtectedRoute role={['AGENT']}>
                <AgentDashboard />
            </ProtectedRoute>} />
            <Route path='/team-lead/dashboard' element={<ProtectedRoute role={['TEAM_LEAD']}>
                <TeamLeadDashboard />
            </ProtectedRoute>} />
            <Route path='/team-lead/assigned-tickets' element={<ProtectedRoute role={['TEAM_LEAD']}>
                <TeamLeadTickets />
            </ProtectedRoute>} />
            <Route path='/team-lead/tickets/:id' element={<ProtectedRoute role={['TEAM_LEAD']}>
                <TeamLeadTicketDetail />
            </ProtectedRoute>} />
            <Route path='/team-lead/summaries' element={<ProtectedRoute role={['TEAM_LEAD']}>
                <TeamLeadSummaryPage />
            </ProtectedRoute>} />
            <Route path='/agent-summary/:summary_id' element={<ProtectedRoute role={['TEAM_LEAD']}>
                <AgentSummaryPage />
            </ProtectedRoute>} />
            <Route path='/manager/dashboard' element={<ProtectedRoute role={['MANAGER']}>
                <ManagerDashboard />
            </ProtectedRoute>} />
            <Route path='/tickets/manager/tickets' element={<ProtectedRoute role={['MANAGER']}>
                <ManagerTickets />
            </ProtectedRoute>} />
            <Route path='/manager/tickets/:id' element={<ProtectedRoute role={['MANAGER']}>
                <ManagerTicketDetail />
            </ProtectedRoute>} />
            <Route path='/manager/clients' element={<ProtectedRoute role={['MANAGER']}>
                <ClientListPage />
            </ProtectedRoute>} />
            <Route path='/manager/client-docs/:client_id' element={<ProtectedRoute role={['MANAGER']}>
                <ClientDocumentsPage />
            </ProtectedRoute>} />
            <Route path='/summary' element={<ProtectedRoute role={['MANAGER']}>
                <SummaryPage />
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
            <Route path='/admin/sla' element={<ProtectedRoute role={['ADMIN']}>
                 <SlaRules />
            </ProtectedRoute>} />
            <Route path='/admin/user-manage' element={<ProtectedRoute role={['ADMIN']}>
                 <UserManagement />
            </ProtectedRoute>} />
            <Route path='/user/create-ticket' element={<ProtectedRoute role={['USER']}>
                <CreateTicket />
            </ProtectedRoute>} />
            <Route path='/user/tickets' element={<ProtectedRoute role={['USER']}>
                <TicketsList />
            </ProtectedRoute>} />
            <Route path='/user/tickets/details/:id' element={<ProtectedRoute role={['USER']}>
                <TicketDetail />
            </ProtectedRoute>} />
            <Route path='/agents/requests/' element={<ProtectedRoute role={['AGENT']}>
                <AgentRequests />
            </ProtectedRoute>} />
            <Route path='/agent/assigned-tickets' element={<ProtectedRoute role={['AGENT']}>
                <AgentOngoing />
            </ProtectedRoute>} />
            <Route path='/agent/ticket-detail/:id' element={<ProtectedRoute role={['AGENT']}>
                <AgentTicketDetail />
            </ProtectedRoute>} />
            <Route path='/agent/summary' element={<ProtectedRoute role={['AGENT']}>
                <AgentSummary />
            </ProtectedRoute>} />
            <Route path='/agent/practice' element={<ProtectedRoute role={['AGENT']}>
                <AgentFakeTicketsPage />
            </ProtectedRoute>} />
            <Route path='/agent/fake-tickets/:id' element={<ProtectedRoute role={['AGENT']}>
                <AgentFakeTicketDetail />
            </ProtectedRoute>} />
            <Route path="/tickets/:id/verify" element={<ProtectedRoute role={['AGENT','MANAGER','TEAM_LEAD']}>
                <VerifyTicketPage/>
            </ProtectedRoute>} />
            <Route path="/notifications" element={<ProtectedRoute role={['AGENT','MANAGER','ADMIN','CLIENT','USER','TEAM_LEAD']}>
                <NotificationsPage/>
            </ProtectedRoute>} />
           
        </Routes>
        </BrowserRouter>
        </NotificationProvider>
        </CallProvider>
    </AuthProvider>
  )
}

export default App
