import { Route } from "react-router-dom";

import Login from "../pages/Login";
import StaffSignup from "../pages/signup/StaffSignup";
import ClientSignup from "../pages/signup/ClientSignup";
import VerifyOtp from "../pages/signup/VerifyOtp";
import ForgotPassword from "../pages/signup/ForgotPassword";
import ResetPassword from "../pages/signup/ResetPassword";
import CompleteProfile from "../pages/signup/CompleteProfile";
import AgentCompleteProfile from "../pages/signup/AgentCompleteProfile";
import Unauthorized from "../pages/Unauthorized";
import PublicRoute from "../auth/PublicRoute";
import SSOLoading from '../auth/SSOLoading';
import SSOErrorPage from "../auth/SSOErrorPage";

const publicRoutes = (
    <>
        <Route path="/" element={<PublicRoute><Login/></PublicRoute>} />
        <Route path="/sso-loading" element={<SSOLoading />} />
        <Route path="/sso-error" element={<SSOErrorPage />} />
        <Route path="/signup" element={<StaffSignup />} />
        <Route path="/client-signup" element={<ClientSignup />} />
        <Route path="/verify-otp" element={<VerifyOtp />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/reset-password" element={<ResetPassword />} />
        <Route path="/client/complete-profile" element={<CompleteProfile />} />
        <Route path="/agent/complete-profile" element={<AgentCompleteProfile />} />
        <Route path="/unauthorized" element={<Unauthorized />} />
    </>
);

export default publicRoutes;