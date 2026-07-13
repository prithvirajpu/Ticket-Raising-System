import { useEffect } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useAuth } from './AuthContext';

const SSOLoading = () => {
    const navigate = useNavigate();
    const [searchParams] = useSearchParams();
    const { login } = useAuth();

    useEffect(() => {
        const access = searchParams.get("access");
        const role = searchParams.get("role");
        const profile_completed = searchParams.get("profile_completed");
        const approval_status = searchParams.get("approval_status");
        const user_id = searchParams.get("user_id");

        console.log("SSO Data Received:", { access: !!access, role });

        if (access && role) {
            login(access, role, profile_completed, approval_status,user_id);

            setTimeout(() => {
                navigate("/user/dashboard", { replace: true });
            }, 150);
        } else {
            console.error("SSO failed - missing data");
            navigate("/login", { replace: true });
        } 
    }, [searchParams, login, navigate]);

    return (
        <div className="flex items-center justify-center min-h-screen text-xl">
            Redirecting to your dashboard...
        </div>
    );
};

export default SSOLoading;