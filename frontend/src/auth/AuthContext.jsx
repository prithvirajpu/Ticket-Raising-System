import { createContext,useContext,useEffect,useState } from "react";

const AuthContext=createContext();

export const AuthProvider=({children})=>{
    const [userRole,setUserRole]=useState(localStorage.getItem('role'));
    const [accessToken,setAccessToken]=useState(localStorage.getItem('access'));
    const [loading, setLoading] = useState(true);
    const [profileCompleted, setProfileCompleted] = useState(
                        localStorage.getItem("profile_completed") === "true"
                    );
    const [approvalStatus, setApprovalStatus] = useState(
                        localStorage.getItem("approval_status") || null
                    );

    useEffect(()=>{
        const role=localStorage.getItem('role');
        const access=localStorage.getItem('access');
        const profile=localStorage.getItem('profile_completed')
        const approval = localStorage.getItem('approval_status');

        if (role)setUserRole(role);
        if (access)setAccessToken(access);
        if (profile) setProfileCompleted(profile==='true')
        if (approval) setApprovalStatus(approval);
        setLoading(false);
    },[])

    const login=(access,refresh,role,profile_completed,approval_status)=>{
        localStorage.setItem('access',access);
        localStorage.setItem('refresh',refresh);
        localStorage.setItem('role',role);
        localStorage.setItem('profile_completed',profile_completed)
        localStorage.setItem('approval_status', approval_status);

        setAccessToken(access)
        setUserRole(role)
        setProfileCompleted(profile_completed)
        setApprovalStatus(approval_status);
    };
    const isAuthenticated=!!accessToken
    const logout=()=>{
        localStorage.clear()
        setUserRole(null)
        setAccessToken(null)
        setProfileCompleted(false)
        setApprovalStatus(null);
    };
    return (
        <AuthContext.Provider value={{login,logout,userRole,isAuthenticated,
        loading,accessToken,profileCompleted,setProfileCompleted,approvalStatus ,setApprovalStatus}} >
            
            {children}
        </AuthContext.Provider>
    )
};

export const useAuth=()=>useContext(AuthContext)