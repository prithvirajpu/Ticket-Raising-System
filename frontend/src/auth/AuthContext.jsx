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
                        localStorage.getItem("approval_status") || 'APPROVED'
                    );
    const [userId, setUserId] = useState(
    Number(localStorage.getItem('user_id')) || null
);

    useEffect(()=>{
        const role=localStorage.getItem('role');
        const access=localStorage.getItem('access');
        const profile=localStorage.getItem('profile_completed')
        const approval = localStorage.getItem('approval_status');
        const userId = localStorage.getItem('user_id');

        if (role)setUserRole(role);
        if (access)setAccessToken(access);
        if (profile) setProfileCompleted(profile==='true')
        if (approval) setApprovalStatus(approval);
        if (userId) setUserId(Number(userId));
        setLoading(false);
    },[])

    const login=(access,refresh,role,profile_completed,approval_status,user_id)=>{
        localStorage.setItem('access',access);
        localStorage.setItem('refresh',refresh);
        localStorage.setItem('role',role);
        localStorage.setItem('profile_completed',profile_completed)
        localStorage.setItem('approval_status', approval_status);
        localStorage.setItem('user_id', user_id);

        setAccessToken(access)
        setUserRole(role)
        setUserId(user_id)
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
        setUserId(null)
    };
    return (
        <AuthContext.Provider value={{login,logout,userRole,userId,isAuthenticated,
        loading,accessToken,profileCompleted,setProfileCompleted,approvalStatus ,setApprovalStatus}} >
            
            {children}
        </AuthContext.Provider>
    )
};

export const useAuth=()=>useContext(AuthContext)