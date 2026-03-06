import { createContext,useContext,useEffect,useState } from "react";

const AuthContext=createContext();

export const AuthProvider=({children})=>{
    const [userRole,setUserRole]=useState(localStorage.getItem('role'));
    const [accessToken,setAccessToken]=useState(localStorage.getItem('access'));
    const [loading, setLoading] = useState(true);

    useEffect(()=>{
        const role=localStorage.getItem('role');
        const access=localStorage.getItem('access');

        if (role)setUserRole(role);
        if (access)setAccessToken(access);
        setLoading(false);
    },[])

    const login=(access,refresh,role)=>{
        localStorage.setItem('access',access);
        localStorage.setItem('refresh',refresh);
        localStorage.setItem('role',role);
        setAccessToken(access)
        setUserRole(role)
    };
    const isAuthenticated=!!accessToken
    const logout=()=>{
        localStorage.clear()
        setUserRole(null)
        setAccessToken(null)
    };
    return (
        <AuthContext.Provider value={{login,logout,userRole,isAuthenticated,loading}} >
            {children}
        </AuthContext.Provider>
    )
};

export const useAuth=()=>useContext(AuthContext)