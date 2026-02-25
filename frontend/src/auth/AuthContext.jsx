import { createContext,useContext,useState } from "react";
import api from './../api/axios'

const AuthContext=createContext();

export const AuthProvider=({children})=>{
    const [userRole,setUserRole]=useState(localStorage.getItem('role'))

    const login=(access,refresh,role)=>{
        localStorage.setItem('access',access);
        localStorage.setItem('refresh',refresh);
        localStorage.setItem('role',role);
        setUserRole(role)
    };
    const logout=()=>{
        localStorage.clear()
        setUserRole(null)
    };
    return (
        <AuthContext.Provider value={{login,logout,userRole}} >
            {children}
        </AuthContext.Provider>
    )
};

export const useAuth=()=>useContext(AuthContext)