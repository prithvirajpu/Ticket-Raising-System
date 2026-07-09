import { BrowserRouter, Routes } from "react-router-dom";

import { AuthProvider } from "./auth/AuthContext";
import { CallProvider } from "./auth/CallContext";
import NotificationProvider from "./auth/NotificationProvider";

import CallAudio from "./auth/CallAudio";
import GlobalCallModal from "./auth/GlobalCallModal";

import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

// Route Groups
import AppRoutes from "./routes/AppRoutes";

const App = () => {
    return (
        <AuthProvider>
            <CallProvider>
                <NotificationProvider>

                    <CallAudio />
                    <GlobalCallModal />

                    <BrowserRouter>

                        <ToastContainer position="top-right" autoClose={2500} hideProgressBar newestOnTop
                         closeOnClick pauseOnHover draggable={false} theme="light"
                            toastStyle={{ borderRadius: "10px", fontSize: "14px", padding: "12px", width: "300px",}}
                        />

                        <AppRoutes/>

                    </BrowserRouter>

                </NotificationProvider>
            </CallProvider>
        </AuthProvider>
    );
};

export default App;