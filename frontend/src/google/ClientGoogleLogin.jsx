// ClientGoogleLogin.jsx
import { GoogleLogin } from "@react-oauth/google";
import api from "../../api/axios";
import { useNavigate } from "react-router-dom";

const ClientGoogleLogin = () => {
  const navigate = useNavigate();

  const handleSuccess = async (credentialResponse) => {
    try {
      const id_token = credentialResponse.credential;
      const res = await api.post("/auth/google-client/", { id_token });

      console.log("Login response:", res.data);
      localStorage.setItem("token", res.data.token);
      navigate("/client/dashboard");
    } catch (err) {
      console.error("Google login failed:", err.response?.data || err.message);
      alert("Google login failed");
    }
  };

  const handleError = () => {
    console.error("Google login error");
  };

  return (
    <GoogleLogin
      onSuccess={handleSuccess}
      onError={handleError}
    />
  );
};

export default ClientGoogleLogin;
