import { useEffect, useState, useRef } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import api from "../../api/axios";
import { notifyError, notifySuccess, notifyWarning, notifyInfo } from "../../utils/notify";
import Loader from "../../components/modals/Loader";


const VerifyOtp = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const intervalRef = useRef(null);

  // --- Grab state from previous page ---
  const email = location.state?.email;
  const purpose = location.state?.purpose;
  const backendExpiresAt = location.state?.expiresAt;

  const storageKey = `otp_expiry_${email}_${purpose}`;

  const [otp, setOtp] = useState("");
  const [loading, setLoading] = useState(false);
  const [timer, setTimer] = useState(0);
  const [error, setError] = useState("");
  const [resendLoading, setResendLoading] = useState(false);

  // --- Timer utilities ---
  const clearTimer = () => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
  };

  const startTimer = (expiresAt) => {
    clearTimer();
    const expiryTime = new Date(expiresAt).getTime();

    const updateTimer = () => {
      const remaining = Math.max(Math.floor((expiryTime - Date.now()) / 1000), 0);
      setTimer(remaining);
      if (remaining <= 0) {
        clearTimer();
        localStorage.removeItem(storageKey);
      }
    };

    updateTimer(); // start immediately
    intervalRef.current = setInterval(updateTimer, 1000);
  };

  // --- Initialize timer after first paint ---
  useEffect(() => {
    if (!email || !purpose || !backendExpiresAt) {
      console.warn("❌ Missing email, purpose, or backendExpiresAt. Timer not started.");
      return;
    }

    console.log("✅ Starting timer with backend expiry:", backendExpiresAt);
    localStorage.setItem(storageKey, backendExpiresAt);
    setTimeout(() => startTimer(backendExpiresAt), 0);

    return clearTimer;
  }, [email, purpose, backendExpiresAt]);

  const formatTime = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins.toString().padStart(2, "0")}:${secs.toString().padStart(2, "0")}`;
  };

  // --- Verify OTP ---
 const verifyOtp = async () => {
    if (!otp) {
      notifyWarning("Please enter OTP");
      return;
    }

    try {
      setLoading(true);
      setError("");
      await api.post("/auth/verify-otp/", { email, otp, purpose });
      clearTimer();
      localStorage.removeItem(storageKey);
      
      if (purpose === "RESET") {
        notifySuccess("OTP verified! Proceed to reset password.");
        navigate("/reset-password", { state: { email } });
      } else {
        notifySuccess("Verification successful! Redirecting...");
        navigate("/");
      }
    } catch (err) {
      notifyError(err.response?.data?.error || "Verification failed");
    } finally {
      setLoading(false);
    }
};

  // --- Resend OTP ---
const resendOtp = async () => {
    try {
      setResendLoading(true);
      setError("");
      const response = await api.post("/auth/resend-otp/", { email, purpose });
      const newExpiry = response.data.expires_at;
      
      localStorage.setItem(storageKey, newExpiry);
      startTimer(newExpiry);
      notifySuccess("OTP resent successfully");
    } catch (err) {
      notifyError(err.response?.data?.error || "Resend failed");
    } finally {
      setResendLoading(false);
    }
};

  useEffect(() => clearTimer, []);

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-white p-4 font-sans text-[#334155]">
      {resendLoading && <Loader />}
      <div className="w-full max-w-[400px] text-center">
        <div className="mb-6 space-y-1">
          <p className="text-[14px] text-gray-500">
            The OTP was sent to your registered email
          </p>
          <p className="text-[14px] text-gray-500">
            Please check your inbox or spam folder.
          </p>
        </div>

        <div className="mb-8 text-[13px] font-medium text-gray-600">
          {formatTime(timer)}
        </div>

        <div className="text-left mb-6">
          <label className="block text-[13px] font-medium text-gray-600 mb-2">
            Enter OTP
          </label>
          <input
            type="text"
            maxLength={6}
            className="w-full px-3 py-3 border border-gray-200 rounded-lg focus:outline-none focus:border-gray-400 transition-colors"
            value={otp}
            onChange={(e) => setOtp(e.target.value)}
          />
          {error && <p className="text-red-500 text-sm mt-2">{error}</p>}
        </div>

        <button
          onClick={verifyOtp}
          disabled={loading}
          className="w-full bg-[#0d1117] text-white py-3.5 rounded-md font-bold text-xs tracking-widest uppercase hover:bg-black transition-colors disabled:opacity-70"
        >
          {loading ? "Verifying..." : "VERIFY"}
        </button>

        {timer === 0 && (
          <button
            onClick={resendOtp}
            disabled={resendLoading}
            className="mt-6 text-sm text-blue-500 hover:underline disabled:opacity-60"
          >
            {resendLoading ? "Resending..." : "Resend OTP"}
          </button>
        )}
      </div>
    </div>
  );
};

export default VerifyOtp;
