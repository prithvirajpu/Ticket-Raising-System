import React, { useEffect, useRef, useState } from 'react';
import { useAuth } from '../auth/AuthContext';
import { useNavigate, Link, useLocation } from 'react-router-dom';
import { redirectByRole } from '../auth/roleRedirect';
import api from '../api/axios';
import { Mail, Eye } from 'lucide-react';
import { GoogleLogin} from '@react-oauth/google';
import { notifyError,notifySuccess,notifyWarning,notifyInfo } from "../utils/notify";

const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [errors, setErrors] = useState({}); 
  const { login,logout } = useAuth();
  const navigate = useNavigate();
  const location=useLocation()
  const hasShownMessage = useRef(false);

  useEffect(() => {
    if (location.state?.message && !hasShownMessage.current) {
      notifyInfo(location.state.message);
      hasShownMessage.current=true
    }
  }, [location.state]);

const handleGoogleSuccess = async (credentialResponse) => {
  try {
    if (!credentialResponse?.credential) {
      notifyError("Google login failed - No credential received");
      return;
    }

    const id_token = credentialResponse.credential;

    const res = await api.post("auth/google/", { id_token });
    const { access, refresh, role, profile_completed, approval_status } = res.data.data;
    console.log(res.data.data)
    console.log('status',approval_status)
    if (role === "AGENT") {
      if (!profile_completed) {

        login(access, refresh, role,profile_completed);
        notifyWarning("📝 Profile incomplete - Please complete your details");
        navigate("/agent/complete-profile");
        return; 
      }

      if (approval_status !== "APPROVED") {
        notifyWarning("⏳ Your application is pending admin approval");
        console.log('here it is')
        
        navigate('/')
        return; 
      }
      login(access, refresh, role,profile_completed,approval_status);
      notifySuccess("🎉 Welcome to Agent Dashboard!");
      console.log("LOGIN DATA:", {
  role,
  profile_completed,
  approval_status
});
      navigate("/agent/dashboard");
      return;
    }

    if (role === "CLIENT") {
      login(access, refresh, role, profile_completed);
      if (!profile_completed) {
        notifyWarning("📋 Client profile incomplete - Complete your profile first");
        navigate("/client/complete-profile");
        return;
      }
      notifySuccess("🎉 Welcome to Client Dashboard!");
      navigate("/");
      return;
    }

    notifyInfo(`Welcome ${role}! Redirecting...`);
    navigate('/');

  } catch (err) {
    const errorMsg = err.response?.data?.errors?.details || 
                     err.response?.data?.errors?.email ||
                     err.response?.data?.errors?.otp ||
                     "Google login failed. Please try again.";
    notifyError(errorMsg);
  }
};
  // Simple email regex
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  const validateFields = () => {
    const newErrors = {};

    if (!email.trim()) {
      newErrors.email = 'Email is required';
    } else if (!emailRegex.test(email)) {
      newErrors.email = 'Please enter a valid email';
    }

    if (!password.trim()) {
      newErrors.password = 'Password is required';
    } else if (password.length < 3) {
      newErrors.password = 'Password must be at least 3 characters';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

const handleLogin = async (e) => {
  e.preventDefault();

  if (!validateFields()) {
    notifyWarning("Please fill all required fields");
    return;
  }

  try {
    const res = await api.post('auth/login/', { email, password });    
    notifySuccess("🎉 Login successful!");
    console.log(res,'login data')
    login(res.data.data.access, res.data.data.refresh, res.data.data.role);
    navigate(redirectByRole(res.data.data.role));
    
  } catch (err) {
    console.log(err)
    const errorMsg = err.response?.data?.detail || 
                    err.response?.data?.non_field_errors?.[0] ||
                    err.response?.data?.email?.[0] ||
                    err.response?.data?.password?.[0] ||
                    'Login failed. Please check your credentials.';   
    notifyError(errorMsg);
  }
};

  return (
    <div className="min-h-screen flex items-center justify-center bg-white px-4">
      <div className="max-w-md w-full space-y-8 text-center">
        <div>
          <h2 className="text-4xl font-serif font-bold text-gray-900">Welcome Back</h2>
          <p className="mt-2 text-sm text-gray-500">Sign in to continue to your account</p>
        </div>
        <GoogleLogin
            onSuccess={handleGoogleSuccess}
            onError={() => console.log("Google Login Failed")}
          />

        <div className="relative">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-gray-200"></div>
          </div>
          <div className="relative flex justify-center text-sm">
            <span className="px-2 bg-white text-gray-400 uppercase">Or</span>
          </div>
        </div>

        <form className="mt-8 space-y-6" onSubmit={handleLogin}>
          <div className="space-y-4 text-left">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
              <div className="relative">
                <input
                  type="text"
                  className={`appearance-none block w-full pl-3 pr-10 py-3 border ${
                    errors.email ? 'border-red-500' : 'border-gray-300'
                  } rounded-lg placeholder-gray-400 focus:outline-none focus:ring-1 focus:ring-black focus:border-black sm:text-sm`}
                  placeholder="Email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
                <Mail className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 h-5 w-5" />
              </div>
              {errors.email && (
                <p className="mt-1 text-sm text-red-600">{errors.email}</p>
              )}
            </div>

            <div>
              <div className="flex justify-between items-center mb-1">
                <label className="block text-sm font-medium text-gray-700">Password</label>
                <Link
                  to="/forgot-password"
                  className="text-sm font-medium text-blue-600 hover:text-blue-500"
                >
                  Forgot Password?
                </Link>
              </div>
              <div className="relative">
                <input
                  type="password"
                  className={`appearance-none block w-full pl-3 pr-10 py-3 border ${
                    errors.password ? 'border-red-500' : 'border-gray-300'
                  } rounded-lg placeholder-gray-400 focus:outline-none focus:ring-1 focus:ring-black focus:border-black sm:text-sm`}
                  placeholder="Password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
                <Eye className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 h-5 w-5" />
              </div>
              {errors.password && (
                <p className="mt-1 text-sm text-red-600">{errors.password}</p>
              )}
            </div>
          </div>

          <p className="text-xs text-gray-500 leading-relaxed text-center">
            By Creating An Account You Agree With Our{' '}
            <span className="underline cursor-pointer">Terms Of Service</span>,{' '}
            <span className="underline cursor-pointer">Privacy Policy</span>.
          </p>

          <div>
            <button
              type="submit"
              className="group relative w-full flex justify-center py-3 px-4 border border-transparent text-sm font-bold rounded-lg text-white bg-[#0f172a] hover:bg-black focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-900 transition-all"
            >
              Sign In
            </button>
          </div>
        </form>

        <p className="text-sm text-gray-600">
          Don't have an account?{' '}
          <Link to="/signup" className="font-medium text-blue-500 hover:text-blue-400">
            Agent
          </Link>{' '}
          <Link
            to="/client-signup"
            className="font-medium text-blue-500 hover:text-blue-400"
          >
            Client
          </Link>
        </p>
      </div>
    </div>
  );
};

export default Login;