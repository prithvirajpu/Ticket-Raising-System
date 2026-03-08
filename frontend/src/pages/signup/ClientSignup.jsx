import { useState } from "react";
import {Link, useNavigate} from 'react-router-dom'
import api from '../../api/axios'
import { GoogleLogin} from '@react-oauth/google';
import { useAuth } from "../../auth/AuthContext";
import { redirectByRole } from "../../auth/roleRedirect";
import { notifyError,notifySuccess,notifyWarning,notifyInfo } from "../../utils/notify";
import { validateClientStep } from "../../validation/validateClientStep";
import Loader from '../../components/modals/Loader'

const ClientSignup = () => {
  const navigate=useNavigate()
  const {login}=useAuth()
  const [errors, setErrors] = useState({});
  const [step, setStep] = useState(1); 
  const[loading,setLoading]=useState(false)
  const [form, setForm] = useState({
    companyName: "",email: "",phone: "",
    business_type: "",password: "",confirmPassword: "",});

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

const handleGoogleSuccess = async (credentialResponse) => {
  try {
    if (!credentialResponse?.credential) {
      notifyError("Google login failed - no credential received");
      return;
    }
    notifyInfo("🔄 Authenticating with Google...");
    const id_token = credentialResponse.credential;
    const res = await api.post("auth/google/", {
      id_token,
      role: "CLIENT",
    });
    const { access, refresh, role, profile_completed } = res.data;
    login(access, refresh, role);
    notifySuccess("✅ Google login successful!");
    if (!profile_completed) {
      navigate("/client/complete-profile");
    } else {
      notifySuccess(`🎉 Welcome back!`);
      navigate(redirectByRole(role));
    }
  } catch (err) {
    const errorMsg = err.response?.data?.errors || 
                    err.response?.data?.detail ||
                    err.response?.data?.non_field_errors?.[0] ||
                    "Google login failed. Please try again.";
    notifyError(errorMsg);
  }
};

const handleNext = async(e) => {
  e.preventDefault();
  const validation = validateClientStep(1, form);
  
  if (!validation.isValid) {
    setErrors(validation.errors);
    return;
  }
  try {
    const res=await api.post('/auth/check-user/',{email:form.email});
    setErrors({});
    setStep(2);

  } catch (error) {
    setErrors({'email':'Email already exists'})
  return;
  }
};



const handleSubmit = async (e) => {
  e.preventDefault();

  const validation = validateClientStep(2, form);

  if (!validation.isValid) {
    setErrors(validation.errors);
    return;
  }
  setLoading(true)
  setErrors({});

  try {
    const res = await api.post('/auth/signup/client/', form);
    notifySuccess("✅ OTP sent successfully! Check your email ");

    navigate('/verify-otp', {
      state: {
        email: form.email,
        purpose: 'SIGNUP',
        expiresAt: res.data.data.expires_at
      }
    });

  } catch (error) {
    const message =
    error?.response?.data?.non_field_errors?.[0] ||
    error?.response?.data?.error ||
    error?.response?.data?.detail ||
    "Signup failed. Please try again.";
    notifyError( message);
  }finally{
    setLoading(false)
  }
};

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gray-50 p-4 font-sans text-[#333]">
      {loading && <Loader /> }
       <div className="w-full max-w-md bg-white p-8 rounded-lg shadow-sm">
        
        {/* Step 1: Basic Details */}
        {step === 1 && (
          <>
           <GoogleLogin
              onSuccess={handleGoogleSuccess}
              onError={() => console.log("Google Login Failed")}
            />
          <div className="text-center mb-4 my-3">
              <h1 className="text-2xl font-semibold text-[#0f172a]">Client SignUp Page</h1>
          </div>
            <form onSubmit={handleNext} className="space-y-5">
              <div>
                <label className="block text-[13px] font-semibold text-gray-600 mb-1">Company Name</label>
                <input
                      type="text"
                      name="companyName"
                      value={form.companyName}
                      className={`w-full px-3 py-2.5 border rounded-lg focus:outline-none 
                      ${errors.companyName ? "border-red-500" : "border-gray-200"}`}
                      onChange={handleChange}
                    />

                    {errors.companyName && (
                      <p className="text-red-500 text-xs mt-1">
                        {errors.companyName}
                      </p>
                    )}

              </div>

              <div>
                <label className="block text-[13px] font-semibold text-gray-600 mb-1">Email</label>
                <input
                      type="text"
                      name="email"
                      value={form.email}
                      className={`w-full px-3 py-2.5 border rounded-lg focus:outline-none 
                      ${errors.email ? "border-red-500" : "border-gray-200"}`}
                      onChange={handleChange}
                    />

                    {errors.email && (
                      <p className="text-red-500 text-xs mt-1">
                        {errors.email}
                      </p>
                    )}

              </div>

              <div>
                <label className="block text-[13px] font-semibold text-gray-600 mb-1">Phone</label>
                <input
                      type="text"
                      name="phone"
                      value={form.phone}
                      className={`w-full px-3 py-2.5 border rounded-lg focus:outline-none 
                      ${errors.phone ? "border-red-500" : "border-gray-200"}`}
                      onChange={handleChange}
                    />

                    {errors.phone && (
                      <p className="text-red-500 text-xs mt-1">
                        {errors.phone}
                      </p>
                    )}

              </div>

              <div>
                <label className="block text-[13px] font-semibold text-gray-600 mb-1">Business type</label>
                <input
                      type="text"
                      name="business_type"
                      value={form.business_type}
                      className={`w-full px-3 py-2.5 border rounded-lg focus:outline-none 
                      ${errors.business_type ? "border-red-500" : "border-gray-200"}`}
                      onChange={handleChange}
                    />

                    {errors.business_type && (
                      <p className="text-red-500 text-xs mt-1">
                        {errors.business_type}
                      </p>
                    )}

              </div>

              <button
                type="submit"
                className="w-full bg-[#0d1117] text-white py-3.5 rounded-md font-semibold text-sm hover:bg-black transition-colors"
              >
                Next
              </button>
            </form>
          </>
        )}

        {/* Step 2: Passwords */}
        {step === 2 && (
          <form onSubmit={handleSubmit} className="space-y-5">
            <h2 className="text-xl font-bold mb-6">Set your password</h2>
            
            <div>
              <label className="block text-[13px] font-semibold text-gray-600 mb-1">Password</label>
              <input
                  type="password"
                  name="password"
                  value={form.password}
                  className={`w-full px-3 py-2.5 border rounded-lg focus:outline-none 
                  ${errors.password ? "border-red-500" : "border-gray-200"}`}
                  onChange={handleChange}
                />

                {errors.password && (
                  <p className="text-red-500 text-xs mt-1">
                    {errors.password}
                  </p>
                )}

            </div>

            <div>
              <label className="block text-[13px] font-semibold text-gray-600 mb-1">Confirm Password</label>
              <input
                  type="password"
                  name="confirmPassword"
                  value={form.confirmPassword}
                  className={`w-full px-3 py-2.5 border rounded-lg focus:outline-none 
                  ${errors.confirmPassword ? "border-red-500" : "border-gray-200"}`}
                  onChange={handleChange}
                />

                {errors.confirmPassword && (
                  <p className="text-red-500 text-xs mt-1">
                    {errors.confirmPassword}
                  </p>
                )}

            </div>

            <p className="text-[11px] text-gray-500 leading-snug">
              By Creating An Account You Agree With Our Terms Of Service, Privacy Policy,
            </p>

            <button
              type="submit"
              className="w-full bg-[#0d1117] text-white py-3.5 rounded-md font-semibold text-sm hover:bg-black transition-colors"
            >
              Create account
            </button>
                   
            <button 
              type="button" 
              onClick={() => setStep(1)}
              className="w-full text-sm text-gray-500 hover:text-black transition-colors mt-2"
            >
              Back to details
            </button>
          </form>
        )}

        {/* Footer Link */}
        <div className="mt-8 text-center text-sm text-gray-500">
          Already have an account?{" "}
          <Link to={'/'} ><button className="text-blue-500 font-medium hover:underline">Log in</button></Link>
        </div>
      </div>
    </div>
  );
};

export default ClientSignup;