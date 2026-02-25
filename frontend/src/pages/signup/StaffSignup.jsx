import { useState } from "react";
import { validateAgentStep } from "../../validation/agentValidation";  
import { Link, useNavigate } from "react-router-dom";
import StepThree from "./StepThree";
import StepTwo from "./StepTwo";
import StepOne from "./StepOne";
import api from "../../api/axios";
import { GoogleLogin} from '@react-oauth/google';
import { useAuth } from "../../auth/AuthContext";
import { redirectByRole } from "../../auth/roleRedirect";
import { notifyError,notifySuccess,notifyWarning,notifyInfo } from "../../utils/notify";
import Loader from '../../components/modals/Loader'

const StaffSignup = () => {
  const {login}=useAuth()
  const [step, setStep] = useState(1);
  const [form, setForm] = useState({full_name: "",email: "",password: "",
  phone: "",skills: "",confirm_password: "",});
  const [resume, setResume] = useState(null);
  const [certificates, setCertificates] = useState([]);
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState({}); 

  const navigate = useNavigate();

const handleGoogleSuccess = async (credentialResponse) => {
  
  try {
    const id_token = credentialResponse.credential;
    const res = await api.post("auth/google/", {
      id_token, 
      role: 'AGENT'
    });

    login(res.data.access, res.data.refresh, res.data.role);
    if (!res.data.profile_completed) {
      notifyWarning("📝 Profile incomplete - please complete your profile");
      navigate("/agent/complete-profile");
    }
    else if (res.data.approval_status !== "APPROVED") {
      notifyWarning("⏳ Application not approved yet - please wait for admin review");
      navigate("/");
    }
    else {
      notifySuccess("🎉 Welcome to Agent Dashboard!");
      navigate(redirectByRole(res.data.role));
    }
  } catch (err) {
    const errorMsg = err.response?.data?.error || 
                    err.response?.data?.detail ||
                    err.response?.data?.non_field_errors?.[0] ||
                    "Google login failed. Please try again.";
    
    notifyError(errorMsg);
  }
};


const handleNext = () => {
  const result = validateAgentStep(step, form, resume, certificates);
  setErrors(result.errors);

  if (result.isValid) {
    setStep((s) => s + 1);
    setErrors({});
    notifySuccess('Step completed successfully!')
  } else {
    notifyError('Please fix the errors before proceeding.')
  }
};

const handleSubmit = async () => {
  const { isValid, errors: finalErrors } = validateAgentStep(3, form, resume, certificates);
  setErrors(finalErrors);
  if (!isValid) {
    notifyWarning('Please fix the errors before submitting.');
    return;
  }
  setLoading(true);
  try {
    const data = new FormData();
    data.append("full_name", form.full_name);
    data.append("email", form.email);
    data.append("phone", form.phone);
    data.append("skills", form.skills || "");
    data.append("password", form.password);
    data.append("confirm_password", form.confirm_password);
    if (resume) data.append("resume", resume);
    if (certificates.length > 0) {
      certificates.forEach((file) => data.append("certificates", file));
    }
    const res = await api.post("/auth/signup/agent/", data);
    notifySuccess("Submitted! Check your email for OTP.");
    navigate("/verify-otp", { 
      state: { 
        email: form.email, 
        purpose: "AGENT",
        expiresAt: res.data.expires_at 
      } 
    });
  } catch (error) {
    console.log("Raw error object:", error?.response);
    console.log("Raw error object:", error);
    notifyError(error?.response?.data?.non_field_errors[0] || 'Signup failed. Please try again.');
  } finally {
    setLoading(false);
  }
};

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-gray-50 p-4">
      { loading && <Loader/> }
      <div className="w-full max-w-md bg-white p-8 rounded-lg shadow-sm">
        <div className="mb-2">
          <GoogleLogin
              onSuccess={handleGoogleSuccess}
              onError={() => console.log("Google Login Failed")}
            />
        </div>
        {step === 1 && (
          <StepOne
            form={form}
            setForm={setForm}
            resume={resume}
            setResume={setResume}
            errors={errors}
            onNext={handleNext}
          />
        )}
        {step === 2 && (
          <StepTwo
            form={form}
            setForm={setForm}
            setCertificates={setCertificates}
            errors={errors}
            onNext={handleNext}
            certificates={certificates}
          />
        )}
        {step === 3 && (
          <StepThree
            form={form}
            setForm={setForm}
            loading={loading}
            errors={errors}
            onSubmit={handleSubmit}
          />
        )}

        <div className="mt-6 text-center text-sm">
          Already have an account?{" "}
          <Link to="/" className="text-blue-500">
            Log in
          </Link>
        </div>
      </div>
    </div>
  );
};

export default StaffSignup