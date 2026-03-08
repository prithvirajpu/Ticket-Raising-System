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
      role: "AGENT"
    });
    const {data}=res.data
    const { profile_completed, approval_status, role, access, refresh } = data;
    if (access && refresh) {
    localStorage.setItem("access", access);
    localStorage.setItem("refresh", refresh);
}

    if (!profile_completed) {
      notifyWarning("📝 Profile incomplete - please complete your profile");
      navigate("/agent/complete-profile");
      return;
    }

    if (approval_status !== "APPROVED") {
      // DO NOT log in yet
      notifyWarning("⏳ Application not approved yet - please wait for admin review");
      navigate("/"); // Redirect to login/home
      return;
    }

    // Only approved agents or other roles can login
    login(access, refresh, role);
    notifySuccess("🎉 Welcome to Agent Dashboard!");
    navigate(redirectByRole(role));

  } catch (err) {
    const backend=err.response?.data
    const errorMsg =
      backend?.data?.errors ||
      backend?.data.details ||
      backend?.non_field_errors?.[0] ||
      "Google login failed. Please try again.";
    notifyError(errorMsg);
  }
};

const handleNext = async() => {
  
  const result = await validateAgentStep(step, form, resume, certificates);
  setErrors(result.errors);

  if (result.isValid) {
    setStep((s) => s + 1);
    setErrors({});
    notifySuccess('Step completed successfully!')
  } else {
    console.log(result.errors);
  }
};

const handleSubmit = async () => {
  const { isValid, errors: finalErrors } = await validateAgentStep(
    3,
    form,
    resume,
    certificates
  );

  setErrors(finalErrors);

  if (!isValid) {
    notifyWarning("Please fix the errors before submitting.");
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
    certificates.forEach((file) => data.append("certificates", file));

    const res = await api.post("/auth/signup/agent/", data);

    notifySuccess("Submitted! Check your email for OTP.");

    navigate("/verify-otp", {
      state: {
        email: form.email,
        purpose: "AGENT",
        expiresAt: res.data.data.expires_at,
      },
    });
  } catch (error) {
    const backendErrors = error?.response?.data;

    if (backendErrors) {
      // Push backend field errors into state
      setErrors(backendErrors);

      // Optional toast for general errors
      if (backendErrors.non_field_errors) {
        notifyError(backendErrors.non_field_errors[0]);
      }
    } else {
      notifyError("Signup failed. Please try again.");
    }
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