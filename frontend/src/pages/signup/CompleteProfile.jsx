import { useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../../api/axios";
import { notifyError,notifySuccess,notifyWarning,notifyInfo } from "../../utils/notify";
import { validateProfile } from "../../validation/validateProfileClient";
import { useAuth } from "../../auth/AuthContext";

const CompleteProfile = () => {
  const [errors, setErrors] = useState({});
  const [companyName, setCompanyName] = useState("");
  const [businessType, setBusinessType] = useState("");
  const [phone, setPhone] = useState("");
  const navigate = useNavigate();
  const {setProfileCompleted}=useAuth()

 const handleSubmit = async (e) => {
  e.preventDefault();
  const {isValid,errors:validationErrors} =validateProfile({
    companyName,businessType,phone
  })
  if(!isValid){
    setErrors(validationErrors)
    return;
  }
  setErrors(validationErrors);
  try {
    await api.put("/auth/client/profile/update/", {
      company_name: companyName,
      business_type: businessType,
      phone: phone,
    });
    setProfileCompleted(true)
    localStorage.setItem('profile_completed',true)
    notifySuccess("✅ Profile updated successfully!");
    navigate("/client/dashboard");
  } catch (err) {
    const errorMsg = err.response?.data?.errors?.details || 
     err.response?.data?.errors?.phone || 
                    err.response?.data?.non_field_errors?.[0] ||
                    err.response?.data?.company_name?.[0] ||
                    "Profile update failed";
    notifyError(errorMsg);
  }
};
  return (
    <div className="min-h-screen flex justify-center items-center bg-white">
      <div className="w-full max-w-md px-6">
        <form onSubmit={handleSubmit} className="space-y-6">
          
          {/* Email / Company Name Field */}
          <div className="flex flex-col gap-2">
            <label className="text-[#374151] font-medium text-sm ml-0.5">
              Company Name
            </label>
            <input
              type="text"
              value={companyName}
              onChange={(e) => {
                  setCompanyName(e.target.value);
                }}
                className="w-full px-4 py-3 rounded-lg border border-gray-200 focus:border-blue-400 focus:ring-4 focus:ring-blue-50/50 outline-none transition-all"/>
          </div>
          {errors.companyName && (
              <p className="mt-1 text-xs text-red-600">
                {errors.companyName}
              </p>
            )}

          {/* Phone Field */}
          <div className="flex flex-col gap-2">
            <label className="text-[#374151] font-medium text-sm ml-0.5">
              Phone
            </label>
            <input
              type="text"
              value={phone}
              onChange={(e) => setPhone(e.target.value)}
              className="w-full px-4 py-3 rounded-lg border border-gray-200 focus:border-blue-400 focus:ring-4 focus:ring-blue-50/50 outline-none transition-all"
            />
          </div>
          {errors.phone && (
              <p className="mt-1 text-xs text-red-600">
                {errors.phone}
              </p>
            )}

          {/* Business Type Field */}
          <div className="flex flex-col gap-2">
            <label className="text-[#374151] font-medium text-sm ml-0.5">
              Business type
            </label>
            <input
              type="text"
              value={businessType}
              onChange={(e) => setBusinessType(e.target.value)}
              className="w-full px-4 py-3 rounded-lg border border-gray-200 focus:border-blue-400 focus:ring-4 focus:ring-blue-50/50 outline-none transition-all"
            />
          </div>
          {errors.businessType && (
          <p className="mt-1 text-xs text-red-600">
            {errors.businessType}
          </p>
        )}

          {/* Submit Button */}
          <button
            type="submit"
            className="w-full bg-[#0a0a0b] hover:bg-black text-white font-semibold py-4 rounded-lg mt-4 transition-colors text-base"
          >
            Save and Continue
          </button>
        </form>
      </div>
    </div>
  );
};

export default CompleteProfile
