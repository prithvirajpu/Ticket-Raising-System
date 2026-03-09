import { useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../../api/axios";
import { notifyError, notifySuccess, notifyWarning, notifyInfo } from "../../utils/notify";
import { validateAgentProfile } from "../../validation/validateAgentProfile";
import { useAuth } from "../../auth/AuthContext";
import Loader from "../../components/modals/Loader";


const AgentCompleteProfile = () => {
  const [errors, setErrors] = useState({});
  const [resume, setResume] = useState(null);
  const [phone, setPhone] = useState("");
  const [skills, setSkills] = useState("");
  const [certificates, setCertificates] = useState([]);
  const navigate = useNavigate();
  const { setProfileCompleted,logout } = useAuth();
  const [loading,setLoading]=useState(false)

 const handleSubmit = async (e) => {
    e.preventDefault();
    const {isValid,errors:validationErrors}=validateAgentProfile({phone,skills,resume})
    if (!isValid){
      setErrors(validationErrors)
      return;
    }
    setErrors({});
    setLoading(true);
    const formData = new FormData();
    formData.append("resume", resume);
    formData.append("phone", phone);
    formData.append("skills", skills);

    certificates.forEach((file) => {
      formData.append("certificates", file);
    });

    try {
      console.log('in try')
      const response = await api.put("/auth/agent/profile/update/", formData, {
        headers: {
          "Content-Type": "multipart/form-data",
          "Authorization": `Bearer ${localStorage.getItem("access")}`,
        },
      });
      setProfileCompleted(true);
      localStorage.setItem("profile_completed", "true");
      const { status } = response.data.data;
      console.log('this is the status',status)
      if (status === "PENDING") {
        logout()
        navigate("/", { 
          state: { 
            message: "Profile submitted! Waiting for admin approval." 
          } 
        });
      } else {
        setProfileCompleted(true);
        localStorage.setItem("profile_completed", "true");
        notifySuccess("Profile updated successfully!");
        navigate("/agent/dashboard");
      }
    } catch (error) {
      notifyError("Profile update failed. Please try again.");
    }finally{
      setLoading(false);
    }
  };

  return (
   <div className="min-h-screen flex justify-center items-center bg-gray-50 p-4">
     {loading && <Loader />}
      <div className="bg-white p-8 rounded-xl shadow-lg border border-gray-100 w-full max-w-md transition-all">
        {/* Header section */}
        <div className="text-center mb-8">
          <h2 className="text-2xl font-semibold text-[#0f172a]">Agent Application</h2>
          <p className="text-sm text-gray-400 mt-1">Complete your professional profile</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-5">
          {/* Phone Number */}
          <div>
            <label className="block text-xs font-medium text-gray-500 mb-1.5 ml-0.5">Phone Number</label>
            <input
              type="text"
              value={phone}
              onChange={(e) => setPhone(e.target.value)}
              placeholder="+91 98765 43210"
              className="w-full p-3 border border-gray-200 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500 transition-all placeholder:text-gray-300"
            />
                    {errors.phone && (
          <p className="mt-1 text-xs text-red-600">{errors.phone}</p>
        )}
          </div>

          {/* Skills */}
          <div>
            <label className="block text-xs font-medium text-gray-500 mb-1.5 ml-0.5">Skills</label>
            <input
              type="text"
              value={skills}
              onChange={(e) => setSkills(e.target.value)}
              placeholder="e.g. React, Node.js, Design"
              className="w-full p-3 border border-gray-200 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500 transition-all placeholder:text-gray-300"
            />
            {errors.skills && (
                  <p className="mt-1 text-xs text-red-600">{errors.skills}</p>
                )}
          </div>

          {/* File Upload Row */}
          <div className="flex gap-4">
            {/* Resume Upload */}
            <div className="flex-1">
              <label className="block text-xs font-medium text-gray-500 mb-1.5 ml-0.5">Resume (PDF)</label>
              <div className={`border rounded-md h-[52px] flex justify-center items-center cursor-pointer transition-all ${
                resume ? "bg-blue-50 border-blue-200" : "border-gray-200 hover:bg-gray-50 hover:border-gray-300"
              }`}>
                {/* REQUIRED REMOVED HERE TO FIX ERROR */}
                <input
                  type="file"
                  className="hidden"
                  id="resume-upload"
                  accept=".pdf,.doc,.docx"
                  onChange={(e) => setResume(e.target.files[0] || null)}
                />
                <label htmlFor="resume-upload" className="cursor-pointer w-full h-full flex items-center justify-center px-2">
                  {resume ? (
                    <span className="text-[11px] text-blue-700 font-semibold truncate px-1">
                      {resume.name}
                    </span>
                  ) : (
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a2 2 0 002 2h12a2 2 0 002-2v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
                    </svg>
                  )}
                </label>
              </div>
              {errors.resume && (
                <p className="mt-1 text-xs text-red-600">{errors.resume}</p>
              )}
            </div>

            {/* Certificates Upload */}
            <div className="flex-1">
              <label className="block text-xs font-medium text-gray-500 mb-1.5 ml-0.5">Certificates</label>
              <div className={`border rounded-md h-[52px] flex justify-center items-center cursor-pointer transition-all ${
                certificates.length > 0 ? "bg-green-50 border-green-200" : "border-gray-200 hover:bg-gray-50 hover:border-gray-300"
              }`}>
                <input
                  type="file"
                  multiple
                  className="hidden"
                  id="cert-upload"
                  onChange={(e) => setCertificates([...e.target.files])}
                />
                <label htmlFor="cert-upload" className="cursor-pointer w-full h-full flex items-center justify-center px-2 text-center">
                  {certificates.length > 0 ? (
                    <span className="text-[11px] text-green-700 font-semibold">
                      {certificates.length} Files selected
                    </span>
                  ) : (
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                    </svg>
                  )}
                </label>
              </div>
            </div>
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            className="w-full bg-[#0f172a] text-white py-3.5 rounded-md mt-4 font-semibold hover:bg-slate-800 transition-all active:scale-[0.98] shadow-sm"
          >
            Submit Application
          </button>
        </form>
      </div>
    </div>
  );
};

export default AgentCompleteProfile