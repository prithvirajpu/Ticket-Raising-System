import {useState,useEffect} from 'react';
import { useLocation,useNavigate } from 'react-router-dom';
import api from '../../api/axios';
import { notifyError, notifySuccess, notifyWarning, notifyInfo } from "../../utils/notify";

const ResetPassword = () => {
    const location=useLocation()
    const navigate=useNavigate()
    const email=location.state?.email;
    const reset_token=location.state?.reset_token;
    
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  

  useEffect(()=>{
    if(!email){
        navigate('/')
    }
  },[email,navigate])

  const handleSubmit = async (e) => {
    e.preventDefault();
    console.log('data sending',email,reset_token,newPassword)
    setError('');

    if (!newPassword || !confirmPassword) {
        notifyWarning('All fields are required');
        return;
    }
    
    if (newPassword !== confirmPassword) {
        notifyWarning('Passwords do not match');
        return;
    }

    try {
        setLoading(true);
        const res= await api.post('/auth/reset-password/', {
            email,
            new_password: newPassword,
            reset_token
        });
        console.log(res.data)
        notifySuccess('Password reset successful!');
        navigate('/');
    } catch (err) {
      console.log(err.response?.data);
      const errorMsg=err.response?.data?.errors?.details ||
                    err.response?.data?.errors ||
                    err.response?.data?.non_field_errors?.[0] ||
                     'Password reset failed';
      notifyError(errorMsg)
    } finally {
        setLoading(false);
    }
};

  return (
    <div className="flex items-center justify-center min-h-screen bg-white">
      <div className="w-full max-w-sm p-6">
        <form className="space-y-6" onSubmit={handleSubmit}>
          {/* New Password Field */}
          <div>
            <label className="block mb-2 text-sm font-medium text-gray-700">
              New password
            </label>
            <input
              value={newPassword}
              onChange={(e)=>setNewPassword(e.target.value)}
              type="password"
              className="w-full px-3 py-2 border border-gray-200 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>

          {/* Confirm Password Field */}
          <div>
            <label className="block mb-2 text-sm font-medium text-gray-700">
              Confirm password
            </label>
            <input
              value={confirmPassword}
              onChange={(e)=>setConfirmPassword(e.target.value)}
              type="password"
              className="w-full px-3 py-2 border border-gray-200 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>
          {error && (
            <p className="text-red-500 text-sm">{error}</p>
          )}

          {/* Reset Button */}
          <button
            type="submit"
            className="w-full py-3 text-sm font-semibold text-white transition-colors bg-[#0f172a] rounded-md hover:bg-slate-800"
          >
            {loading ? "Resetting..." : "Reset password"}
          </button>
        </form>
      </div>
    </div>
  );
};

export default ResetPassword;