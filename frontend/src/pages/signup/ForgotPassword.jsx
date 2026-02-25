import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import api from '../../api/axios';
import { notifyError, notifySuccess, notifyWarning, notifyInfo } from "../../utils/notify";
import Loader from '../../components/modals/Loader'

const ForgotPassword = () => {
  const [email, setEmail] = useState('');
  const [loading,setLoading]=useState(false)
  const navigate=useNavigate()

 const handleSubmit = async(e) => {
    e.preventDefault();
    setLoading(true);
    
    try {
        const res = await api.post('/auth/forgot-password/', { email }); 
        notifySuccess('OTP sent to your email! Check your inbox.');
        navigate('/verify-otp', { 
            state: { 
                email: email,
                purpose: 'RESET',
                expiresAt: res.data.expires_at } 
        });   
    } catch (error) {
        notifyError('Failed to send OTP. Please try again.');
    }finally{
      setLoading(false);
    }
};

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-white p-4">
      {loading && <Loader />}
      <div className="w-full max-w-[400px] space-y-8">
        
        {/* Instructional Text */}
        <p className="text-gray-500 text-[15px] leading-relaxed text-center px-2">
          Please enter the email address associated with your account. 
          We'll promptly send you a link to reset your password.
        </p>

        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Email Input */}
          <div className="space-y-1">
            <label htmlFor="email" className="block text-sm font-semibold text-gray-700">
              Email
            </label>
            <input
              id="email"
              type="email"
              required
              className="w-full p-3 border border-gray-200 rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500 transition-all shadow-sm"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            className="w-full bg-[#0f172a] text-white py-3.5 rounded-md font-semibold text-[15px] hover:bg-slate-800 transition-colors shadow-sm"
          >
            Send reset link
          </button>
        </form>

        {/* Footer Link */}
        <div className="text-center">
          <p className="text-sm text-gray-600">
            Remembered your password?{' '}
            <Link to="/" className="text-blue-600 font-medium hover:underline">
              Login here
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default ForgotPassword;