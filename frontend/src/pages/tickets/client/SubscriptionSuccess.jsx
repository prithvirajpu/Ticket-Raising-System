import React from 'react'
import { CheckCircle2, ArrowRight } from 'lucide-react'
import DashboardLayout from '../../../layouts/DashboardLayout'
import { useNavigate } from 'react-router-dom'

const SubscriptionSuccess = () => {
    const navigate=useNavigate()
  return (
    <DashboardLayout>
      <div className="flex flex-col items-center justify-center min-h-[70vh] px-4">
        <div className="max-w-md w-full bg-white border border-slate-100 rounded-2xl p-8 shadow-sm text-center">
          
          {/* Icon Badge */}
          <div className="mx-auto flex items-center justify-center h-16 w-16 rounded-full bg-emerald-50 border border-emerald-100 mb-6">
            <CheckCircle2 className="h-8 w-8 text-emerald-500" />
          </div>

          {/* Heading */}
          <h2 className="text-2xl font-semibold text-slate-900 tracking-tight mb-2">
            Subscription Successful!
          </h2>
          
          {/* Description */}
          <p className="text-slate-500 text-sm leading-relaxed mb-8">
            Thank you for upgrading. Your account has been successfully updated, and your new premium features are now unlocked.
          </p>

          {/* Action Buttons */}
          <div className="space-y-3">
            <button 
              onClick={()=>navigate('/client/dashboard')}
              className="w-full flex items-center justify-center gap-2 bg-slate-950 text-white font-medium text-sm py-3 px-4 rounded-xl hover:bg-slate-800 transition-colors duration-200 shadow-sm"
            >
              Go to Dashboard
              <ArrowRight className="h-4 w-4" />
            </button>
            
          </div>

        </div>
      </div>
    </DashboardLayout>
  )
}

export default SubscriptionSuccess