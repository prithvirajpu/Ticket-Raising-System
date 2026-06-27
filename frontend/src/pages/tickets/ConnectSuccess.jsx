import React from "react";
import { Link } from "react-router-dom";
import DashboardLayout from "../../layouts/DashboardLayout";
import { CheckCircle2, Wallet, LayoutDashboard } from "lucide-react";

const ConnectSuccess = () => {
  return (
    <DashboardLayout>
      <div className="flex items-center justify-center min-h-[60vh] text-slate-800 antialiased p-4">
        
        {/* SUCCESS CARD CONTAINER */}
        <div className="bg-white border border-slate-200/80 rounded-2xl shadow-xl max-w-md w-full p-8 text-center space-y-6 transform scale-100 transition-all">
          
          {/* SUCCESS STATUS ICON INDICATOR */}
          <div className="flex justify-center">
            <div className="p-3 bg-emerald-50 border border-emerald-100 rounded-2xl animate-bounce duration-1000">
              <CheckCircle2 className="w-12 h-12 text-emerald-500 stroke-[1.5]" />
            </div>
          </div>

          {/* STATUS TEXT CONTEXT */}
          <div className="space-y-2">
            <h2 className="text-xl font-extrabold text-slate-900 tracking-tight">
              Stripe Account Connected
            </h2>
            <p className="text-xs font-medium text-slate-500 leading-relaxed">
              Your Stripe payout account has been successfully connected.
              Once your account verification is completed, you can receive
              withdrawals directly to your bank account.
            </p>
          </div>

          {/* DYNAMIC REDIRECTION CONTROL PLATFORMS */}
          <div className="flex flex-col sm:flex-row gap-2 pt-2 justify-center">
            <Link
              to="/wallet"
              className="inline-flex items-center justify-center gap-1.5 px-4 py-2.5 text-xs font-bold text-white bg-indigo-600 hover:bg-indigo-700 rounded-xl transition-colors shadow-sm"
            >
              <Wallet className="w-3.5 h-3.5" />
              Go to Wallet
            </Link>
          </div>

        </div>

      </div>
    </DashboardLayout>
  );
};

export default ConnectSuccess;