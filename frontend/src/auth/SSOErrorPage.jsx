import { useSearchParams } from "react-router-dom";
// Make sure to install lucide-react if you haven't already: npm i lucide-react
import { AlertCircle, ArrowLeft } from "lucide-react";

const SSOErrorPage = () => {
  const [searchParams] = useSearchParams();
  const code = searchParams.get("code");

  const errorMap = {
    role_conflict:
      "Please use another email or contact support.",
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50 px-4">
      <div className="bg-white rounded-xl shadow-xl p-8 max-w-md w-full text-center border border-slate-100 transition-all">
        
        {/* Warning Icon Badge */}
        <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-rose-50 border border-rose-100 text-rose-600 mb-5">
          <AlertCircle size={24} />
        </div>

        {/* Heading */}
        <h2 className="text-2xl font-bold text-slate-900 tracking-tight">
          SSO Login Failed
        </h2>
        
        <p className="mt-2 text-sm text-slate-500">
          We encountered an issue while authenticating your account.
        </p>

        {/* Dynamic Error Content Box */}
        <div className="mt-6 p-4 bg-rose-50/50 border border-rose-100 rounded-lg text-sm text-rose-900 font-medium leading-relaxed">
          {errorMap[code] || "Something went wrong during SSO login."}
        </div>

        {/* Action Button */}
        <div className="mt-8">
          <a
            href="/"
            className="inline-flex items-center justify-center gap-2 w-full px-4 py-2.5 bg-slate-900 hover:bg-slate-800 text-white text-sm font-semibold rounded-lg shadow-sm hover:shadow transition-all group"
          >
            <ArrowLeft size={16} className="transform group-hover:-translate-x-0.5 transition-transform" />
            Go back to login
          </a>
        </div>
        
      </div>
    </div>
  );
};

export default SSOErrorPage;