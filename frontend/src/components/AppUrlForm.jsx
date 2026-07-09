import { useState } from "react";
import { updateAppUrl } from "../services/ticketService";
import { notifyError, notifySuccess } from "../utils/notify";

function AppUrlForm() {
  const [appUrl, setAppUrl] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      const res= await updateAppUrl(appUrl);
      notifySuccess(res?.data?.message)
    } catch (err) {
      notifyError(err?.response?.data?.errors?.details);
    }
  };

  return (
    <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">
            Base Application URL
          </label>
          <div className="flex flex-col sm:flex-row items-stretch gap-3">
            <div className="relative flex-1">
              <input
                type="url"
                placeholder="https://shopkickora.com"
                value={appUrl}
                onChange={(e) => setAppUrl(e.target.value)}
                required
                className="w-full bg-slate-50 text-slate-800 text-sm rounded-lg border border-slate-200 px-4 py-2.5 placeholder-slate-400 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/50 transition-all duration-150 shadow-inner"
              />
            </div>
            <button
              type="submit"
              className="px-5 py-2.5 text-sm font-semibold text-white bg-slate-900 hover:bg-slate-800 active:bg-slate-950 rounded-lg shadow-sm transition-colors duration-150 shrink-0 text-center"
            >
              Save Configuration
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}

export default AppUrlForm;