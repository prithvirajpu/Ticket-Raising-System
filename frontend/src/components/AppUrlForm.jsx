import { useState } from "react";
import { updateAppUrl } from "../services/ticketService";
import { notifyError, notifySuccess } from "../utils/notify";

function AppUrlForm() {
  const [appUrl, setAppUrl] = useState("");
  const [urlError, setUrlError] = useState("");

  const validateUrl=(url)=>{
    try{
      const parsedUrl=new URL(url)
      if(!["http:","https:"].includes(parsedUrl.protocol)){
        return "URL must start with https://"
      }
      if(!parsedUrl.hostname){
        return 'Please enter a valid application URL'
      }
      return ''
    }catch{
      return 'Please enter a valid URL'
    }
  }
  const handleSubmit = async (e) => {
    e.preventDefault();
    const error= validateUrl(appUrl)
    if(error){
      setUrlError(error)
      return;
    }
    setUrlError('')
    try {
      const res= await updateAppUrl(appUrl);
      notifySuccess(res?.data?.message)
    } catch (err) {
      notifyError(err?.response?.data?.errors?.details ||
        'Failed to update application URL'
      );
    }
  };
  const handleURLChange=(e)=>{
    const value=e.target.value
    setAppUrl(value);
    if(urlError){
      setUrlError('');
    }
  }

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
                // type="url"
                placeholder="https://shopkickora.com"
                value={appUrl}
                onChange={handleURLChange}
                required
                className={`w-full bg-slate-50 text-slate-800 text-sm rounded-lg border px-4 py-2.5 placeholder-slate-400 focus:outline-none focus:ring-1 transition-all duration-150 shadow-inner ${ urlError ? "border-red-500 focus:border-red-500 focus:ring-red-500/50" : "border-slate-200 focus:border-indigo-500 focus:ring-indigo-500/50" }`}
              />
              {urlError && ( <p className="mt-2 text-sm text-red-500"> {urlError} </p> )}
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