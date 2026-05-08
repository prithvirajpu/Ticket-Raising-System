import { useState, useEffect } from "react";

const EditProfileModal = ({ isOpen, onClose, initialData, onSave, saving }) => {
  const [editData, setEditData] = useState({ ...initialData });
  const [error, setError] = useState("");

  useEffect(() => {
    if (isOpen) {
      setEditData({ ...initialData });
      setError(""); // Reset errors when modal opens
    }
  }, [isOpen, initialData]);

  if (!isOpen) return null;

  const validatePhone = (phone) => {
    // Basic regex: allows +, spaces, dashes, and 10-15 digits
    const phoneRegex = /^\+?[\d\s\-]{10,15}$/;
    return phoneRegex.test(phone);
  };

  const handleChange = (e) => {
    setEditData({ ...editData, [e.target.name]: e.target.value });
    // Clear error as user types
    if (error) setError("");
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    
    // Validation Logic
    if (editData.phone && !validatePhone(editData.phone)) {
      setError("Please enter a valid phone number (10-15 digits).");
      return;
    }

    onSave(editData);
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
      <div 
        className="absolute inset-0 bg-slate-900/40 backdrop-blur-md transition-opacity" 
        onClick={onClose} 
      />

      <div className="relative bg-white rounded-[2.5rem] shadow-2xl w-full max-w-md overflow-hidden animate-in fade-in zoom-in duration-300">
        <div className="h-2 bg-gradient-to-r from-indigo-500 via-purple-500 to-violet-500" />

        <div className="p-8">
          <div className="mb-8 text-center">
            <h2 className="text-2xl font-extrabold text-slate-900 tracking-tight">Edit Profile</h2>
            <p className="text-slate-500 text-sm mt-1">Update your personal account details</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Name Input */}
            <div className="space-y-1.5">
              <label className="text-[11px] uppercase tracking-widest font-bold text-slate-400 ml-1">
                Full Name
              </label>
              <input
                name="name"
                type="text"
                value={editData.name || ""}
                onChange={handleChange}
                className="w-full px-4 py-3.5 bg-slate-50 border border-slate-200 rounded-2xl focus:bg-white focus:ring-4 focus:ring-indigo-500/10 focus:border-indigo-500 outline-none transition-all text-slate-800 font-medium"
              />
            </div>

            {/* Email Input */}
            <div className="space-y-1.5">
              <label className="text-[11px] uppercase tracking-widest font-bold text-slate-400 ml-1">
                Email Address
              </label>
              <input
                value={editData.email}
                disabled
                className="w-full px-4 py-3.5 bg-slate-100 border border-slate-200 rounded-2xl text-slate-400 cursor-not-allowed font-medium"
              />
            </div>

            {/* Phone Input with Validation Styling */}
            <div className="space-y-1.5">
              <label className="text-[11px] uppercase tracking-widest font-bold text-slate-400 ml-1">
                Phone Number
              </label>
              <input
                name="phone"
                type="tel"
                value={editData.phone || ""}
                onChange={handleChange}
                placeholder="e.g. +1 234 567 890"
                className={`w-full px-4 py-3.5 border rounded-2xl outline-none transition-all font-medium ${
                  error 
                  ? "bg-red-50 border-red-300 focus:ring-4 focus:ring-red-500/10 text-red-900" 
                  : "bg-slate-50 border-slate-200 focus:bg-white focus:ring-4 focus:ring-indigo-500/10 focus:border-indigo-500 text-slate-800"
                }`}
              />
              {error && (
                <p className="text-red-500 text-xs font-semibold ml-1 animate-in fade-in slide-in-from-top-1">
                  {error}
                </p>
              )}
            </div>

            {/* Actions */}
            <div className="flex flex-col sm:flex-row gap-3 pt-6">
              <button
                type="button"
                onClick={onClose}
                className="flex-1 px-6 py-3.5 border border-slate-200 text-slate-600 font-bold rounded-2xl hover:bg-slate-50 active:scale-95 transition-all order-2 sm:order-1"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={saving}
                className="flex-[2] px-6 py-3.5 bg-slate-900 text-white font-bold rounded-2xl hover:bg-black shadow-lg shadow-slate-200 active:scale-95 disabled:bg-slate-400 transition-all flex items-center justify-center gap-2 order-1 sm:order-2"
              >
                {saving ? "Saving..." : "Save Changes"}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default EditProfileModal;