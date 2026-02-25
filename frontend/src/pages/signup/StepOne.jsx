const StepOne = ({ form, setForm, resume, setResume, errors, onNext }) => {
  return (
    <div className="space-y-6">
      {/* Header section */}
      <div className="text-center mb-8">
        <h2 className="text-2xl font-semibold text-[#0f172a]">Agent Application</h2>
      </div>

      <div className="space-y-4">
        {/* Full Name */}
        <div>
          <label className="block text-xs font-medium text-gray-500 mb-1">Full Name</label>
          <input
            className={`w-full p-3 border rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500 ${
              errors.full_name ? "border-red-500" : "border-gray-200"
            }`}
            value={form.full_name || ""}
            onChange={(e) => setForm({ ...form, full_name: e.target.value })}
            placeholder="Enter your full name"
          />
          {errors.full_name && (
            <p className="mt-1 text-xs text-red-600">{errors.full_name}</p>
          )}
        </div>

        {/* Email */}
        <div>
          <label className="block text-xs font-medium text-gray-500 mb-1">Email</label>
          <input
            className={`w-full p-3 border rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500 ${
              errors.email ? "border-red-500" : "border-gray-200"
            }`}
            type="email"
            value={form.email || ""}
            onChange={(e) => setForm({ ...form, email: e.target.value })}
            placeholder="example@email.com"
          />
          {errors.email && (
            <p className="mt-1 text-xs text-red-600">{errors.email}</p>
          )}
        </div>

        <div className="flex gap-4">
          {/* Resume */}
          <div className="flex-1">
            <label className="block text-xs font-medium text-gray-500 mb-1">Resume</label>
            <div
              className={`border rounded-md h-[50px] flex justify-center items-center cursor-pointer transition-colors ${
                resume
                  ? "bg-blue-50 border-blue-200"
                  : errors.resume
                  ? "border-red-500 bg-red-50"
                  : "border-gray-200 hover:bg-gray-50"
              }`}
            >
              <input
                type="file"
                className="hidden"
                id="resume"
                accept=".pdf,.doc,.docx"
                onChange={(e) => setResume(e.target.files[0] || null)}
              />
              <label
                htmlFor="resume"
                className="cursor-pointer w-full h-full flex items-center justify-center px-2"
              >
                {resume ? (
                  <span className="text-[11px] text-blue-700 font-medium truncate block w-full text-center">
                    {resume.name}
                  </span>
                ) : (
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    className="h-5 w-5 text-blue-600"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M4 16v1a2 2 0 002 2h12a2 2 0 002-2v-1m-4-8l-4-4m0 0L8 8m4-4v12"
                    />
                  </svg>
                )}
              </label>
            </div>
            {errors.resume && (
              <p className="mt-1 text-xs text-red-600">{errors.resume}</p>
            )}
          </div>

          {/* Phone */}
          <div className="flex-1">
            <label className="block text-xs font-medium text-gray-500 mb-1">Phone</label>
            <input
              className={`w-full p-3 border rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500 ${
                errors.phone ? "border-red-500" : "border-gray-200"
              }`}
              value={form.phone || ""}
              onChange={(e) => setForm({ ...form, phone: e.target.value })}
              placeholder="+91 98765 43210"
            />
            {errors.phone && (
              <p className="mt-1 text-xs text-red-600">{errors.phone}</p>
            )}
          </div>
        </div>

        <button
          onClick={onNext}
          className="w-full bg-[#0f172a] text-white py-3 rounded-md mt-6 font-medium hover:bg-slate-800 transition-colors"
        >
          Next
        </button>
      </div>
    </div>
  );
};

export default StepOne;