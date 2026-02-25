const StepTwo = ({ form, setForm,certificates, setCertificates, errors, onNext }) => {
  return (
    <div className="space-y-6">
      <div className="text-center mb-8">
        <h2 className="text-2xl font-semibold text-[#0f172a]">Agent Application</h2>
        <p className="text-sm text-gray-500 mt-2">Tell us about your skills & certificates</p>
      </div>

      <div className="space-y-4">
        {/* Skills */}
        <div>
          <label className="block text-xs font-medium text-gray-500 mb-1">Skills</label>
          <textarea
            className={`w-full p-3 border rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500 min-h-[100px] ${
              errors.skills ? "border-red-500" : "border-gray-200"
            }`}
            value={form.skills || ""}
            onChange={(e) => setForm({ ...form, skills: e.target.value })}
            placeholder="List your key skills "
          />
          {errors.skills && (
            <p className="mt-1 text-xs text-red-600">{errors.skills}</p>
          )}
        </div>

        {/* Certificates */}
        <div>
          <label className="block text-xs font-medium text-gray-500 mb-1">
            Certificates (Optional)
          </label>
          <div className="flex gap-2">
            <input
              className="flex-1 p-3 border rounded-md bg-gray-50 text-gray-500"
              placeholder={
                certificates.length > 0
                  ? `${certificates.length} file${certificates.length > 1 ? "s" : ""} selected`
                  : "No files chosen"
              }
              readOnly
            />
            <label className="border border-gray-300 px-4 py-3 rounded-md cursor-pointer hover:bg-gray-50 transition-colors">
              <span className="text-sm font-medium">Upload</span>
              <input
                type="file"
                multiple
                className="hidden"
                accept=".pdf,.doc,.docx,.jpg,.jpeg,.png"
                onChange={(e) => setCertificates(Array.from(e.target.files || []))}
              />
            </label>
          </div>
          {errors.certificates && (
            <p className="mt-1 text-xs text-red-600">{errors.certificates}</p>
          )}
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

export default StepTwo;