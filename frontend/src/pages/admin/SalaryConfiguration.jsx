import { useEffect, useState } from "react";
import {
  getSalaryConfig,
  createSalaryConfig,
  updateSalaryConfig,
} from "../../services/admin/ticketService";
import { validateSalaryConfig } from "../../validation/salaryValidation";

const SalaryConfiguration = () => {
  const [config, setConfig] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  // Field-specific inline errors state
  const [fieldErrors, setFieldErrors] = useState({});
  const [apiError, setApiError] = useState("");

  const [formData, setFormData] = useState({
    agent_percentage: "",
    incentive_percentage: "",
    team_lead_percentage: "",
    manager_percentage: "",
  });

  const fetchConfig = async () => {
    setLoading(true);
    setApiError("");

    try {
      const result = await getSalaryConfig();
      const data = result?.data;

      if (data) {
        setConfig(data);
        setFormData({
          agent_percentage: data.agent_percentage ?? "",
          incentive_percentage: data.incentive_percentage ?? "",
          team_lead_percentage: data.team_lead_percentage ?? "",
          manager_percentage: data.manager_percentage ?? "",
        });
      }
    } catch (error) {
      const errors = error.response?.data?.errors;
      if (errors?.details === "Salary configuration not found.") {
        setConfig(null);
        setLoading(false);
        return;
      }
      setApiError(errors?.details || "Failed to load salary configuration");
    }

    setLoading(false);
  };

  useEffect(() => {
    fetchConfig();
  }, []);

  const handleChange = (e) => {
    const { name, value } = e.target;

    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));

    // Clear inline error when user types
    if (fieldErrors[name]) {
      setFieldErrors((prev) => ({
        ...prev,
        [name]: "",
      }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setApiError("");

    // Validate using custom validator function
    const { isValid, errors } = validateSalaryConfig(formData);

    if (!isValid) {
      setFieldErrors(errors);
      return;
    }

    setFieldErrors({});
    setSaving(true);

    const payload = {
      agent_percentage: formData.agent_percentage,
      incentive_percentage: formData.incentive_percentage,
      team_lead_percentage: formData.team_lead_percentage,
      manager_percentage: formData.manager_percentage,
    };

    try {
      let result;
      if (config) {
        result = await updateSalaryConfig(payload);
      } else {
        result = await createSalaryConfig(payload);
      }

      if (result.errors) {
        setApiError(
          typeof result.errors === "string"
            ? result.errors
            : "Failed to save salary configuration"
        );
        setSaving(false);
        return;
      }

      setSaving(false);
      await fetchConfig();
    } catch (error) {
      setApiError(
        error.response?.data?.errors?.details ||
          "Failed to save salary configuration"
      );
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[300px] text-gray-500 font-medium animate-pulse">
        Loading salary configuration...
      </div>
    );
  }

  const companyPercentage = Math.max(
    0,
    100 -
      Number(formData.agent_percentage || 0) -
      Number(formData.incentive_percentage || 0) -
      Number(formData.team_lead_percentage || 0) -
      Number(formData.manager_percentage || 0)
  );

  return (
    <div className="max-w-6xl mx-auto p-6 md:p-8">
      {/* Header section */}
      <div className="mb-8">
        <h1 className="text-2xl font-bold tracking-tight text-gray-900">
          Salary Configuration
        </h1>
        <p className="mt-1 text-sm text-gray-500">
          Configure revenue share allocations across organizational roles.
        </p>
      </div>

      {/* Global API / Overhead Error Banner */}
      {(apiError || fieldErrors.total) && (
        <div className="mb-6 flex items-center gap-3 p-4 rounded-xl border border-red-200 bg-red-50 text-red-800 text-sm shadow-sm">
          <span className="font-bold">⚠️</span>
          <div className="flex-1 font-medium">
            {apiError || fieldErrors.total}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* Form Card */}
        <form
          onSubmit={handleSubmit}
          noValidate
          className="lg:col-span-8 bg-white p-6 md:p-8 rounded-2xl border border-gray-200/80 shadow-sm space-y-6"
        >
          {/* 2-Column Grid for Inputs */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
            
            {/* Agent Percentage */}
            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-1">
                Agent Percentage (%)
              </label>
              <input
                type="number"
                name="agent_percentage"
                value={formData.agent_percentage}
                onChange={handleChange}
                step="0.01"
                className={`w-full border rounded-lg px-3.5 py-2.5 text-gray-900 shadow-sm placeholder:text-gray-400 focus:outline-none focus:ring-2 transition ${
                  fieldErrors.agent_percentage
                    ? "border-red-500 focus:ring-red-500"
                    : "border-gray-300 focus:ring-black"
                }`}
                placeholder="10 - 50"
              />
              {fieldErrors.agent_percentage && (
                <p className="mt-1 text-xs text-red-600 font-medium">
                  {fieldErrors.agent_percentage}
                </p>
              )}
            </div>

            {/* Incentive Percentage */}
            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-1">
                Incentive Percentage (%)
              </label>
              <input
                type="number"
                name="incentive_percentage"
                value={formData.incentive_percentage}
                onChange={handleChange}
                step="0.01"
                className={`w-full border rounded-lg px-3.5 py-2.5 text-gray-900 shadow-sm placeholder:text-gray-400 focus:outline-none focus:ring-2 transition ${
                  fieldErrors.incentive_percentage
                    ? "border-red-500 focus:ring-red-500"
                    : "border-gray-300 focus:ring-black"
                }`}
                placeholder="Under 8"
              />
              {fieldErrors.incentive_percentage && (
                <p className="mt-1 text-xs text-red-600 font-medium">
                  {fieldErrors.incentive_percentage}
                </p>
              )}
            </div>

            {/* Team Lead Percentage */}
            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-1">
                Team Lead Percentage (%)
              </label>
              <input
                type="number"
                name="team_lead_percentage"
                value={formData.team_lead_percentage}
                onChange={handleChange}
                step="0.01"
                className={`w-full border rounded-lg px-3.5 py-2.5 text-gray-900 shadow-sm placeholder:text-gray-400 focus:outline-none focus:ring-2 transition ${
                  fieldErrors.team_lead_percentage
                    ? "border-red-500 focus:ring-red-500"
                    : "border-gray-300 focus:ring-black"
                }`}
                placeholder="Up to 15"
              />
              {fieldErrors.team_lead_percentage && (
                <p className="mt-1 text-xs text-red-600 font-medium">
                  {fieldErrors.team_lead_percentage}
                </p>
              )}
            </div>

            {/* Manager Percentage */}
            <div>
              <label className="block text-sm font-semibold text-gray-700 mb-1">
                Manager Percentage (%)
              </label>
              <input
                type="number"
                name="manager_percentage"
                value={formData.manager_percentage}
                onChange={handleChange}
                step="0.01"
                className={`w-full border rounded-lg px-3.5 py-2.5 text-gray-900 shadow-sm placeholder:text-gray-400 focus:outline-none focus:ring-2 transition ${
                  fieldErrors.manager_percentage
                    ? "border-red-500 focus:ring-red-500"
                    : "border-gray-300 focus:ring-black"
                }`}
                placeholder="Up to 10"
              />
              {fieldErrors.manager_percentage && (
                <p className="mt-1 text-xs text-red-600 font-medium">
                  {fieldErrors.manager_percentage}
                </p>
              )}
            </div>

          </div>

          <div className="pt-4 border-t border-gray-100 flex justify-end">
            <button
              type="submit"
              disabled={saving}
              className="w-full sm:w-auto px-6 py-2.5 rounded-lg bg-black hover:bg-gray-800 text-white font-medium text-sm shadow-sm transition disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {saving
                ? "Saving..."
                : config
                ? "Update Configuration"
                : "Create Configuration"}
            </button>
          </div>
        </form>

        {/* Summary Card */}
        <div className="lg:col-span-4 bg-gray-50/80 p-6 rounded-2xl border border-gray-200/80 shadow-sm space-y-4">
          <div>
            <h2 className="text-base font-semibold text-gray-900">
              Distribution Summary
            </h2>
            <p className="text-xs text-gray-500 mt-0.5">
              Live calculation of total distribution.
            </p>
          </div>

          <div className="divide-y divide-gray-200/60 text-sm">
            <div className="flex justify-between py-2 text-gray-600">
              <span>Agent</span>
              <span className="font-semibold text-gray-900">
                {formData.agent_percentage || 0}%
              </span>
            </div>

            <div className="flex justify-between py-2 text-gray-600">
              <span>Incentive</span>
              <span className="font-semibold text-gray-900">
                {formData.incentive_percentage || 0}%
              </span>
            </div>

            <div className="flex justify-between py-2 text-gray-600">
              <span>Team Lead</span>
              <span className="font-semibold text-gray-900">
                {formData.team_lead_percentage || 0}%
              </span>
            </div>

            <div className="flex justify-between py-2 text-gray-600">
              <span>Manager</span>
              <span className="font-semibold text-gray-900">
                {formData.manager_percentage || 0}%
              </span>
            </div>

            <div className="flex justify-between pt-3 pb-1 text-gray-900 font-semibold border-t border-gray-200">
              <span>Company Share</span>
              <span
                className={
                  companyPercentage < 0 ? "text-red-600" : "text-emerald-700"
                }
              >
                {companyPercentage}%
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SalaryConfiguration;