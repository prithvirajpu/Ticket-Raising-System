import React, { useEffect, useState } from 'react'
import DashboardLayout from '../../layouts/DashboardLayout'
import axios from 'axios'
import { createSlaRuleInAdminSide, getSubscriptionPlans, slaRulesInAdminSide } from '../../services/ticketService'
import { notifyError, notifySuccess } from '../../utils/notify'
import HierarchyPage from './HierarchyPage'
import { Clock, Sliders, ChevronDown, ShieldCheck } from 'lucide-react';

const priorities = ['LOW', 'MEDIUM', 'HIGH']

const SlaRules = () => {

  const [rules, setRules] = useState([])
  const [plans,setPlan]=useState([])

  const [formData, setFormData] = useState({
    plan_id: '',
    priority: 'LOW',
    resolution_time_minutes: '',
    auto_reassign: true,
    max_reassign_attempts: 3
  })

  const [loading, setLoading] = useState(false)

  useEffect(() => {
    fetchRules()
  }, [])

  const fetchRules = async () => {
    try {
      const res = await slaRulesInAdminSide()
      setRules(res.message)
      const response= await getSubscriptionPlans()
      setPlan(response.message)
    } catch (error) {
      console.log(error)
    }
  }

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target
    setFormData((prev) => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }))
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    try {
      setLoading(true)
      const res = await createSlaRuleInAdminSide(formData)
      notifySuccess(res.data.message)

      setFormData({
        plan_id: '',
        priority: 'LOW',
        resolution_time_minutes: '',
        auto_reassign: true,
        max_reassign_attempts: 3
      })

      fetchRules()

    } catch (error) {
      notifyError(
        error?.response?.data?.errors?.details ||
        'Something went wrong'
      )
    } finally {
      setLoading(false)
    }
  }

  const getPriorityBadge = (priority) => {
    switch (priority) {
      case 'HIGH':
        return 'bg-red-50 text-red-700 border-red-100';
      case 'MEDIUM':
        return 'bg-amber-50 text-amber-700 border-amber-100';
      default:
        return 'bg-slate-50 text-slate-700 border-slate-200';
    }
  };

  return (
    <DashboardLayout
      title="SLA Rules & Hierarchy"
      subtitle="Manage SLA rules based on plans and ticket priorities"
    >

      <div className="space-y-8 text-slate-800 antialiased">
        
        {/* TOP PANEL SECTION: SLA CONFIGURATIONS GRID */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">

          {/* CREATE RULE FORM */}
          <div className="lg:col-span-4 bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">
            <div className="flex items-center gap-3 border-b border-slate-100 pb-4 mb-5">
              <div className="p-2 bg-slate-50 rounded-lg border border-slate-100 text-slate-700">
                <Sliders className="w-5 h-5" />
              </div>
              <h2 className="text-base font-bold text-slate-900">Create SLA Rule</h2>
            </div>

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block mb-1.5 text-xs font-semibold text-slate-700 tracking-wide uppercase">Plan</label>
                <div className="relative">
                  <select
                    name="plan_id"
                    value={formData.plan_id}
                    onChange={handleChange}
                    className="w-full border border-slate-200 rounded-xl p-3 text-sm bg-white focus:ring-4 focus:ring-slate-950/5 focus:border-slate-950 outline-none appearance-none pr-10 transition-all"
                    required
                  >
                    <option value="">Select Subscription Plan</option>
                    {plans.map((plan) => (
                      <option key={plan.id} value={plan.id}>
                        {plan.name}
                      </option>
                    ))}
                  </select>
                  <ChevronDown className="w-4 h-4 text-slate-400 absolute right-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                </div>
              </div>

              <div>
                <label className="block mb-1.5 text-xs font-semibold text-slate-700 tracking-wide uppercase">Priority</label>
                <div className="relative">
                  <select
                    name="priority"
                    value={formData.priority}
                    onChange={handleChange}
                    className="w-full border border-slate-200 rounded-xl p-3 text-sm bg-white focus:ring-4 focus:ring-slate-950/5 focus:border-slate-950 outline-none appearance-none pr-10 transition-all"
                  >
                    {priorities.map((priority) => (
                      <option key={priority} value={priority}>
                        {priority}
                      </option>
                    ))}
                  </select>
                  <ChevronDown className="w-4 h-4 text-slate-400 absolute right-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                </div>
              </div>

              <div>
                <label className="block mb-1.5 text-xs font-semibold text-slate-700 tracking-wide uppercase">Resolution Time (Minutes)</label>
                <input
                  type="number"
                  name="resolution_time_minutes"
                  value={formData.resolution_time_minutes}
                  onChange={handleChange}
                  placeholder="Enter resolution time"
                  className="w-full border border-slate-200 rounded-xl p-3 text-sm bg-white focus:ring-4 focus:ring-slate-950/5 focus:border-slate-950 outline-none transition-all"
                  required
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full bg-slate-950 text-white py-3 rounded-xl text-sm font-semibold hover:bg-slate-800 transition-all shadow-sm"
              >
                {loading ? 'Creating...' : 'Create Rule'}
              </button>
            </form>
          </div>

          {/* RULE LIST */}
          <div className="lg:col-span-8 bg-white rounded-2xl border border-slate-200 p-6 shadow-sm">
            <div className="flex items-center gap-3 border-b border-slate-100 pb-4 mb-5">
              <div className="p-2 bg-slate-50 rounded-lg border border-slate-100 text-slate-700">
                <Clock className="w-5 h-5" />
              </div>
              <h2 className="text-base font-bold text-slate-900">Existing SLA Rules</h2>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left text-sm">
                <thead>
                  <tr className="border-b border-slate-100 text-[11px] font-bold tracking-wider text-slate-400 uppercase">
                    <th className="pb-3 font-semibold">Plan</th>
                    <th className="pb-3 font-semibold">Priority</th>
                    <th className="pb-3 font-semibold">Resolution</th>
                    <th className="pb-3 font-semibold text-right">Auto assign</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-50 font-medium text-slate-700">
                  {rules.map((rule) => (
                    <tr key={rule.id} className="hover:bg-slate-50/40 transition-colors">
                      <td className="py-3.5 font-bold text-slate-900">{rule.plan_name}</td>
                      <td className="py-3.5">
                        <span className={`text-[11px] px-2.5 py-0.5 rounded-full font-bold border ${getPriorityBadge(rule.priority)}`}>
                          {rule.priority}
                        </span>
                      </td>
                      <td className="py-3.5 text-slate-600 font-mono text-xs">{rule.resolution_time_minutes} mins</td>
                      <td className="py-3.5 text-right">
                        <span className="inline-flex items-center gap-1 text-xs text-emerald-600 font-semibold bg-emerald-50 px-2 py-0.5 rounded-md border border-emerald-100">
                          <ShieldCheck className="w-3 h-3" /> Enabled
                        </span>
                      </td>
                    </tr>
                  ))}
                  {rules.length === 0 && (
                    <tr>
                      <td colSpan="4" className="py-8 text-center text-xs text-slate-400 italic">
                        No operational parameters configured.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

        </div>

        {/* BOTTOM PANEL SECTION: HIERARCHY MAP (Renders clean Split Panel structure automatically) */}
        <HierarchyPage />

      </div>
    </DashboardLayout>
  )
}

export default SlaRules