import React, { useEffect, useState } from 'react'
import DashboardLayout from '../../layouts/DashboardLayout'
import axios from 'axios'
import { createSlaRuleInAdminSide, getSubscriptionPlans, slaRulesInAdminSide } from '../../services/ticketService'
import { notifyError, notifySuccess } from '../../utils/notify'

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
      notifySuccess(res.message)

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

  return (
    <DashboardLayout
      title="SLA Rules"
      subtitle="Manage SLA rules based on plans and ticket priorities"
      headerAction={
        <button className="bg-gray-200 text-black px-4 py-2 rounded-md text-sm font-medium hover:bg-gray-300">
          Manage Rules
        </button>
      }
    >

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* CREATE RULE FORM */}

        <div className="bg-white rounded-2xl shadow p-6">

          <h2 className="text-xl font-bold mb-5">
            Create SLA Rule
          </h2>

          <form onSubmit={handleSubmit} className="space-y-4">

            <div>

              <label className="block mb-2 text-sm font-medium">
                Plan 
              </label>

              <select
  name="plan_id"
  value={formData.plan_id}
  onChange={handleChange}
  className="w-full border rounded-lg p-3"
  required
>

  <option value="">
    Select Subscription Plan
  </option>

  {plans.map((plan) => (

    <option
      key={plan.id}
      value={plan.id}
    >
      {plan.name}
    </option>

  ))}

</select>

            </div>

            <div>

              <label className="block mb-2 text-sm font-medium">
                Priority
              </label>

              <select
                name="priority"
                value={formData.priority}
                onChange={handleChange}
                className="w-full border rounded-lg p-3"
              >

                {priorities.map((priority) => (

                  <option key={priority} value={priority}>
                    {priority}
                  </option>

                ))}

              </select>

            </div>

            <div>

              <label className="block mb-2 text-sm font-medium">
                Resolution Time (Minutes)
              </label>

              <input
                type="number"
                name="resolution_time_minutes"
                value={formData.resolution_time_minutes}
                onChange={handleChange}
                placeholder="Enter resolution time"
                className="w-full border rounded-lg p-3"
                required
              />

            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-black text-white py-3 rounded-lg hover:bg-gray-800"
            >
              {
                loading
                  ? 'Creating...'
                  : 'Create Rule'
              }
            </button>

          </form>

        </div>

        {/* RULE LIST */}

        <div className="lg:col-span-2 bg-white rounded-2xl shadow p-6">

          <h2 className="text-xl font-bold mb-5">
            Existing SLA Rules
          </h2>

          <div className="overflow-x-auto">

            <table className="w-full border-collapse">

              <thead>

                <tr className="border-b text-left">

                  <th className="py-3">Plan</th>
                  <th className="py-3">Priority</th>
                  <th className="py-3">Resolution</th>
                  <th className="py-3">Auto assign</th>

                </tr>

              </thead>

              <tbody>

                {rules.map((rule) => (

                  <tr key={rule.id} className="border-b">

                    <td className="py-4">
                      {rule.plan_name}
                    </td>

                    <td className="py-4">
                      {rule.priority}
                    </td>

                    <td className="py-4">
                      {rule.resolution_time_minutes} mins
                    </td>

                    <td className="py-4">
                        Enabled
                    </td>

                  </tr>

                ))}

              </tbody>

            </table>

          </div>

        </div>

      </div>

    </DashboardLayout>
  )
}

export default SlaRules