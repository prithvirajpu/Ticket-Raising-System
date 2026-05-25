import React, { useEffect, useState } from 'react'
import DashboardLayout from '../../../layouts/DashboardLayout'
import { getSubscriptionPlans, paymentUpdate } from '../../../services/ticketService'
import { notifyError, notifySuccess } from '../../../utils/notify'

const SubscriptionPlans = () => {
    const [plans,setPlans]=useState([])
    const [loading,setLoading]=useState(true)
    const [loadingPlan,setLoadingPlan]=useState(null)

    useEffect(()=>{
        fetchPlans();
    },[])

    const fetchPlans=async ()=>{
        try {
            const response= await getSubscriptionPlans()
            console.log(response)
            setPlans(response.message)
        } catch (error) {
            console.log(error)
        } finally{
            setLoading(false)
        }
    }
    const handleDemoPayment= async(planId)=>{
        try {
            setLoadingPlan(planId)
            const response=await paymentUpdate(planId);
            notifySuccess(response.message)
        } catch (error) {
            notifyError(error?.response?.data?.errors?.details || 
                'something wrong in demo payment')
        } finally{
            setLoadingPlan(null)
        }
    }

  return (
    <DashboardLayout 
      title="Plans" 
      subtitle="Overview of your Subscription plans"
      headerAction={
        <button className="bg-gray-200 text-black px-4 py-2 rounded-md text-sm font-medium hover:bg-gray-300">
          Manage Plans
        </button>
      }
    >
        {
        loading ? (

          <div className="text-center py-10 text-lg font-medium">
            Loading plans...
          </div>

        ) : (

          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">

            {plans.map((plan) => (

              <div
                key={plan.id}
                className="bg-white rounded-2xl shadow-md border p-6 flex flex-col justify-between"
              >

                <div>

                  <h2 className="text-2xl font-bold mb-2">
                    {plan.name}
                  </h2>

                  <p className="text-4xl font-bold text-blue-600 mb-4">
                    ₹{plan.price}
                  </p>

                  <div className="space-y-3 text-gray-700">

                    <p>
                      <span className="font-semibold">Duration:</span>{" "}
                      {plan.duration_days} Days
                    </p>

                    <p>
                      <span className="font-semibold">Max Agents:</span>{" "}
                      {plan.max_agents}
                    </p>

                    <p>
                      <span className="font-semibold">Max Tickets:</span>{" "}
                      {plan.max_tickets}
                    </p>

                  </div>

                </div>

                <button
                  onClick={() => handleDemoPayment(plan.id)}
                  disabled={loadingPlan === plan.id}
                  className="mt-6 bg-black text-white py-3 rounded-lg hover:bg-gray-800 transition"
                >
                  {
                    loadingPlan === plan.id
                      ? "Processing..."
                      : "Pay Now"
                  }
                </button>

              </div>

            ))}

          </div>

        )
      }

    </DashboardLayout>
  )
}

export default SubscriptionPlans
