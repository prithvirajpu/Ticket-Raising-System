import React, { useEffect, useState } from 'react'
import DashboardLayout from '../../../layouts/DashboardLayout'
import { getSubscriptionPlans, createCheckoutSession, getCurrentPlan, cancelSubscription } from '../../../services/ticketService'
import { notifyError, notifySuccess } from '../../../utils/notify'

const SubscriptionPlans = () => {
    const [plans,setPlans]=useState([])
    const [loading,setLoading]=useState(true)
    const [loadingPlan,setLoadingPlan]=useState(null)
    const [currentPlan, setCurrentPlan] = useState(null);

    useEffect(()=>{
        fetchPlans();
        fetchCurrentPlan();
    },[])
    const fetchCurrentPlan= async()=>{
      const res= await getCurrentPlan();
      setCurrentPlan(res)
    }
    const handleCancelSubscription= async()=>{
      const res= await cancelSubscription();
      notifySuccess(res.message)
      fetchCurrentPlan();
    }

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
    const handlePayment= async(planId)=>{
        try {
            setLoadingPlan(planId)
            const res=await createCheckoutSession (planId);
            window.location.href =res.checkout_url
        } catch (error) {
            notifyError(error?.response?.data?.errors?.details || 
                'Payment initialization failed')
        } finally{
            setLoadingPlan(null)
        }
    }

  return (
    <DashboardLayout 
      title="Plans" 
      subtitle="Overview of your Subscription plans"
    >
     {currentPlan && (
  <div className="bg-green-50 border border-green-200 rounded-2xl p-6 mb-6">

    <h2 className="text-xl font-bold text-green-700 mb-4">
      Current Subscription
    </h2>

    <p>
      <span className="font-semibold">Plan:</span>
      {currentPlan.plan_name}
    </p>

    <p>
      <span className="font-semibold">Status:</span>
      {currentPlan.status}
    </p>

    <p>
      <span className="font-semibold">Start Date:</span>
      {currentPlan.start_date}
    </p>

    <p>
      <span className="font-semibold">End Date:</span>
      {currentPlan.end_date}
    </p>

    {currentPlan.cancel_at_period_end ? (
      <div className="mt-4 text-red-600 font-medium">
        Subscription will end on {currentPlan.end_date}
      </div>
    ) : (
      <button
        onClick={handleCancelSubscription}
        className="mt-4 bg-red-600 text-white px-4 py-2 rounded"
      >
        Cancel Subscription
      </button>
    )}
  </div>
)}
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
                  onClick={() => handlePayment(plan.id)}
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
