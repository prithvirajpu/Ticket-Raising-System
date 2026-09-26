import api from "../../api/axios";

export const updateClientProfile= async (data)=>{
    const res = await api.put('/clients/profile/update/',data)
    return res.data.data
}
export const uploadDocument= async (formData)=>{
    const res = await api.post ('/clients/upload/',formData,{
        headers:{
            'Content-Type':'multipart/form-data'
        }
    });
    return res.data.data
}
export const getIntegrationKeys = async ()=>{
    try {
        const res= await api.get("/clients/integration-keys/");
        return res.data.data
    } catch (error) {
        console.log('integration key error')
        console.log(error?.response?.data?.errors?.details)
        throw error
    }
}

export const regenerateIntegrationKeys = async ()=>{
    try {
        const res= await api.patch("/clients/integration/keys/regenerate/");
        return res.data.data
    } catch (error) {
        console.log('regenerate key error')
        console.log(error?.response?.data?.errors?.details)
        throw error
    }
}

export const getSubscriptionPlans= async ()=>{
    try {
        const res= await api.get('/clients/subscription/plans/')
        return res.data.data
    } catch (error) {
        console.log('error in fetch plans')
    }
}

export const getCurrentPlan= async()=>{
    try {
        const res= await api.get('/clients/subscription/current/');
        return res.data.data
    } catch (error) {
        console.log('current subscription plan fetch error')
        throw error
    }
}

export const cancelSubscription=async()=>{
    try {
        const res= await api.post('/clients/subscription/cancel/');
    return res.data.data
    } catch (error) {
        console.log('cancel subscription error ')
    }
}

export const createCheckoutSession= async(planId)=>{
    try {
        const res= await api.post(`/clients/subscriptions/checkout/`,{plan_id:planId})
        return res.data.data
    } catch (error) {
        console.log('error in payment')
        throw error
    }
}
export const getClientDashboard = async()=>{
    try {
        const res = await api.get(`/clients/dashboard/`)
        return res.data.data
    } catch (error) {
        console.log(error)
    }
}
export const updateAppUrl = async (appUrl) => {
    const response = await api.patch("/clients/app-url/", {
        app_url: appUrl,
    });

    return response.data;
};
export const sendClientNotification  = async (ticketId,subject,message) => {
    const response = await api.post("/clients/notify-client/", {
        ticket_id: ticketId,
        subject,message,
    });

    return response.data;
};
export const getClientTickets=async(status='',page=1)=>{
    try{
        const params= {page}
        if(status){
            params.status=status
        }
        const res=await api.get(`/clients/tickets/all/`,{params})
        return res.data
    }catch(error){
        console.log('Get client tickets failed',
            error.response?.data?.error?.details
        )
        throw error
    }
}