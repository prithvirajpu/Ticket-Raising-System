import api from "../../api/axios";

export const getAgentTicketDetail= async(id)=>{
    const response=await api.get(`/agents/details/${id}/`);
    return response.data.data
}

export const getAgentRequests=async ({search='',sort='newest',page=1})=>{
    const params={sort,page}
    if (search){
        params.search=search
    }
    const res= await api.get(`/agents/requests/`,{params})
    return res.data.data
}

export const acceptTicket = async (id) => {
    try {
        const res = await api.post(`/agents/${id}/accept/`);
        return res.data.data;
    } catch (error) {
        console.log("❌ TICKET ACCEPT API CALL FAILED =====================");
        throw error;
    }
};

export const rejectTicket =async (id)=>{
    const res= await api.post(`/agents/${id}/reject/`)
    return res.data.data
}

export const getOngoingTickets = async ({search='',sort='newest',page=1}) => {
    const params={sort,page}
    if (search){
        params.search=search
    }
  const res = await api.get(`/agents/in-progress/`,{params});
  return res.data.data;
};
export const getAgentSummary=async ()=>{
    try {
        const res= await api.get('/agents/summary/')
        return res.data.data
    } catch (error) {
        console.log(error ||'something wrong')
    }
}

export const getAgentDashboard=async (role)=>{
    try {
        const res= await api.get('/agents/dashboard/')
        return res.data.data
    } catch (error) {
        console.log('something went wrong')
    }
}
export const getAgentFakeTickets= async()=>{
    try {
        const res= await api.get('/agents/fake-tickets/');
    return res.data.data
    } catch (error) {
        console.log('fake ticket fetch error')
    }
}

export const getFakeTicketDetail = async(id)=>{
    try {
        const res= await api.get(`/agents/fake-tickets/${id}/`);
        console.log(res.data.data.message)
    return res.data.data
    } catch (error) {
        console.log('fake ticket detail page error')
    }
}
export const verifyTicketDetails =async (payload)=>{
    try {
        const res= await api.post('/agents/verify/',payload);
        return res.data.data
    } catch (error) {
        console.log('verify error: ',error.response?.data)

        console.log('something wrong with verifyticket')
        throw error.response?.data ||error
    }
}
export const retryTraining =async(Id)=>{
    try {
        const res= await api.post(`/agents/training/${Id}/retry/`)
        return res.data.data
    } catch (error) {
        console.log(error)
    }
}