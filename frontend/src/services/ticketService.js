import { ServerCog } from 'lucide-react'
import api from '../api/axios'
import { notifyError } from '../utils/notify'

export const createTicket= async(data)=>{
    try {
        const response= await api.post('/users/tickets/create/',data)
    return response.data.data
    } catch (error) {
        console.log("CREATE TICKET FAILED ❌")
        throw error
    }
}

export const getTickets=async ({search='',sort='newest',page=1})=>{
    const params={sort,page};
    if (search){
        params.search=search;
    }
    const response=await api.get(`/users/tickets/list/`,{params})
    return response.data.data
}

export const getUserTicketDetail= async(id)=>{
    const response=await api.get(`/users/details/${id}/`);
    return response.data.data
}

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

export const resolveTicket = async (id) => {
  const res = await api.post(`/tickets/${id}/resolve/`);
  return res.data.data;
};

export const closeTicket= async (id) =>{
    const res = await api.post(`/users/tickets/${id}/close/`)
    return res.data.data
}

export const submitReview=async(id,data)=>{
    const res= await api.post(`/users/tickets/${id}/review/`,data);
    return res.data.data
}

export const escalateTicket=async(id)=>{
    try {
        const res= await api.post(`/tickets/${id}/escalate/`);
    return res.data.data
    } catch (error) {
        const err=error.response?.data?.errors?.details ||'my error'
        console.log(err)
    }
}

export const getProfile=async()=>{
    const res= await api.get('/users/profile')
    return res.data.data
}

export const updateProfile= async (data)=>{
    const res = await api.put('/users/profile/update/',data)
    return res.data.data
}

export const getTeamLeadTickets=async()=>{
    const res= await api.get('/team-leads/assigned-tickets/');
    return res.data.data 
}

export const getManagerTickets=async ()=>{
    const res= await api.get('/managers/tickets/');
    return res.data.data
}

export const uploadDocument= async (formData)=>{
    try {
        const res = await api.post ('/clients/upload/',formData,{
            headers:{
                'Content-Type':'multipart/form-data'
            }
        });
        return res.data.data
    } catch (error) {
        console.log(error)
    }
}

export const getClientsWithDocs=async()=>{
    const res= await api.get('/managers/clients-docs/');
    return res.data.data;
}

export const getClientDocs= async(clientId)=>{
    try {
    const res= await api.get(`/managers/clients-docs/${clientId}/`);
    return res.data.data    
    } catch (error) {
        console.log(error?.response?.data?.errors?.details ||' something wrong')
        throw error
    }
}

export const summarizeAllDocuments=async (docId)=>{
    const res= await api.post(`/managers/summarize/${docId}/`)
    return res.data.data
}

export const summarySubmit =async (docId,data)=>{
    const res= await api.post(`/managers/submit-summary/${docId}/`,data)
    return res.data.data
}

export const getTeamLeadSummaries = async() =>{
    const res = await api.get('/team-leads/summaries/');
    return res.data.data
}

export const generateAgentSummary= async (summary_id)=>{
    const res= await api.post(`/team-leads/generate-agent-summary/${summary_id}/`);
    return res.data.data
}

export const submitAgentSummary= async (summary_id,data)=>{
    const res = await api.post(`/team-leads/submit-summary/${summary_id}/`,data);
    return res.data.data
}

export const getAgentSummary=async ()=>{
    try {
        const res= await api.get('/agents/summary/')
        return res.data.data
    } catch (error) {
        console.log(error ||'something wrong')
    }
}

export const getDashboard=async (role)=>{
    try {
        const res= await api.get('/tickets/dashboard/')
        return res.data.data
    } catch (error) {
        notifyError('something went wrong')
    }
}

export const generateFakeTickets= async (summary)=>{
    try {
        const res= await api.post('/team-leads/generate-fake-tickets/',{
        summary:summary,
        count:3,
    });
    return res.data.data
    } catch (error) {
        notifyError('generate ticket--')
    }
}

export const getAgentFakeTickets= async()=>{
    try {
        const res= await api.get('/agents/fake-tickets/');
    return res.data.data
    } catch (error) {
        notifyError('fake ticket fetch error')
    }
}

export const getFakeTicketDetail = async(id)=>{
    try {
        const res= await api.get(`/agents/fake-tickets/${id}/`);
        console.log(res.data.data.message)
    return res.data.data
    } catch (error) {
        notifyError('fake ticket detail page error')
    }
}

export const getTicketMessages= async(ticketId)=>{
    try {
        const res= await api.get(`/tickets/${ticketId}/messages/`)
        return res.data
    } catch (error) {
        console.log("Error fetching messages:", error);
        throw error;
    }
}

export const sendMessage=async(ticketId,message)=>{
    try {
        const res= await api.post(`/tickets/${ticketId}/send-message/`,{message});
        return res.data
    } catch (error) {
        console.log('error sending message: ',error);
        throw error;       
    }
}

export const reopenTicket= async(ticketId)=>{
   try {
     const res= await api.patch(`/users/${ticketId}/reopen/`)
    return res.data.data
   } catch (error) {
    console.log('something wrong with REOPEN')
    console.log(error.response?.data)
    console.log(error)
   }
}

export const getTicketTimeline= async(ticketId)=>{
   try {
     const res= await api.get(`/users/${ticketId}/timeline/`)
    return res.data.data
   } catch (error) {
    console.log('something wrong with timeline')
    console.log(error.response?.data)
    console.log(error)
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
