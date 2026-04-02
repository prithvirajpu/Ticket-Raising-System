import { ServerCog } from 'lucide-react'
import api from '../api/axios'

export const createTicket= async(data)=>{
    const response= await api.post('/tickets/create/',data)
    return response.data.data
}

export const getTickets=async ({search='',sort='newest'})=>{
    const params={sort};
    if (search){
        params.search=search;
    }
    const response=await api.get(`/tickets/list/`,{params})
    return response.data.data
}

export const getTicketDetail= async(id)=>{
    const response=await api.get(`/tickets/details/${id}/`);
    return response.data.data
}

export const getAgentRequests=async ({search='',sort='newest'})=>{
    const params={sort}
    if (search){
        params.search=search
    }
    const res= await api.get(`/tickets/agents/requests/`,{params})
    return res.data.data
}

export const acceptTicket =async (id)=>{
    const res= await api.post(`/tickets/${id}/accept/`)
    return res.data.data
}

export const rejectTicket =async (id)=>{
    const res= await api.post(`/tickets/${id}/reject/`)
    return res.data.data
}

export const getOngoingTickets = async ({search='',sort='newest'}) => {
    const params={sort}
    if (search){
        params.search=search
    }
  const res = await api.get(`/tickets/agents/in-progress/`,{params});
  return res.data.data;
};

export const resolveTicket = async (id) => {
  const res = await api.post(`/tickets/${id}/resolve/`);
  return res.data.data;
};

export const closeTicket= async (id) =>{
    const res = await api.post(`/tickets/${id}/close/`)
    return res.data.data
}

export const submitReview=async(id,data)=>{
    const res= await api.post(`/tickets/${id}/review/`,data);
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
    const res= await api.get('/tickets/user/profile')
    return res.data.data
}

export const updateProfile= async (data)=>{
    const res = await api.put('/tickets/user/profile/update/',data)
    return res.data.data
}

export const getTeamLeadTickets=async()=>{
    const res= await api.get('/tickets/team-lead/assigned-tickets/');
    return res.data.data
}

export const getManagerTickets=async ()=>{
    const res= await api.get('/tickets/manager/tickets/');
    return res.data.data
}

export const uploadDocument= async (formData)=>{
    try {
        const res = await api.post ('/tickets/client/upload/',formData,{
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
    const res= await api.get('/tickets/manager/clients-docs/');
    return res.data.data;
}

export const getClientDocs= async(clientId)=>{
    try {
    const res= await api.get(`/tickets/manager/clients-docs/${clientId}/`);
    return res.data.data    
    } catch (error) {
        console.log(error?.response?.data?.errors?.details ||' something wrong')
        throw error
    }
}

export const summarizeAllDocuments=async (docId)=>{
    const res= await api.post(`/tickets/manager/summarize/${docId}/`)
    return res.data.data
}