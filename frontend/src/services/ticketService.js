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