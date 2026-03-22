import api from '../api/axios'

export const createTicket= async(data)=>{
    const response= await api.post('/tickets/create/',data)
    return response.data.data
}

export const getTickets=async ()=>{
    const response=await api.get('/tickets/list/')
    return response.data.data.message
}

export const getTicketDetail= async(id)=>{
    const response=await api.get(`/tickets/details/${id}/`);
    return response.data.data
}

export const getAgentRequests=async (sort='newest')=>{
    const res= await api.get(`/tickets/agents/requests/?sort=${sort}`)
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

export const getOngoingTickets = async (sort='newest') => {
  const res = await api.get(`/tickets/agents/in-progress/?sort=${sort}`);
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