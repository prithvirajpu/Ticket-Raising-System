import api from '../../api/axios'

export const createTicket= async(data)=>{
    try {
        const response= await api.post('/users/tickets/create/',data)
    return response.data.data
    } catch (error) {
        console.log("CREATE TICKET FAILED ❌",error.response?.data?.errors?.details)
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
export const closeTicket= async (id) =>{
    const res = await api.post(`/users/tickets/${id}/close/`)
    return res.data.data
}

export const submitReview=async(id,data)=>{
    const res= await api.post(`/users/tickets/${id}/review/`,data);
    return res.data.data
}
export const getProfile=async()=>{
    const res= await api.get('/users/profile/')
    return res.data.data
}

export const updateProfile= async (data)=>{
    const res = await api.put('/users/profile/update/',data)
    return res.data.data
}
export const getUserDashboard=async (role)=>{
    try {
        const res= await api.get('/users/dashboard/')
        return res.data.data
    } catch (error) {
        console.log('something went wrong in user dashboard')
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