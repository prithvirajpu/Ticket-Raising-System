import api from "../../api/axios";

export const resolveTicket = async (id) => {
  const res = await api.post(`/tickets/${id}/resolve/`);
  return res.data.data;
};
export const escalateTicket=async(id)=>{
    try {
        const res= await api.post(`/tickets/${id}/escalate/`);
    return res.data.data
    } catch (error) {
        const err=error.response?.data?.errors?.details ||'my error'
        console.log(err)
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

export const getNotifications= async()=>{
    const res= await api.get('/tickets/notifications/');
    return res.data.data
}

export const markNotificationRead= async(Id)=>{
    const res= await api.patch(`/tickets/notifications/${Id}/read/`)
    return res.data.data
}
export const markAllNotificationsRead= async()=>{
    const res= await api.put(`/tickets/notifications/mark-all-read/`)
    return res.data.data
}
export const getTrainingMessages=async(Id)=>{
    try {
        const res= await api.get(`/tickets/training-tickets/${Id}/messages/`)
        return res.data.data
    } catch (error) {
        console.log(error)
    }
}