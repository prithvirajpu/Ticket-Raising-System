import api from "../../api/axios";

export const getManagerTickets=async ()=>{
    const res= await api.get('/managers/tickets/');
    return res.data.data
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

export const getManagerDashboard = async()=>{
    try {
        const res = await api.get(`/managers/dashboard/`)
        return res.data.data
    } catch (error) {
        console.log(error)
        throw error.response.data.errors.details
    }
}