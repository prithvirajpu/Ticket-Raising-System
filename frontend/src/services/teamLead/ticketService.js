import api from "../../api/axios";

export const getTeamLeadTickets=async()=>{
    const res= await api.get('/team-leads/assigned-tickets/');
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
export const generateFakeTickets= async (summary)=>{
    try {
        const res= await api.post('/team-leads/generate-fake-tickets/',{
        summary:summary,
        count:3,
    });
    return res.data.data
    } catch (error) {
            console.log(error);
    console.log(error.response);
    console.log(error.response?.data);

    console.log(
        error.response?.data?.errors?.details ||
        'Failed to generate tickets'
    );
    }
}
export const getTLDashboard = async()=>{
    try {
        const res = await api.get(`/team-leads/dashboard/`)
        return res.data.data
    } catch (error) {
        console.log(error)
        throw error.response.data.errors.details
    }
}