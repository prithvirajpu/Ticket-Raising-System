import { useEffect, useState } from "react"
import DashboardLayout from "../../../layouts/DashboardLayout"
import { getClientsWithDocs } from "../../../services/ticketService"
import { useNavigate } from "react-router-dom"

const ClientListPage = () => {
    const [clients,setClients]=useState([])
    const [loading,setLoading]=useState(false)
    const navigate= useNavigate()
    
    useEffect(()=>{
        fetchClients();
    },[])
    
    const fetchClients= async()=>{
        setLoading(true);
        try {
            const res= await getClientsWithDocs();
            setClients(res.message || []);
            setLoading(false)
        } catch (error) {
            console.log(error)
        } finally{
            setLoading(false)
        }
    }

  return (
    <DashboardLayout
    title="Knowledge Base" 
    subtitle="Training documents and resources">
        <div className="max-w-3xl mx-auto mt-10 space-y-4">
                <h2 className="text-xl font-bold">Clients Documents</h2>

                {clients.map((client) => (
                    <div
                        key={client.client_id}
                        className="p-4 border rounded cursor-pointer hover:bg-gray-50"
                        onClick={() => navigate(`/manager/client-docs/${client.client_id}`)}
                    >
                        {client.client_name}
                    </div>
                ))}
            </div>
    </DashboardLayout>
  )
}

export default ClientListPage
