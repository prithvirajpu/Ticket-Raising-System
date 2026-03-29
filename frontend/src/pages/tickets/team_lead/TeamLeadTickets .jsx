import React, { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { getTeamLeadTickets } from '../../../services/ticketService';
import Loader from '../../../components/modals/Loader';
import DashboardLayout from '../../../layouts/DashboardLayout';

const TeamLeadTickets  = () => {
    const [tickets,setTickets]=useState([])
    const [loading,setLoading]=useState(false)
    const navigate=useNavigate();

    useEffect(()=>{
        fetchTickets();
    },[])

    const fetchTickets=async()=>{
        setLoading(true)
        try {
            const res=await getTeamLeadTickets();
            setTickets(res.message)
        } catch (error) {
            console.log(error)
        }   finally{
            setLoading(false)
        }
    }
    if (loading) return <Loader />

  return (
    <DashboardLayout>
        <div className="max-w-6xl mx-auto">
        <h1 className="text-2xl font-bold mb-6">Escalated Tickets</h1>

        <div className="space-y-4">
          {tickets.length===0 ? <p className='p-10 text-center'>No tickets</p>: tickets.map((t) => (
            <div
              key={t.id}
              onClick={() => navigate(`/team-lead/tickets/${t.id}`)}
              className="p-4 border rounded-xl cursor-pointer hover:bg-gray-50"
            >
              <div className="flex justify-between">
                <h2 className="font-semibold">{t.subject}</h2>
                <span className="text-sm">{t.priority}</span>
              </div>
              <p className="text-sm text-gray-500">{t.ticket_code}</p>
            </div>
          ))}
        </div>
      </div>
    </DashboardLayout>
  )
}

export default TeamLeadTickets 
