import React, { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { getManagerTickets } from '../../../services/ticketService'
import { Fingerprint } from 'lucide-react'
import Loader from '../../../components/modals/Loader'
import DashboardLayout from '../../../layouts/DashboardLayout'

const ManagerTickets = () => {
    const [tickets,setTickets]=useState([])
    const [loading,setLoading]=useState(false)
    const navigate=useNavigate()

    useEffect(()=>{
        fetchTickets();
    },[])

    const fetchTickets=async()=>{
        setLoading(true)
        try {
            const res= await getManagerTickets();
            setTickets(res.message)
            setLoading(false);
        } catch (error) {
            console.log(error)
        } finally{
            setLoading(false)
        }
    }
    if (loading) return <Loader />

  return (
    <DashboardLayout>
        <div className="max-w-6xl mx-auto">
        <h1 className="text-2xl font-bold mb-6">Escalated Tickets</h1>

        <div className="space-y-4">
          {tickets.length===0? <p className='text-center p-10'>No tickets</p>: tickets.map((t) => (
            <div
              key={t.id}
              onClick={() => navigate(`/manager/tickets/${t.id}`)} 
              className="p-4 border rounded-xl cursor-pointer hover:bg-gray-50"
            >
              <div className="flex justify-between">
                <h2 className="font-semibold">{t.subject}</h2>
                <span>{t.priority}</span>
              </div>
              <p className="text-sm text-gray-500">{t.ticket_code}</p>
            </div>
          ))}
        </div>
      </div>
    </DashboardLayout>
  )
}

export default ManagerTickets
