import { createContext,useContext,useEffect,useState } from "react"
import { useAuth } from "./AuthContext"
import { getNotifications, markAllNotificationsRead, markNotificationRead } from "../services/ticketService"

const NotificationContext= createContext()
const NotificationProvider = ({children}) => {
    const {accessToken} =useAuth()
    const [notifications,setNotifications]=useState([])
    const unreadCount= notifications.filter(n=>!n.is_read).length;
    
    useEffect(()=>{
         if (!accessToken) return;
         console.log("Creating Notification WS");
        const ws= new WebSocket(`ws://localhost:8000/ws/notifications/?token=${accessToken}`)

        ws.onmessage=(event)=>{
            const data= JSON.parse(event.data);
            console.log('notification WS',data)
            setNotifications(prev => {
        const existing = prev.find(n => n.id === data.id);

        if (existing) {
            return prev.map(n =>
                n.id === data.id ? data : n
            );
        }

        return [data, ...prev];
    });
            
        }
        ws.onopen = () => {
        console.log("Notification WS Connected");
    };

    ws.onerror = (event) => {
        console.log("Notification WS Error", event);
    };

    ws.onclose = (event) => {
        console.log(
            "Notification WS Closed",
            event.code,
            event.reason
        );
    };
        return ()=>{
             console.log("Cleaning Notification socket");
            ws.close()
        }
    },[accessToken])

    useEffect(()=>{
        if (!accessToken)return;
        loadNotifications();
    },[accessToken])

    const loadNotifications=async()=>{
        try {
            const res= await getNotifications();
            setNotifications(res.serializer)
        } catch (error) {
            console.log(error)
        }
    }

    const handleNotificationClick= async(notification)=>{
        console.log("clicked notification", notification);
    console.log("notification id", notification.id);
    if(!notification.is_read){
        setNotifications(prev=>
            prev.map(item=>
                item.id===notification.id ? {...item,is_read:true}: item
            )
        )
        try {
            await markNotificationRead(notification.id)
            console.log('maked read')
        } catch (error) {
            console.log(error)
        }}
    }

    const handleMarkAllRead = async() => {
        if (unreadCount === 0) return;
        setNotifications(prev =>
            prev.map(item => ({
                ...item,
                is_read: true,
            }))
        );

        try {
            await markAllNotificationsRead();
        } catch (error) {
            console.log(error);
        }
    };

  return (
    <NotificationContext.Provider value={{
        notifications,
        handleNotificationClick,
        handleMarkAllRead,unreadCount,
    }}>
        {children}
    </NotificationContext.Provider>
  )
}
export default NotificationProvider

export const useNotifications=()=>useContext(NotificationContext)
