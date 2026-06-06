import { createContext,useContext,useEffect,useState } from "react"
import { useAuth } from "./AuthContext"
import { getNotifications, markAllNotificationsRead, markNotificationRead } from "../services/ticketService"

const NotificationContext= createContext()
const NotificationProvider = ({children}) => {
    const {accessToken} =useAuth()
    const [notifications,setNotifications]=useState([])
    const [unreadCount, setUnreadCount] = useState(0);
    
    useEffect(()=>{
         if (!accessToken) return;
         console.log("Creating Notification WS");
        const ws= new WebSocket(`ws://localhost:8000/ws/notifications/?token=${accessToken}`)

        ws.onmessage=(event)=>{
            console.log('notification data in front',event.data)
            const data= JSON.parse(event.data);
            setNotifications(prev=>[data,...prev])
            setUnreadCount(prev=>prev+1)
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
            console.log(res)
            setNotifications(res.serializer)
            setUnreadCount(res.unread_count)
        } catch (error) {
            console.log(error)
        }
    }

    const handleNotificationClick= async(notification)=>{
        console.log('clicked',notification)
    if(!notification.is_read){
        setNotifications(prev=>
            prev.map(item=>
                item.id===notification.id ? {...item,is_read:true}: item
            )
        )
        setUnreadCount(prev=>Math.max(prev-1,0));
        try {
            await markNotificationRead(notification.id)
            console.log('maked read')
        } catch (error) {
            console.log(error)
        }
        }
    }

    const handleMarkAllRead = async() => {
        setNotifications(prev =>
            prev.map(item => ({
                ...item,
                is_read: true,
            }))
        );

        setUnreadCount(0);
        try {
            await markAllNotificationsRead();
        } catch (error) {
            console.log(error);
        }
    };

  return (
    <NotificationContext.Provider value={{
        notifications,unreadCount,
        setUnreadCount,handleNotificationClick,
        handleMarkAllRead
    }}>
        {children}
    </NotificationContext.Provider>
  )
}
export default NotificationProvider

export const useNotifications=()=>useContext(NotificationContext)
