import { useEffect, useRef, useState } from "react";
import { getTicketMessages } from "../services/ticketService";
import { useAuth } from "../auth/AuthContext";
import { useCall } from "../auth/CallContext";

const useChat = (ticketId, currentUserId) => {
    const {
        incomingCall,setIncomingCall,
        callState,setCallState,
        callPartnerId,setCallPartnerId,
        localStreamRef,remoteAudioRef,
        initializePeer,setUpLocalStream,
        cleanupCall
    }=useCall()
    const {accessToken}= useAuth()
    const [messages, setMessages] = useState([]);
    const [newMessage, setNewMessage] = useState("");

    const messageEndRef = useRef(null);
    const socketRef = useRef(null);
    

    
    useEffect(() => {
    if (!ticketId) return;

    socketRef.current = new WebSocket(
        `ws://localhost:8000/ws/chat/${ticketId}/?token=${accessToken}`
    );

    socketRef.current.onmessage = (event) => {
        const data = JSON.parse(event.data);
        console.log('WS data',data)

    if (data.type === "chat_message") {

  setMessages(prev => [
    ...prev,
    {
      id: data.id,
      message: data.message,
      sender_id: Number(data.sender_id),
      sender_name: data.sender_name,
      created_at: data.created_at,
      is_seen: false,
    }
  ]);

  // IMPORTANT: only receiver marks read
  if (Number(data.sender_id) !== Number(currentUserId)) {
    socketRef.current?.send(
      JSON.stringify({ type: "mark_read" })
    );
  }
}

if (data.type === "messages_read") {
  const { message_ids, reader_id } = data;

  // only apply if OTHER user read it
  if (Number(reader_id) === Number(currentUserId)) return;

  setMessages(prev =>
    prev.map(msg =>
      message_ids.includes(msg.id)
        ? { ...msg, is_seen: true }
        : msg
    )
  );
}
    };
           socketRef.current.onclose = () => {
    console.log("Chat socket closed");
};

    return () => {
        socketRef.current.close();
    };
}, [ticketId]);

   // Enter key to send message
   const handleKeyDown=(e)=>{
    if (e.key==='Enter' &&!e.shiftKey){
        e.preventDefault();
        handleSendMessage()
    }
   }
    // scroll helper
    const scrollToBottom = () => {
        messageEndRef.current?.scrollIntoView({ behavior: "smooth" });
    };
    useEffect(() => {
        scrollToBottom();
    }, [messages]);

    // fetch messages
    useEffect(() => {
    const fetchMessages = async () => {
        const message = await getTicketMessages(ticketId);
        console.log('getTicketmessages',message)
        console.log(
  message.data.filter(m => m.id === 221 || m.id === 222)
);
        const res=message.data

        const normalized = res.map((m) => ({
            id: m.id,
            message: m.message,
            sender_id: Number(m.sender_id),   
            sender_name: m.sender_name,
            created_at: m.created_at,
            is_seen:m.is_seen,
        }));
        console.log('normalized',normalized)
        console.log('another data',normalized[normalized.length - 1]);
        console.log('another data2',normalized[normalized.length - 2]);

        setMessages(normalized);
        scrollToBottom();
        console.log(
    "WS state before mark read:",
    socketRef.current?.readyState
);
        if (socketRef.current?.readyState === WebSocket.OPEN) {
        socketRef.current.send(
            JSON.stringify({
                type: "mark_read"
            })
        );
        console.log("SENDING MARK READ");
    }
    };

    if (ticketId) fetchMessages();
}, [ticketId]);

    const handleSendMessage = async () => {
        if (!newMessage.trim()) return;

        const payload = {
            type: "chat_message",
            message: newMessage,
            sender_name: "You",
            sender_id: currentUserId,
            created_at: new Date().toISOString(),
        };
    if (
            socketRef.current &&
            socketRef.current.readyState === WebSocket.OPEN
        ) {
            socketRef.current.send(JSON.stringify(payload));
            setNewMessage("");
            scrollToBottom();
        } else {
            console.error("WebSocket is not connected");
        }
    };

 

 
   
    

    return { messages, newMessage, setNewMessage, 
        handleSendMessage, messageEndRef, handleKeyDown,
    };
};

export default useChat;