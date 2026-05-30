import { useEffect, useRef, useState } from "react";
import { getTicketMessages, sendMessage } from "../services/ticketService";
import { useAuth } from "../auth/AuthContext";
import { createPeer } from "../services/peerService";
import {startPeerCall} from '../services/StartPeerCall'

const useChat = (ticketId, currentUserId) => {
    const {accessToken}= useAuth()
    const [incomingCall,setIncomingCall]=useState(null)
    const [messages, setMessages] = useState([]);
    const [newMessage, setNewMessage] = useState("");

    const messageEndRef = useRef(null);
    const socketRef = useRef(null);
    const localStreamRef = useRef(null);
    const remoteAudioRef = useRef(null);

    useEffect(()=>{
        console.log("CURRENT USER ID", currentUserId);
        if (!currentUserId) return;
        createPeer(currentUserId,remoteAudioRef);
    },[currentUserId])
    
    useEffect(() => {
    if (!ticketId) return;

    socketRef.current = new WebSocket(
        `ws://localhost:8000/ws/chat/${ticketId}/?token=${accessToken}`
    );

    socketRef.current.onmessage = (event) => {
        const data = JSON.parse(event.data);
        console.log('WS data',data)
        if (data.type==='chat_message'){
            setMessages((prev) => [
                ...prev,
                {
                    id: Date.now(), // temporary id
                    message: data.message,
                    sender_id: Number(data.sender_id),
                    sender_name: data.sender_name,
                    created_at: data.created_at || new Date().toISOString()
                }
            ]);
        }
        if (data.type==='incoming_call'){
            setIncomingCall(data)
        }
        if (data.type==='call_accepted'){
            console.log('customer accepted call',data)
            startPeerCall(data.peer_id,localStreamRef,remoteAudioRef)
        }
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
        const res=message.data

        const normalized = res.map((m) => ({
            id: m.id,
            message: m.message,
            sender_id: Number(m.sender_id),   
            sender_name: m.sender_name,
            created_at: m.created_at,
        }));

        setMessages(normalized);
        scrollToBottom();
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

    const handleCall = (targetUserId) => {
        console.log('call fn')
    if (
        socketRef.current &&
        socketRef.current.readyState === WebSocket.OPEN
    ) {
        socketRef.current.send(
            JSON.stringify({
                type: "call_request",
                customer_id: targetUserId,
            })
        );
    }
};
const handleAccept = async (incomingCall,userId) => {
    try {
        const stream = await navigator.mediaDevices.getUserMedia({
            audio: true,
            video: false,
        });
        localStreamRef.current=stream
        console.log("Microphone granted", stream);
        socketRef.current.send(
          JSON.stringify({
            type:'call_accepted',
            caller_id:incomingCall.caller_id,
            peer_id:`user-${userId}`,
          })
        ) 
        console.log('call accepted')

        setIncomingCall(null);
    } catch (err) {
        console.error(err);
    }
};

    return {
        messages,
        newMessage,
        setNewMessage,
        handleSendMessage,
        messageEndRef,
        handleKeyDown,
        socketRef,
        handleCall,
        incomingCall,
        setIncomingCall,
        handleAccept,
        remoteAudioRef,
    };
};

export default useChat;