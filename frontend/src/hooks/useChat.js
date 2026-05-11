import { useEffect, useRef, useState } from "react";
import { getTicketMessages, sendMessage } from "../services/ticketService";
import { useAuth } from "../auth/AuthContext";

const useChat = (ticketId, currentUserId) => {
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
        console.log('onmessage data',data)

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
    };

    return () => {
        socketRef.current.close();
    };
}, [ticketId]);

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

    return {
        messages,
        newMessage,
        setNewMessage,
        handleSendMessage,
        messageEndRef
    };
};

export default useChat;