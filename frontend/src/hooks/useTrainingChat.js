import { useEffect, useRef, useState } from "react";
import { useAuth } from "../auth/AuthContext";

const useTrainingChat = (ticketId,currentUserId) => {
  const { accessToken } = useAuth();

  const socketRef = useRef(null);

  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState("");
  const [isTyping, setIsTyping] = useState(false);

  useEffect(() => {
    if (!ticketId) return;

    socketRef.current = new WebSocket(
      `ws://localhost:8000/ws/training-chat/${ticketId}/?token=${accessToken}`
    );

    socketRef.current.onopen = () => {
      console.log("Training WS Connected");
    };

    socketRef.current.onmessage = (event) => {
      const data = JSON.parse(event.data);
      console.log("WS RECEIVED", new Date().toISOString(), data);
      if (data.type==="typing_indicator"){
      console.log("WS RECEIVED", data);
        setIsTyping(data.is_typing);
        return;
      }
      setMessages((prev) => [...prev, data]);
    };

    socketRef.current.onclose = () => {
      console.log("Training WS Closed");
    };

    return () => {
      socketRef.current?.close();
    };
  }, [ticketId]);

  const sendMessage = () => {
    if (!newMessage.trim()) return;

    socketRef.current.send(
      JSON.stringify({
        type: "chat_message",
        message: newMessage,
      })
    );

    setNewMessage("");
  };


  return {
    messages,
    newMessage,
    setMessages,
    setNewMessage,
    sendMessage,
    isTyping,
  };
};

export default useTrainingChat;