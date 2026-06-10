import { useEffect, useRef, useState } from "react";
import { useAuth } from "../auth/AuthContext";

const useTrainingChat = (ticketId,currentUserId) => {
  const { accessToken } = useAuth();

  const socketRef = useRef(null);

  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState("");
  const [isTyping, setIsTyping] = useState(false);
  const [evaluation, setEvaluation] = useState(null);
  const [showRetry, setShowRetry] = useState(false);
  const [isResolving, setIsResolving] = useState(false);

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
      if (data.type === "evaluation_result") {

  setEvaluation(data);
  setIsResolving(false);
  setShowRetry(data.passed === false);
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

const startResolve = () => {
  setIsResolving(true);

  socketRef.current.send(
    JSON.stringify({
      type: "resolve_ticket",
    })
  );
};


  return {
    messages,newMessage,startResolve,
    setMessages,setNewMessage,
    sendMessage,
    setIsResolving,isResolving,
    isTyping,showRetry,
    socketRef,setShowRetry,
    evaluation,setEvaluation,
  };
};

export default useTrainingChat;