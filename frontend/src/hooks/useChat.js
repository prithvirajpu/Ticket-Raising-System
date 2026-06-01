import { useEffect, useRef, useState } from "react";
import { getTicketMessages } from "../services/ticketService";
import { useAuth } from "../auth/AuthContext";
import { createPeer } from "../services/peerService";
import {startPeerCall} from '../services/StartPeerCall'
import { notifyError } from "../utils/notify";

const useChat = (ticketId, currentUserId) => {
    const {accessToken}= useAuth()
    const [incomingCall,setIncomingCall]=useState(null)
    const [messages, setMessages] = useState([]);
    const [newMessage, setNewMessage] = useState("");
    const [callState, setCallState] = useState("idle");
    const [callPartnerId, setCallPartnerId] = useState(null);

    const messageEndRef = useRef(null);
    const socketRef = useRef(null);
    const localStreamRef = useRef(null);
    const remoteAudioRef = useRef(null);
    const timeoutRef = useRef(null);

   useEffect(() => {
    if (!currentUserId) return;

    const initPeer = async () => {
        createPeer(currentUserId, remoteAudioRef,()=>localStreamRef.current);
    };

    initPeer();
}, [currentUserId]);
    
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
        const playRingtone = () => {
            const audio = new Audio("/sounds/bye-bye-bye.mp3");
                audio.loop = true;
                audio.play().catch((err) => {
                    console.log("Audio blocked", err);
                });
                window._ringtone = audio;
            };
        if (data.type==='incoming_call'){
            setIncomingCall(data)
            setCallPartnerId(data.caller_id)
            playRingtone();
        }
        if (data.type==='call_accepted'){
            console.log('customer accepted call',data)
            clearCallTimeout()
            setCallState('connecting')

            startPeerCall(data.peer_id,localStreamRef,remoteAudioRef)
            setCallState('in_call')
        }
        if(data.type==='call_ended'){
            clearCallTimeout()
            cleanupCall()
            stopRingtone()
            resetCallState()
        }
        if(data.type==='call_rejected'){
            clearCallTimeout()
            notifyError('User rejected the call')
            cleanupCall()
            resetCallState()
        }
        if(data.type==='call_missed'){
            stopRingtone()
            notifyError('Missed call from Agent')
            resetCallState()
        }
    };
    socketRef.current.onclose = () => {
    clearCallTimeout();
    cleanupCall();
    stopRingtone();
    resetCallState();
};

    return () => {
        clearCallTimeout()
        cleanupCall()
        stopRingtone()
        if (socketRef.current){
        socketRef.current.close();
        }
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

   const handleCall = async (targetUserId) => {
    if (callState!=='idle') return
    try {
        await setupLocalStream();

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

        setCallPartnerId(targetUserId);
        setCallState("calling");
        clearCallTimeout()
        timeoutRef.current = setTimeout(() => {
            if (socketRef.current?.readyState === WebSocket.OPEN) {
                socketRef.current.send(
                    JSON.stringify({
                        type: "call_missed",
                        caller_id: currentUserId,
                        customer_id: targetUserId,
                    })
                );
            }
            notifyError('Customer did not answer')
            cleanupCall();
            resetCallState();
        }, 30000);
    } catch (err) {
        console.error("Mic permission denied", err);
    }
};

const handleAccept = async (incomingCall,userId) => {
    try {
        setCallState('connecting')
        await setupLocalStream()
        if (socketRef.current?.readyState===WebSocket.OPEN){
            socketRef.current.send(
            JSON.stringify({
                type:'call_accepted',
                caller_id:incomingCall.caller_id,
                peer_id:`user-${userId}`,
            })
            )
        } 
        console.log('call accepted')

        setIncomingCall(null);
        setCallPartnerId(incomingCall.caller_id);
        clearCallTimeout();
        setCallState("in_call");
        stopRingtone()
    } catch (err) {
        console.error(err);
    }
};

const handleReject=async (incomingCall)=>{
    if (socketRef.current?.readyState === WebSocket.OPEN) {
        socketRef.current.send(
            JSON.stringify({
                type:'call_rejected',
                'caller_id':incomingCall.caller_id
            })
        )
    }
    stopRingtone()
    resetCallState()
}

const cleanupCall = () => {
    if (localStreamRef.current) {
        localStreamRef.current.getTracks().forEach(track => track.stop());
        localStreamRef.current = null;
    }

    window.localStream = null;
};

const clearCallTimeout = () => {
    if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
        timeoutRef.current = null;
    }
};

const setupLocalStream = async () => {
    const stream = await navigator.mediaDevices.getUserMedia({
        audio: true,
    });

    localStreamRef.current = stream;
    window.localStream = stream;

    return stream;
};

const stopRingtone = () => {
    window._ringtone?.pause();
    window._ringtone = null;
};

const resetCallState = () => {
    setIncomingCall(null);
    setCallPartnerId(null);
    if (remoteAudioRef.current) {
        remoteAudioRef.current.srcObject = null;
    }
    setCallState("idle");
};

    const handleEndCall= ()=>{
        console.log('end function ')
        clearCallTimeout()
        if (socketRef.current?.readyState === WebSocket.OPEN){
            socketRef.current.send(
                JSON.stringify({
                    type: 'call_ended',
                    customer_id:callPartnerId,
                    receiver_id:currentUserId
                })
            )
        }
        cleanupCall()
        stopRingtone()
        resetCallState()

    }

    return { messages, newMessage, setNewMessage, handleSendMessage, messageEndRef, handleKeyDown,
        socketRef, handleCall, incomingCall, setIncomingCall, handleAccept, remoteAudioRef,
        callState, setCallState, handleEndCall,handleReject
    };
};

export default useChat;