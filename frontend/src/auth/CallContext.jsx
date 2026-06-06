import { createContext, useContext, useEffect, useRef, useState } from "react";
import { createPeer } from "../services/peerService";
import { useAuth } from "./AuthContext";
import { notifyError } from "../utils/notify";
import { startPeerCall } from "../services/StartPeerCall";

const CallContext = createContext();
export const CallProvider = ({ children }) => {
  const { accessToken, userId } = useAuth();
  const [callState, setCallState] = useState("idle");
  const [incomingCall, setIncomingCall] = useState(null);
  const [callPartnerId, setCallPartnerId] = useState(null);

  const socketRef = useRef(null);
  const localStreamRef = useRef(null);
  const remoteAudioRef = useRef(null);
  const timeoutRef = useRef(null);
  const callLockRef = useRef(false);

  useEffect(() => {
    if (!accessToken) return;
    console.log("the user id is : ", userId);

    const ws = new WebSocket(
      `ws://localhost:8000/ws/call/?token=${accessToken}`,
    );

    socketRef.current = ws;

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);

      switch (data.type) {
        case "incoming_call":
          console.log("CALL CONTEXT RECEIVED", data);
          setIncomingCall(data);
          setCallPartnerId(data.caller_id);
          playRingtone();
          break;

        case "call_accepted":
          console.log("customer accepted call", data);
          clearCallTimeout();
          setCallState("connecting");

          startPeerCall(data.peer_id, localStreamRef, remoteAudioRef);
          setCallState("in_call");
          break;

        case "call_rejected":
          clearCallTimeout();
          notifyError("User rejected the call");
          cleanupCall();
          resetCallState();
          break;

        case "call_ended":
          clearCallTimeout();
          cleanupCall();
          stopRingtone();
          resetCallState();
          break;
        case "call_missed":
          stopRingtone();
          notifyError("Missed call from Agent");
          resetCallState();
          break;
      }
    };

    return () => ws.close();
  }, [accessToken]);

  useEffect(() => {
    if (userId) initializePeer(userId);
  }, [userId]);

  const initializePeer = (userId) => {
    createPeer(userId, remoteAudioRef, () => localStreamRef.current);
  };

  const handleCall = async (targetUserId) => {
    if (callState !== "idle") return;
    if (callLockRef.current) return;

    callLockRef.current = true;
    try {
      await setUpLocalStream();

      if (
        socketRef.current &&
        socketRef.current.readyState === WebSocket.OPEN
      ) {
        socketRef.current.send(
          JSON.stringify({
            type: "call_request",
            customer_id: targetUserId,
          }),
        );
      }

      setCallPartnerId(targetUserId);
      setCallState("calling");
      clearCallTimeout();
      timeoutRef.current = setTimeout(() => {
        if (socketRef.current?.readyState === WebSocket.OPEN) {
          socketRef.current.send(
            JSON.stringify({
              type: "call_missed",
              caller_id: userId,
              customer_id: targetUserId,
            }),
          );
        }
        notifyError("Customer did not answer");
        cleanupCall();
        resetCallState();
      }, 30000);
    } catch (err) {
      console.error("Mic permission denied", err);
      callLockRef.current = false;
    }
  };

  const handleAccept = async (incomingCall) => {
    try {
      setCallState("connecting");
      await setUpLocalStream();
      if (socketRef.current?.readyState === WebSocket.OPEN) {
        socketRef.current.send(
          JSON.stringify({
            type: "call_accepted",
            caller_id: incomingCall.caller_id,
            peer_id: `user-${userId}`,
          }),
        );
      }
      console.log("call accepted");

      setIncomingCall(null);
      setCallPartnerId(incomingCall.caller_id);
      clearCallTimeout();
      setCallState("in_call");
      stopRingtone();
    } catch (err) {
      console.error(err);
    }
  };

  const handleReject = async (incomingCall) => {
    if (socketRef.current?.readyState === WebSocket.OPEN) {
      socketRef.current.send(
        JSON.stringify({
          type: "call_rejected",
          caller_id: incomingCall.caller_id,
        }),
      );
    }
    stopRingtone();
    resetCallState();
  };

  const handleEndCall = () => {
    console.log("end function ");
    clearCallTimeout();
    if (socketRef.current?.readyState === WebSocket.OPEN) {
      socketRef.current.send(
        JSON.stringify({
          type: "call_ended",
          customer_id: callPartnerId,
          receiver_id: userId,
        }),
      );
    }
    cleanupCall();
    stopRingtone();
    resetCallState();
  };

  const setUpLocalStream = async () => {
    const stream = await navigator.mediaDevices.getUserMedia({
      audio: true,
    });
    localStreamRef.current = stream;
    return stream;
  };

  const cleanupCall = () => {
    if (localStreamRef.current) {
      localStreamRef.current.getTracks().forEach((track) => track.stop());
      localStreamRef.current = null;
    }
    if (remoteAudioRef.current) {
      remoteAudioRef.current.srcObject = null;
    }
  };

  const clearCallTimeout = () => {
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
      timeoutRef.current = null;
    }
  };

  const stopRingtone = () => {
    window._ringtone?.pause();
    window._ringtone = null;
  };

  const playRingtone = () => {
    const audio = new Audio("/sounds/bye-bye-bye.mp3");
    audio.loop = true;
    audio.play().catch((err) => {
      console.log("Audio blocked", err);
    });
    window._ringtone = audio;
  };

  const resetCallState = () => {
    callLockRef.current = false;
    setIncomingCall(null);
    setCallPartnerId(null);
    if (remoteAudioRef.current) {
      remoteAudioRef.current.srcObject = null;
    }
    setCallState("idle");
  };

  return (
    <CallContext.Provider
      value={{
        callState,
        setCallState,
        socketRef,
        incomingCall,
        setIncomingCall,
        callPartnerId,
        setCallPartnerId,
        localStreamRef,
        remoteAudioRef,
        initializePeer,
        setUpLocalStream,
        cleanupCall,
        handleCall,
        handleAccept,
        handleReject,
        handleEndCall,
        stopRingtone,
        resetCallState,
        clearCallTimeout,
      }}
    >
      {children}
       <audio ref={remoteAudioRef} autoPlay playsInline hidden />
    </CallContext.Provider>
  );
};

export const useCall = () => useContext(CallContext);
