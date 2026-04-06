// hooks/useAgentTimer.js - FIXED
import { useEffect, useState } from "react";
import { startSession, sendHeartbeat } from "../services/ticketService";

const useAgentTimer = () => {
  const [sessionId, setSessionId] = useState(null);
  const [isActive, setIsActive] = useState(true);
  const [seconds, setSeconds] = useState(0);

  // 1. Initialize session (runs once)
  useEffect(() => {
    const init = async () => {
      try {
        // Always call backend to get latest session or create new one
        const res = await startSession();
        const id = res?.message?.session_id;
        const totalSeconds = res?.message?.total_seconds || 0;

        setSessionId(id);
        setSeconds(totalSeconds);

        // Save to localStorage for page reloads
        localStorage.setItem('agentSessionId', id);
        localStorage.setItem('agentSeconds', totalSeconds.toString());

        console.log('Session initialized:', id, totalSeconds);
      } catch (error) {
        console.error('Session init failed:', error);

        // fallback to localStorage if backend fails
        const savedSessionId = localStorage.getItem('agentSessionId');
        const savedSeconds = parseInt(localStorage.getItem('agentSeconds') || '0');

        if (savedSessionId) {
          setSessionId(savedSessionId);
          setSeconds(savedSeconds);
        }
      }
    };

    init();
  }, []);

  // 2. Detect activity
  useEffect(() => {
    let timeout;
    const handleActivity = () => {
      setIsActive(true);
      clearTimeout(timeout);
      timeout = setTimeout(() => setIsActive(false), 30000);
    };

    ['mousemove', 'keydown', 'click', 'scroll'].forEach(event => {
      window.addEventListener(event, handleActivity);
    });

    return () => {
      ['mousemove', 'keydown', 'click', 'scroll'].forEach(event => {
        window.removeEventListener(event, handleActivity);
      });
      clearTimeout(timeout);
    };
  }, []);

  // 3. Tab visibility
  useEffect(() => {
    const handleVisibility = () => setIsActive(!document.hidden);
    document.addEventListener('visibilitychange', handleVisibility);
    return () => document.removeEventListener('visibilitychange', handleVisibility);
  }, []);

  // 4. Heartbeat + Timer tick
  useEffect(() => {
    if (!sessionId) return;

    const heartbeatInterval = setInterval(() => {
      if (isActive) sendHeartbeat(sessionId).catch(console.error);
    }, 10000); // heartbeat every 10s

    const tickInterval = setInterval(() => {
      if (isActive) {
        setSeconds(prev => {
          const newSeconds = prev + 1;

          // Sync every 30s to localStorage
          if (newSeconds % 30 === 0) {
            localStorage.setItem('agentSessionId', sessionId);
            localStorage.setItem('agentSeconds', newSeconds.toString());
          }

          return newSeconds;
        });
      }
    }, 1000);

    return () => {
      clearInterval(heartbeatInterval);
      clearInterval(tickInterval);
    };
  }, [sessionId, isActive]);

  return seconds;
};

export default useAgentTimer;