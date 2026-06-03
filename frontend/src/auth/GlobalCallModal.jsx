import { useCall } from "./CallContext";
import IncomingCallModal from "../components/modals/IncomingCallModal";
import OngoingCallModal from "../components/modals/OngoingCallModal";

const GlobalCallModal = () => {
    const {
        incomingCall,
        callState,
        handleAccept,
        handleReject,
        handleEndCall,
    } = useCall();

    return (
        <>
            <IncomingCallModal
                isOpen={!!incomingCall}
                callerName={incomingCall?.caller_name}
                onAccept={() => handleAccept(incomingCall)}
                onReject={() => handleReject(incomingCall)}
            />

            <OngoingCallModal
                isOpen={callState === "in_call"}
                onEnd={handleEndCall}
            />
        </>
        );
};

export default GlobalCallModal;