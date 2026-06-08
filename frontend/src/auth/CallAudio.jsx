import { useCall } from "./CallContext";

const CallAudio = () => {
    const {remoteAudioRef}= useCall()
  return (
    <audio 
    ref={remoteAudioRef}
    autoPlay
    />
  )
}

export default CallAudio
