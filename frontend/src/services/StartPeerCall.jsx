import { getPeer } from "./peerService";

export const startPeerCall = async (
    peerId,
    localStreamRef,remoteAudioRef
) => {
  try {
  
    const peer = getPeer();
    const stream = localStreamRef.current ;
    if (!stream) {
        console.error("No local stream");
        return;
      }

    if (!peer) {
      console.log("❌ Peer not ready");
      return;
    }

    console.log("📞 Calling:", peerId);

    const call = peer.call(peerId, stream);

    call.on("stream", (remoteStream) => {
      console.log("🎧 Remote stream received");

      if (remoteAudioRef.current) {
        remoteAudioRef.current.srcObject = remoteStream;

        remoteAudioRef.current.play().catch((err) =>
            console.error("Audio play failed", err)
          );
      }
    });

    call.on("close", () => {
      console.log("📴 Call ended");
    });

    call.on("error", (err) => {
      console.error("🚨 Call error", err);
    });

  } catch (err) {
    console.error(err);
  }
};

