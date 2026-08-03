import { getPeer } from "./peerService";

export const startPeerCall = async (peerId, localStreamRef, remoteAudioRef) => {
  try {
    const peer = getPeer();
    console.log("Current peer:", peer);
    console.log("Current peer id:", peer?.id);

    const stream = localStreamRef.current;
    if (!stream) {
      console.error("No local stream");
      return;
    }

    if (!peer) {
      console.log("❌ Peer not ready");
      return;
    }

    console.log("📞 Calling:", peerId);
    console.log("peer open:", peer.open, "destroyed:", peer.destroyed);

    const call = peer.call(peerId, stream);
    window.currentCall = call;
window.currentPeer = peer;

console.log("Call object created:", call);
    console.log("Call object created:", call);
    console.log("Peer instance id:", peer.id);
    console.log("Target peer:", peerId);
    call.peerConnection?.addEventListener("iceconnectionstatechange", () => {
  console.log(
    "ICE State:",
    call.peerConnection.iceConnectionState,
  );
});

call.peerConnection?.addEventListener("connectionstatechange", () => {
  console.log(
    "Connection State:",
    call.peerConnection.connectionState,
  );
});
    call.on("error", (err) => {
      console.error("CALL ERROR", err);
    });

    call.on("stream", (remoteStream) => {
      console.log("🎧 Remote stream received");
          window.currentCall = call;
    window.currentPC = call.peerConnection;
 
      if (remoteAudioRef.current) {
        remoteAudioRef.current.srcObject = remoteStream;

        remoteAudioRef.current
          .play()
          .catch((err) => console.error("Audio play failed", err));
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
