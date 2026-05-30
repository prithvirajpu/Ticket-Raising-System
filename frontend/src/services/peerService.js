import Peer from "peerjs";

let peerInstance = null;

export const createPeer = (userId, remoteAudioRef) => {
  const peerId = `user-${userId}`;

  if (
    peerInstance &&
    !peerInstance.destroyed &&
    peerInstance.id === peerId
  ) {
    return peerInstance;
  }

  if (peerInstance && !peerInstance.destroyed) {
    peerInstance.destroy();
  }

  peerInstance = new Peer(peerId, {
    debug: 2,
  });

  peerInstance.on("open", (id) => {
    console.log("✅ Peer connected:", id);
  });

  peerInstance.on("call", async (call) => {
    try {
      console.log("📞 Incoming Peer Call from:", call.peer);

      const stream = await navigator.mediaDevices.getUserMedia({
        audio: true,
        video: false,
      });

      call.answer(stream);

      call.on("stream", (remoteStream) => {
        console.log("🎧 Remote stream received");

        if (remoteAudioRef?.current) {
          remoteAudioRef.current.srcObject = remoteStream;

          remoteAudioRef.current
            .play()
            .catch((err) =>
              console.error("Audio play failed", err)
            );
        }
      });

      call.on("close", () => {
        console.log("📴 Call closed");
      });

      call.on("error", (err) => {
        console.error("🚨 Call error", err);
      });

    } catch (err) {
      console.error(err);
    }
  });

  peerInstance.on("connection", (conn) => {
    console.log("🔗 Data connection:", conn.peer);
  });

  peerInstance.on("disconnected", () => {
    console.warn("⚠️ Peer disconnected");
  });

  peerInstance.on("close", () => {
    console.warn("❌ Peer closed");
  });

  peerInstance.on("error", (err) => {
    console.error("🚨 Peer error:", err);
  });

  return peerInstance;
};

export const getPeer = () => peerInstance;

export const destroyPeer = () => {
  if (peerInstance && !peerInstance.destroyed) {
    peerInstance.destroy();
  }
  peerInstance = null;
};