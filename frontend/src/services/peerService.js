import Peer from "peerjs";

let peerInstance = null;
let getLocalStream = null;

export const createPeer = (userId, remoteAudioRef, streamGetter) => {
  const peerId = `user-${userId}`;

  getLocalStream = streamGetter;
  if (peerInstance && !peerInstance.destroyed) {
    console.log("Peer already exists");
    return peerInstance;
  }
  console.log("CREATING NEW PEER", peerId);
  console.log(
    "peer exists?",
    peerInstance,
    "destroyed?",
    peerInstance?.destroyed,
  );
peerInstance = new Peer(peerId, {
  debug: 2,

  config: {
  iceServers: [
    {
      urls: "stun:stun.l.google.com:19302",
    },
    {
      urls: [
        "turn:13.205.216.174:3478?transport=udp",
        "turn:13.205.216.174:3478?transport=tcp",
      ],
      username: "trs",
      credential: "trs123",
    },
  ],
},
});

  peerInstance.on("open", (id) => {
    console.log("✅ Peer connected:", id);
  });

  peerInstance.on("call", async (call) => {
    console.log("this is peerinstanse call in peerjs .on", call);
    console.log("Incoming call event", call.peer, getLocalStream?.());
    try {
      console.log("📞 Incoming Peer Call from:", call.peer);
      const stream = getLocalStream?.();
      if (!stream) {
        console.error("No mic stream found");
        return;
      }

      call.answer(stream);
      call.peerConnection?.addEventListener("iceconnectionstatechange", () => {
  console.log(
    "Receiver ICE:",
    call.peerConnection.iceConnectionState,
  );
});

call.peerConnection?.addEventListener("connectionstatechange", () => {
  console.log(
    "Receiver Connection:",
    call.peerConnection.connectionState,
  );
});

      call.on("stream", (remoteStream) => {
        console.log("🎧 Remote stream received");
            window.currentCall = call;
    window.currentPC = call.peerConnection;

        if (remoteAudioRef?.current) {
          remoteAudioRef.current.srcObject = remoteStream;

          remoteAudioRef.current
            .play()
            .catch((err) => console.error("Audio play failed", err));
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
    console.log("destroying peer");
    peerInstance.destroy();
  }
  peerInstance = null;
};
