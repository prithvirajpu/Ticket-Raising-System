import React from "react";
import Lottie from "lottie-react";
import loadingAnimation from '../../assets/loading.json';

const Loader = ({ fullScreen = true }) => {
  return (
    <div
      className={`${
        fullScreen
          ? "fixed inset-0 bg-white bg-opacity-70 z-50"
          : "w-full"
      } flex items-center justify-center`}
    >
      <div className="w-40">
        <Lottie animationData={loadingAnimation} loop={true} />
      </div>
    </div>
  );
};

export default Loader;