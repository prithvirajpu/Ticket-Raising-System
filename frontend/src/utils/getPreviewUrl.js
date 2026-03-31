// utils/getPreviewUrl.js

const CLOUDINARY_BASE_URL = "https://res.cloudinary.com/dlfyesjsd/raw/upload/";

const getPreviewUrl = (url) => {
  if (!url) return "";

  // If the URL is already a full https:// URL, use it; otherwise prepend Cloudinary base
  const fullUrl = url.startsWith("http") ? url : `${CLOUDINARY_BASE_URL}${url}`;

  // Wrap with Google Docs Viewer for iframe preview
  return `https://docs.google.com/gview?url=${encodeURIComponent(fullUrl)}&embedded=true`;
};

export default getPreviewUrl;