export const validateName = (name) => {
    const trimmedName = name.trim();

    if (!trimmedName) {
        return "Name is required";
    }

    if (trimmedName.length < 4) {
        return "Name must be at least 4 characters";
    }

    if (trimmedName.length > 50) {
        return "Name cannot exceed 50 characters";
    }

    // Name must contain at least one alphabetic character
    if (!/^[A-Za-z]/.test(trimmedName)) {
        return "Name must start with a letter";
    }

    return "";
};
export const validatePhone = (phone) => {
    const trimmedPhone = phone.trim();

    // Phone number is optional
    if (!trimmedPhone) {
        return "";
    }

    // Indian mobile number:
    // - Exactly 10 digits
    // - Starts with 6, 7, 8, or 9
    // - No spaces, hyphens, letters or special characters
    const phoneRegex = /^\d{10}$/;

    if (!phoneRegex.test(trimmedPhone)) {
        return "Please enter a valid 10-digit mobile number";
    }

    return "";
};
