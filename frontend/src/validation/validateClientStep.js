export const validateClientStep = (step, form) => {
  const errors = {};

  // ========================
  // STEP 1 – COMPANY DETAILS
  // ========================
  if (step === 1) {

    // Company Name
    if (!form.companyName?.trim()) {
      errors.companyName = "Company name is required";
    } else if (form.companyName.trim().length < 2) {
      errors.companyName = "Company name must be at least 2 characters";
    }

    // Email
    if (!form.email?.trim()) {
      errors.email = "Email is required";
    } else if (
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email.trim())
    ) {
      errors.email = "Please enter a valid email address";
    }

    // Phone
    if (!form.phone?.trim()) {
      errors.phone = "Phone number is required";
    } else if (
      !/^[0-9\s\-\+\(\)]{10,15}$/.test(form.phone.trim())
    ) {
      errors.phone = "Please enter a valid phone number";
    }

    // Business Type
    if (!form.business_type?.trim()) {
      errors.business_type = "Business type is required";
    } else if (form.business_type.trim().length < 2) {
      errors.business_type = "Business type must be at least 2 characters";
    }
  }

  // ========================
  // STEP 2 – PASSWORD
  // ========================
  if (step === 2) {

    if (!form.password) {
      errors.password = "Password is required";
    } else if (form.password.length < 8) {
      errors.password = "Password must be at least 8 characters";
    } else if (!/[A-Z]/.test(form.password)) {
      errors.password = "Password must contain at least one uppercase letter";
    } else if (!/[0-9]/.test(form.password)) {
      errors.password = "Password must contain at least one number";
    }

    if (!form.confirmPassword) {
      errors.confirmPassword = "Confirm password is required";
    } else if (form.password !== form.confirmPassword) {
      errors.confirmPassword = "Passwords do not match";
    }
  }

  return {
    isValid: Object.keys(errors).length === 0,
    errors,
  };
};
