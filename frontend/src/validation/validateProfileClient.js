export const validateProfile = (form) => {
  const errors = {};

  // =========================
  // Company Name Validation
  // =========================
  if (!form.companyName?.trim()) {
    errors.companyName = "Company name is required";
  } else {
    const companyName = form.companyName.trim();

    // Must start with a letter
    if (!/^[A-Za-z]/.test(companyName)) {
      errors.companyName = "Company name must start with a letter";
    }

    // Only allow letters, numbers and spaces
    else if (!/^[A-Za-z0-9\s]+$/.test(companyName)) {
      errors.companyName =
        "Company name can only contain letters, numbers and spaces";
    }

    // Minimum length
    else if (companyName.length < 2) {
      errors.companyName =
        "Company name must be at least 2 characters";
    }
  }

  // =========================
  // Phone Validation
  // =========================
  if (!form.phone?.trim()) {
    errors.phone = "Phone number is required";
  } else {
    const phone = form.phone.trim();

    // Only digits allowed
    if (!/^\d+$/.test(phone)) {
      errors.phone = "Phone number must contain only digits";
    }

    // Length check (10–15 digits)
    else if (phone.length < 10 || phone.length > 15) {
      errors.phone =
        "Phone number must be between 10 and 15 digits";
    }
  }

  // =========================
  // Business Type Validation
  // =========================
  if (!form.businessType?.trim()) {
    errors.businessType = "Business type is required";
  } else {
    const businessType = form.businessType.trim();

    if (!/^[A-Za-z]/.test(businessType)) {
      errors.businessType =
        "Business type must start with a letter";
    } else if (businessType.length < 2) {
      errors.businessType =
        "Business type must be at least 2 characters";
    }
  }

  return {
    isValid: Object.keys(errors).length === 0,
    errors,
  };
};