export const validateAgentProfile = (form) => {
  const errors = {};

  // =====================
  // Phone Validation
  // =====================
  if (!form.phone?.trim()) {
    errors.phone = "Phone number is required";
  } else {
    const phone = form.phone.trim();

    if (!/^\d+$/.test(phone)) {
      errors.phone = "Phone number must contain only digits";
    } else if (phone.length < 10 || phone.length > 15) {
      errors.phone = "Phone number must be between 10 and 15 digits";
    }
  }

  // =====================
  // Skills Validation
  // =====================
  if (!form.skills?.trim()) {
    errors.skills = "Skills are required";
  } else if (form.skills.trim().length < 3) {
    errors.skills = "Skills must be at least 3 characters";
  }

  // =====================
  // Resume Validation
  // =====================
  if (!form.resume) {
    errors.resume = "Resume is required";
  } else {
    const allowedTypes = [
      "application/pdf",
      "application/msword",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ];

    if (!allowedTypes.includes(form.resume.type)) {
      errors.resume = "Resume must be PDF or Word document";
    }

    if (form.resume.size > 2 * 1024 * 1024) {
      errors.resume = "Resume must be less than 2MB";
    }
  }

  return {
    isValid: Object.keys(errors).length === 0,
    errors,
  };
};