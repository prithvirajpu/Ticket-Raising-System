export const validateAgentStep = (step, form, resume = null, certificates = []) => {
  const errors = {};

  if (step === 1) {
    // Full name
    if (!form.full_name?.trim()) {
      errors.full_name = "Full name is required";
    } else if (form.full_name.trim().length < 2) {
      errors.full_name = "Name must be at least 2 characters";
    }

    // Email
    if (!form.email?.trim()) {
      errors.email = "Email is required";
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email.trim())) {
      errors.email = "Please enter a valid email";
    }

    // Phone
    if (!form.phone?.trim()) {
      errors.phone = "Phone number is required";
    } else if (!/^[0-9\s\-\+\(\)]{10,12}$/.test(form.phone.trim())) {
      errors.phone = "Please enter a valid phone number";
    }

    // Resume
    if (!resume) {
      errors.resume = "Resume is required";
    } else {
      const allowedTypes = [
        "application/pdf",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      ];
      if (!allowedTypes.includes(resume.type)) {
        errors.resume = "Only PDF, DOC, DOCX files are allowed";
      }
    }
  }

  if (step === 2) {
    // Skills – still optional, but length limit if filled
    if (form.skills?.trim() && form.skills.trim().length > 500) {
      errors.skills = "Skills description is too long (max 500 characters)";
    }
    if (!form.skills.trim()) errors.skills='Skill is required'

    // Certificates – optional, but validate type if any
    if (certificates.length > 0) {
      const allowed = [
        "application/pdf",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "image/jpeg",
        "image/png",
      ];
      const hasInvalid = certificates.some((f) => !allowed.includes(f.type));
      if (hasInvalid) {
        errors.certificates = "Only PDF, DOC, DOCX, JPG, PNG allowed";
      }
    }

    // NEW: Check password fields before allowing to go to step 3
    
  }

  if (step === 3) {
    // You can leave it minimal or remove these checks entirely
    if (form.password?.length < 8) {
      errors.password = "Password must be at least 8 characters";
    }
    if (form.password !== form.confirm_password) {
      errors.confirm_password = "Passwords do not match";
    }
  }

  return {
    isValid: Object.keys(errors).length === 0,
    errors,
  };
};