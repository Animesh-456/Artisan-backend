import express, { Request, Response } from "express";
import cn from "@client/controller/auth";
import upload from "express-fileupload";

const router = express.Router();

router.get("/test", cn.test);

router.post("/register", cn.register);

router.post("/login", cn.login);

router.get("/verify-email", cn.verifyEmail);
router.post("/resend-verify-email", cn.resendverifyEmail);
router.post("/google-register", cn.google_register);
router.post("/google-login", cn.google_login);
router.post("/facebook-login", cn.facebook_login);
router.post("/facebook-callback", cn.facebook_register);


// Mobile OTP services

router.post("/otp-send", cn.OTP_send);
router.post("/otp-verify", cn.OTP_verify);


// Email OTP services

router.post("/email-otp-send", cn.email_OTP_send);
router.post("/email-otp-verify", cn.email_OTP_verify);


router.post("/register-otp-send", cn.register_OTP_send);
router.post("/register-otp-verify", cn.RegisterOTP_verify);

router.get("/me", cn.me);
router.get("/delivery_contacts", cn.delivery_contacts);


router.post("/change-password", cn.change_password);

router.get("/countries", cn.list_countries);

router.post("/update_modal", cn.update_modal);

/*FILE UPLOAD APIs */
router.use(upload());

router.post("/update-profile", cn.update);

router.post("/update-address", cn.update_address);

router.get("/machanic_details", cn.machanic_details);

router.get("/user-balance", cn.user_balance);

router.post("/update-balance", cn.update_balance);
router.get("/user_projects", cn.user_projects);

router.get("/user-spent", cn.user_spent);
router.post("/update_pro", cn.update_pro);
router.post("/save-address", cn.save_address);


router.post("/generate-new-password", cn.generate_new_password);
router.post("/forgot-username", cn.forgot_username);

export default router;
