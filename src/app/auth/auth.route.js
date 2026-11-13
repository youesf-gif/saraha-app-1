import { Router } from "express";
import authController from "./auth.controller.js";

const authRouter = Router();

authRouter.post("/register", authController.register);
authRouter.patch("/verify-account", authController.verifyAccount);
authRouter.post("/resend-otp", authController.resendOTP);
authRouter.post("/login", authController.login);


export default authRouter;
