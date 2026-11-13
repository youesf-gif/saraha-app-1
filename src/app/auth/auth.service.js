import bcrypt from "bcrypt";
import crypto from "node:crypto";
import jwt from "jsonwebtoken";

import userRepo from "../user/user.repository.js";
import authRepo from "./auth.repository.js";
import { toMS } from "../../common/utils/time.js";
import { sendMail } from "../../common/email/nodemailer.js";
import { SECRET_KEY } from "../../common/config/config.js";

async function register(userName, email, password) {
  const user = await userRepo.findUserByEmail(email);

  if (user) throw new Error("User already exists");

  password = await bcrypt.hash(password, 10);

  const createdUser = await userRepo.createUser(userName, email, password);

  const otp = crypto.randomInt(100000, 999999);

  sendMail(createdUser.email, "Your OTP", `<h3>Your OTP Code is ${otp}</h3>`);

  await authRepo.createOTP(
    otp,
    createdUser._id,
    new Date(Date.now() + toMS(2, "m")),
  );

  createdUser.password = undefined;

  return createdUser;
}

async function verifyAccount(email, otp) {
  const user = await userRepo.findUserByEmail(email);

  if (!user) throw new Error("User not found");

  if (user.isVerified) throw new Error("Account is already verified");

  const otpRecord = await authRepo.findOTPByUserId(user._id);

  if (!otpRecord) throw new Error("OTP not found");

  if (otpRecord.code !== otp) throw new Error("Invalid OTP");

  await userRepo.updateUser(user._id, {
    isVerified: true,
  });

  await authRepo.deleteOTPByUserId(user._id);
}

async function resendOTP(email) {
  const user = await userRepo.findUserByEmail(email);

  if (!user) throw new Error("User not found");

  if (user.isVerified) throw new Error("Account is already verified");

  await authRepo.deleteOTPByUserId(user._id);

  const otp = crypto.randomInt(100000, 999999);

  sendMail(user.email, "Your OTP", `<h3>Your OTP Code is ${otp}</h3>`);

  await authRepo.createOTP(otp, user._id, new Date(Date.now() + toMS(2, "m")));
}

async function login(email, password) {
  const user = await userRepo.findUserByEmail(email);

  if (!user) {
    throw new Error("Invalid email or password");
  }

  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) throw new Error("Invalid email or password");

  if (!user.isVerified) throw new Error("Account is not verified");

  const token = jwt.sign(
    {
      sub: user._id,
      name: user.userName,
      email: user.email,
    },
    SECRET_KEY,
    {
      expiresIn: toMS(1, "h"),
    },
  );

  return { token };
}

export default { register, verifyAccount, resendOTP, login };
