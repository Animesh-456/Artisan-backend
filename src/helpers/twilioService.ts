import Twilio from 'twilio';

// Replace with your Twilio credentials
const accountSid = process.env.TWILIO_ACCOUNT_SID || '';
const authToken = process.env.TWILIO_AUTH_TOKEN || '';
const serviceSid = process.env.TWILIO_SERVICE_SID || '';

const client = Twilio(accountSid, authToken);

export const sendOtp = async (phoneNumber: string): Promise<void> => {
  try {
    await client.verify.v2.services(serviceSid)
      .verifications
      .create({
        to: phoneNumber,
        channel: 'sms', // You can also use 'call' for voice OTPs
      });
    console.log('OTP sent successfully');
  } catch (error) {
    console.error('Error sending OTP:', error);
    throw new Error('Failed to send OTP');
  }
};

export const verifyOtp = async (phoneNumber: string, code: string): Promise<boolean> => {
  try {
    const verification = await client.verify.v2.services(serviceSid)
      .verificationChecks
      .create({
        to: phoneNumber,
        code: code,
      });

    return verification.status === 'approved';
  } catch (error) {
    console.error('Error verifying OTP:', error);
    throw new Error('Failed to verify OTP');
  }
};
