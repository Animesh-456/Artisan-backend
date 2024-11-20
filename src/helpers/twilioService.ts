import Twilio from 'twilio';

// Replace with your Twilio credentials
const accountSid = process.env.TWILIO_ACCOUNT_SID || 'ACe4cb4a5c3a3db30dbe9a09c951431555';
const authToken = process.env.TWILIO_AUTH_TOKEN || '0582a1d043ab011460800fa91d427b0b';
const serviceSid = process.env.TWILIO_SERVICE_SID || 'VAfb26928bf6d4f0026e0df34f24c2e8fb';


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
