import jwt from "jsonwebtoken";


export const createVerificationToken = async(user: any) => {
    const payload = { id: user.id, email: user.email };
    const token = await jwt.sign(payload, 'ahjuii88hsgd', { expiresIn: '1h' });
    return token;
};
