import dotenv from "dotenv";
dotenv.config();

export default {
    cashfree_api_url: String(process.env.CASHFREE_API_URL),
    return_url: String(process.env.RETURN_URL),
    cancel_url: String(process.env.CANCEL_URL),
    order_currency: String(process.env.ORDER_CURRENCY),
    x_client_id: process.env.XClientId,
    x_client_ecret: process.env.XClientSecret,
    x_api_version: String(process.env.X_API_VERSION),
}