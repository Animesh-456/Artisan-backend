import axios from "axios";
import cashfreeCredentials from "@config/cashfreeCredentials";

export async function verifyCashfree(orderId: string) {
    try {
        const response = await axios.get(`${cashfreeCredentials.cashfree_api_url}/pg/orders/${orderId}`, {
            headers: {
                'accept': 'application/json',
                'x-api-version': `${cashfreeCredentials?.x_api_version}`,
                'x-client-id': `${cashfreeCredentials?.x_client_id}`,
                'x-client-secret': `${cashfreeCredentials?.x_client_ecret}`,
            },
        });
        return response.data;
    } catch (error) {
        console.error('Error fetching payment status:', error);
        throw new Error('Failed to fetch payment status');
    }
}
