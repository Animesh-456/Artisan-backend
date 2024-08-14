import axios from "axios";

export async function verifyCashfree(orderId: string) {
    try {
        const response = await axios.get(`https://sandbox.cashfree.com/pg/orders/${orderId}`, {
            headers: {
                'accept': 'application/json',
                'x-api-version': '2023-08-01',
                'x-client-id': 'TEST10167206cb646b2c5b786024977f60276101',
                'x-client-secret': 'cfsk_ma_test_27727896027d911c54b85a03aa909f2d_248e91f4',
            },
        });
        return response.data;
    } catch (error) {
        console.error('Error fetching payment status:', error);
        throw new Error('Failed to fetch payment status');
    }
}
