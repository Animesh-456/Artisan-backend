
import mail from "@config/mail";
import { any, object } from "joi";
import nodemailer from "nodemailer";

export async function sendMailtest(
	data: any
) {
	const { to, html, body, subject, isAsync, attachment } = data;
	const transporter = nodemailer.createTransport({
		//service: "Gmail",
		host: 'jhunsinfobay.com',
		port: 465,
		secure: true,
		auth: {
			user: 'kazi@jhunsinfobay.com',
			pass: 'fkkyyzvqzhhsocvy',
		},
		//tls: { ciphers: "SSLv3" },
	});

	let mailOption;
	mailOption = {
		from: `kazi@jhunsinfobay.com`,
		to: to,
		subject: subject || "",
		html: html || body,
		//bcc: "notification@usineur.fr",

	};

	if (isAsync) {
		await transporter.sendMail(mailOption, function (error, info) {
			if (error) {
				console.log(error);
			} else {
				console.log("Email sent for verification: " + info.response);
			}
		});
	} else {
		return transporter.sendMail(mailOption);
	}
}

export const site_mail_data2 = {
	"!site_name": "Usineur.fr",
	"!site_url": "www.usineur.fr",
	"!contact_url": "admin@Usineur.fr",
	"!site_title": "Usineur",


}
