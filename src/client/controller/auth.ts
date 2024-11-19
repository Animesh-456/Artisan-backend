import express, { Request, Response } from "express";
import { asyncWrapper, R } from "@helpers/response-helpers";
import { UserAuthRequest } from "@middleware/auth";
import Joi from "joi";
import models from "@model/index";
import { Op, Sequelize } from "sequelize";
import db from "@db/mysql";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import env from "@config/env";
import { Validate } from "@validation/utils";
import schema from "@validation/schema";
import { uploadFile, uploadMachiningFile, uploadOneFile, uploadProtpic } from "@helpers/upload";
import moment from "moment";
import { sendMail, site_mail_data } from "@helpers/mail";
import crypto from 'crypto';
import mail from "@config/mail";
import { createVerificationToken } from "@helpers/emailVerification";

import { sendOtp, verifyOtp } from '@helpers/twilioService';

export default {
	test: asyncWrapper(async (req: UserAuthRequest, res: Response) => {
		return R(res, true, "Test Route from Auth");
	}),

	register: asyncWrapper(async (req: UserAuthRequest, res: Response) => {

		//console.log("data 1", req.body);

		//validation
		const schema = Joi.object({
			role: Joi.number().required(),
			email: Joi.string().required(),
			check: Joi.boolean().required(),
		})
			.unknown(true)
			.validate(req.body);


		if (schema.error) {
			return R(res, false, schema.error.message);
		}

		let data = schema.value;

		let objectToBeDeleted = ["role", "check"];

		// Check if data["check"] is true
		if (data.check) {
			let role = await models.roles.findOne({
				where: {
					id: data.role,
				},
			});

			if (!role) {
				return R(res, false, "Invalid Role");
			}

			let userExist = await models.users.count({
				where: {
					email: data.email,
				},
			});

			if (userExist > 0) {
				return R(res, false, "You already have an Account");
			}

			return R(res, true, "Account can be created", {
				role: role,
			});
		} else if (data.role === 1) {
			//user is customer

			//machinist validation




			const schema = Joi.object({
				account: Joi.string().required(),
				name: Joi.string().required(),
				surname: Joi.string().required(),
				user_name: Joi.string().required(),
				email: Joi.string().required(),
				password: Joi.string()
					.pattern(new RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.{6,})"))
					.required()
					.messages({
						"string.pattern.base":
							"Password must contains at least 6 characters, including UPPER or lowercase with numbers.",
					}),
				siren: Joi.required(),
				company_name: Joi.required(),
				company_number: Joi.required(),
				pro_user: Joi.required(),
				show_modal: Joi.required(),
				mobile_number: Joi.number().required()
			})
				.unknown(true)
				.validate(req.body);

			if (schema.error) {
				return R(res, false, schema.error.message);
			}

			let data = schema.value;

			let userPassword = data.password;

			let userExist = await models.users.count({
				where: {
					[Op.or]: [
						{
							user_name: data.user_name,
						},
						{
							email: data.email,
						},
					],
				},
			});

			if (userExist > 0) {
				return R(res, false, "Username or Email already exists");
			}

			// Logic for validating duplicate mobile_number

			let userExist2 = await models.users.count({
				where: {
					mobile_number: data?.mobile_number
				},
			});

			if (userExist2 > 0) {
				return R(res, false, "Mobile number already exists");
			}


			if (req.body.pro_user == 1) {
				data["pro_user"] = 1
			}

			data["siren"] = req.body.siren

			data["role_id"] = 1;
			data["created"] = moment().unix();
			data["country_code"] = 2;
			data["mobileVerified"] = 1;
			const hash = crypto.createHash('md5');
			hash.update(data?.password);
			const hashedPassword = hash.digest('hex');
			console.log("hashbefore", hashedPassword)


			data.password = hashedPassword;
			data.mobile_number = req?.body?.mobile_number;

			objectToBeDeleted.forEach((f) => delete data[f]);

			let user = await models.users.create(data);

			const token = jwt.sign({ id: user.id }, env.secret);

			let u: any = user.toJSON();
			delete u.password;
			u["token"] = token;

			// send mail function


			const verifyToken = await createVerificationToken(user);

			const backendURL = 'https://db.aartstudio.in/'

			const verificationLink = `${backendURL}user/auth/verify-email?token=${verifyToken}`;

			const api_data_rep: object = {
				"!username": user.user_name,
				"!usertype": "customer",
				"!password": userPassword,
				"!activation_url": `${verificationLink}`
			};



			let task_id = 186;

			const mailData = await models.email_templates.findOne({
				where: {
					id: task_id,
					country_code: "en",
				},
				attributes: ["title", "mail_subject", "mail_body"],
			});

			var body = mailData?.mail_body;
			var title = mailData?.title;
			var subject = mailData?.mail_subject;

			(Object.keys(api_data_rep) as (keyof typeof api_data_rep)[]).forEach(
				(key) => {
					if (body?.includes(key)) {
						var re = new RegExp(key, "g");
						body = body.replace(re, api_data_rep[key]);
					}

					if (title?.includes(key)) {
						var re = new RegExp(key, "g");
						title = title.replace(re, api_data_rep[key]);
					}

					if (subject?.includes(key)) {
						var re = new RegExp(key, "g");
						subject = subject.replace(re, api_data_rep[key]);
					}
				}
			);

			(Object.keys(site_mail_data) as (keyof typeof site_mail_data)[]).forEach(
				(key) => {
					if (body?.includes(key)) {
						var re = new RegExp(key, "g");

						body = body.replace(re, site_mail_data[key]);
					}

					if (title?.includes(key)) {
						var re = new RegExp(key, "g");
						title = title.replace(re, site_mail_data[key]);
					}

					if (subject?.includes(key)) {
						var re = new RegExp(key, "g");
						subject = subject.replace(re, site_mail_data[key]);
					}
				}
			);

			sendMail({ to: data.email, subject, body });



			return R(res, true, "Registered", u);
		} else if (data.role === 2) {
			//user is machinist

			//machinist validation
			const schema = Joi.object({
				user_name: Joi.string().required(),
				email: Joi.string().required(),
				password: Joi.string()
					.pattern(new RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.{6,})"))
					.required()
					.messages({
						"string.pattern.base":
							"Password must contains at least 6 characters, including UPPER or lowercase with numbers.",
					}),
				// password_confirmation: Joi.any()
				// 	.equal(Joi.ref("password"))
				// 	.required()
				// 	.messages({ "any.only": "{{#label}} does not match" }),
				name: Joi.string().required(),
				surname: Joi.string().required(),
				address1: Joi.required(),
				zcode: Joi.required(),
				city: Joi.required(),
				company_name: Joi.required(),
				company_number: Joi.required(),
				Squestion: Joi.required(),
				answer: Joi.required(),
				category: Joi.string().required(),
				mobile_number: Joi.number().required()
			})
				.unknown(true)
				.validate(req.body);

			if (schema.error) {
				return R(res, false, schema.error.message);
			}

			let data = schema.value;

			const machanicPass = data.password;

			let userExist = await models.users.count({
				where: {
					[Op.or]: [
						{
							user_name: data.user_name,
						},
						{
							email: data.email,
						},
					],
				},
			});

			if (userExist > 0) {
				return R(res, false, "Username or Email already exists");
			}

			// Logic for validating duplicate mobile_number

			let userExist2 = await models.users.count({
				where: {
					mobile_number: data?.mobile_number
				},
			});

			if (userExist2 > 0) {
				return R(res, false, "Mobile number already exists");
			}

			data["role_id"] = 2;
			data["created"] = moment().unix();
			data["country_code"] = 2;
			data["mobileVerified"] = 1;
			const hash = crypto.createHash('md5');
			hash.update(data?.password);
			const hashedPassword = hash.digest('hex');
			console.log("hashbefore", hashedPassword)
			data.password = hashedPassword;
			[...objectToBeDeleted, "password_confirmation"].forEach(
				(f) => delete data[f]
			);

			let user = await models.users.create(data);

			const token = jwt.sign({ id: user.id }, env.secret);

			let u: any = user.toJSON();
			delete u.password;
			u["token"] = token;


			// Email verification logic

			const verifyToken = await createVerificationToken(user);

			const backendURL = 'https://db.aartstudio.in/'

			const verificationLink = `${backendURL}user/auth/verify-email?token=${verifyToken}`;

			//console.log("verificationLink", verificationLink)


			// send mail function

			const api_data_rep: object = {
				"!username": user.user_name,
				"!usertype": "machanic",
				"!password": machanicPass,
				"!activation_url": `${verificationLink}`
			};



			let task_id = 1;

			const mailData = await models.email_templates.findOne({
				where: {
					id: task_id,
					country_code: "en",
				},
				attributes: ["title", "mail_subject", "mail_body"],
			});

			var body = mailData?.mail_body;
			var title = mailData?.title;
			var subject = mailData?.mail_subject;

			(Object.keys(api_data_rep) as (keyof typeof api_data_rep)[]).forEach(
				(key) => {
					if (body?.includes(key)) {
						var re = new RegExp(key, "g");
						body = body.replace(re, api_data_rep[key]);
					}

					if (title?.includes(key)) {
						var re = new RegExp(key, "g");
						title = title.replace(re, api_data_rep[key]);
					}

					if (subject?.includes(key)) {
						var re = new RegExp(key, "g");
						subject = subject.replace(re, api_data_rep[key]);
					}
				}
			);

			(Object.keys(site_mail_data) as (keyof typeof site_mail_data)[]).forEach(
				(key) => {
					if (body?.includes(key)) {
						var re = new RegExp(key, "g");

						body = body.replace(re, site_mail_data[key]);
					}

					if (title?.includes(key)) {
						var re = new RegExp(key, "g");
						title = title.replace(re, site_mail_data[key]);
					}

					if (subject?.includes(key)) {
						var re = new RegExp(key, "g");
						subject = subject.replace(re, site_mail_data[key]);
					}
				}
			);

			sendMail({ to: data.email, subject, body });

			return R(res, true, "Registered", u);
		}
	}),



	verifyEmail: asyncWrapper(async (req: UserAuthRequest, res: Response) => {


		const token: any = req.query.token;

		if (!token) {
			return res.status(400).send('Invalid token');
		}

		jwt.verify(token, 'ahjuii88hsgd', async (err: any, decoded: any) => {
			if (err) {
				return R(res, false, "Invalid/Expired token");
			}

			let user = await models.users.findOne({
				where: {
					id: decoded?.id,
				},
			});

			if (!user) return R(res, false, "Invalid/Expired token");
			if (user.emailVerified == 1) return R(res, true, "Email already verified");

			await user?.update({ emailVerified: 1 })
			return res.redirect(`${mail.mailbaseurl}auth/sign-in`)
			//return R(res, true, "Email Verified");
		});


	}),



	resendverifyEmail: asyncWrapper(async (req: UserAuthRequest, res: Response) => {
		//validation

		const { email } = req.body;

		try {
			const user = await models.users.findOne({
				where: {
					email: email
				}
			});

			if (!user) {
				return R(res, false, "Email not found");
			}

			if (user.emailVerified == 1) {
				return R(res, false, "Email Already verified");
			}

			const verifyToken = await createVerificationToken(user);

			const backendURL = 'https://db.aartstudio.in/'


			const verificationLink = `${backendURL}user/auth/verify-email?token=${verifyToken}`;




			// send mail function

			const api_data_rep: object = {
				"!username": user.user_name,
				"!usertype": "machanic",
				"!activation_url": `${verificationLink}`
			};



			let task_id = 188;

			const mailData = await models.email_templates.findOne({
				where: {
					id: task_id,
					country_code: "en",
				},
				attributes: ["title", "mail_subject", "mail_body"],
			});

			var body = mailData?.mail_body;
			var title = mailData?.title;
			var subject = mailData?.mail_subject;

			(Object.keys(api_data_rep) as (keyof typeof api_data_rep)[]).forEach(
				(key) => {
					if (body?.includes(key)) {
						var re = new RegExp(key, "g");
						body = body.replace(re, api_data_rep[key]);
					}

					if (title?.includes(key)) {
						var re = new RegExp(key, "g");
						title = title.replace(re, api_data_rep[key]);
					}

					if (subject?.includes(key)) {
						var re = new RegExp(key, "g");
						subject = subject.replace(re, api_data_rep[key]);
					}
				}
			);

			(Object.keys(site_mail_data) as (keyof typeof site_mail_data)[]).forEach(
				(key) => {
					if (body?.includes(key)) {
						var re = new RegExp(key, "g");

						body = body.replace(re, site_mail_data[key]);
					}

					if (title?.includes(key)) {
						var re = new RegExp(key, "g");
						title = title.replace(re, site_mail_data[key]);
					}

					if (subject?.includes(key)) {
						var re = new RegExp(key, "g");
						subject = subject.replace(re, site_mail_data[key]);
					}
				}
			);

			sendMail({ to: email, subject, body });

			return R(res, true, "Verification link sent again");
		} catch (error) {
			return R(res, false, "Error sending email link");
		}





	}),




	login: asyncWrapper(async (req: UserAuthRequest, res: Response) => {
		//validation
		const schema = Joi.object({
			email_username: Joi.string().required(),
			password: Joi.string().required(),
		}).validate(req.body);

		if (schema.error) {
			return R(res, false, schema.error.message);
		}

		let data = schema.value;

		let user = await models.users.findOne({
			where: {
				[Op.or]: [
					{
						email: data.email_username,
					},
					{
						user_name: data.email_username,
					},
				],
			},
		});

		if (!user) {
			return R(res, false, "Invalid Credentials");
		}



		function hashPassword(password: any) {
			const hash = crypto.createHash('md5');
			hash.update(password);
			const hashedPassword = hash.digest('hex');
			console.log("hashbefore", hashedPassword)
			return hashedPassword;
		}

		function verifyPassword(plainTextPassword: any, hashedPassword: any) {
			const hashedPlainTextPassword = hashPassword(plainTextPassword);
			return hashedPlainTextPassword === hashedPassword;
		}

		// Example usage
		let plainTextPassword = data.password;
		let hashedPasswordFromDatabase = user.password; // Example MD5 hashed password from the database

		console.log("plainTextPassword", plainTextPassword);
		console.log("hashedPasswordFromDatabase", hashedPasswordFromDatabase)

		const isMatch = verifyPassword(plainTextPassword, hashedPasswordFromDatabase);

		console.log("crypt veryfy is", isMatch);

		// if (!bcrypt.compareSync(data.password, user.password || "")) {
		// 	return R(res, false, "Invalid Credentials.");
		// }

		if (isMatch == false) {
			return R(res, false, "Invalid Credentials.");
		}
		let current_date = new Date();
		user.last_seen = current_date;

		await user.save();

		await models.login_info.create({
			user_id: (user.id),
			ip_address: `${req.headers["x-forwarded-for"]}`.split(",")[0] || "",
		});

		let user_balance = await models.user_balance.findOne({
			where: {
				user_id: user.id,
			},
		});

		if (!user_balance) {
			await models.user_balance.create({
				user_id: user.id,
				amount: 0.0,
				amount_gbp: 0.0,
			});
		}

		const token = jwt.sign({ id: user.id }, env.secret);

		console.log('token is ', token)

		let u: any = user.toJSON();
		delete u.password;
		u["token"] = token;

		return R(res, true, "Logged in successfully", u);
	}),

	me: asyncWrapper(async (req: UserAuthRequest, res: Response) => {
		let user = await models.users.findOne({
			where: {
				id: req.user?.id,
			},
			include: [
				{
					model: models.country,
					as: "country_code_country",
				},
			],
			attributes: { exclude: ["password"] },
		});

		if (!user) {
			return R(res, false, "Invalid User");
		}


		const categoryIds = user?.category
			? user?.category.split(',').map((id: any) => parseInt(id.trim(), 10))
			: [];

		// Fetch category names from Project_categories
		const categories = await models.Project_categories.findAll({
			where: {
				id: {
					[Op.in]: categoryIds
				}
			}
		});

		// Create a map of ID to category name
		const categoryMap = new Map<number, string>();
		categories.forEach(category => {
			categoryMap.set(category?.id, category?.category_name);
		});

		// Replace comma-separated IDs with category names
		const categoryNames = categoryIds
			.map((id: any) => categoryMap.get(id))
			.filter((name: any) => name !== undefined);

		// Include category names in the project object
		const projectWithCategories = {
			...user.toJSON(),
			category_names: categoryNames
		};
		return R(res, true, "User data", projectWithCategories);
	}),

	delivery_contacts: asyncWrapper(async (req: UserAuthRequest, res: Response) => {

		console.log("req-->", req);
		let id: number = Number(req.query.id);
		console.log("id--------", id)
		let project = await models.projects.findOne({
			where: {
				id: id

			}

		});
		let user = await models.delivery_contacts.findOne({
			where: {
				project_id: id,
				// user_id: project?.creator_id,

			},


		});


		return R(res, true, "delivery User data", user);
	}),


	update: asyncWrapper(async (req: UserAuthRequest, res: Response) => {


		// validation
		let data = await Validate(res, [], schema.user.editUser, req.body, {});







		let user = await models.users.findOne({
			where: {
				id: req.user?.id,
			},
		});

		if (!user) {
			return R(res, false, "Invalid user");
		}

		let country = await models.country.findOne({
			where: {
				id: data.country_code,
			},
		});

		if (!country) {
			return R(res, false, "Invalid country");
		}
		let file;

		if (req.query?.change_pic) {
			// file upload
			file = await uploadOneFile(req, res);
		}

		if (file) {
			data["prof_pic"] = file;
			data["logo"] = file;
		}

		data["country_code"] = country.id;
		data["country_symbol"] = data?.country_symbol;

		if (user?.role_id == 2) {
			data["service_desc"] = req.body.service_desc;
			data["description"] = "";
		} else {
			data["service_desc"] = "";
			data["description"] = req.body.description;
		}

		if (user?.role_id == 2 && user?.pro_user == 1) {
			data["pro_vat"] = req.body.tva;
			data["company_name"] = req.body.company_name;
			data["siren"] = req.body.siren;
		}

		await user.update(data);
		// await user.save();
		if (req.files?.file2) {
			let file2 = await uploadProtpic(req, res)
			let concatenatedData = file2.join(',');
			if (user?.prot_pic != null && user?.prot_pic != "") {
				await user?.update({ prot_pic: Sequelize.literal(`concat(prot_pic, ',', '${concatenatedData}')`) })
			} else {
				await user?.update({ prot_pic: concatenatedData })
			}

		}






		return R(res, true, "profile updated");
	}),

	update_pro: asyncWrapper(async (req: UserAuthRequest, res: Response) => {
		let u = await models.users.findOne({
			where: {
				id: req.body.id
			}
		});

		u?.update({ siren: req.body.SIREN, company_name: req.body.company_name, pro_user: req.body.pro_user });
		return R(res, true, "You are now a PRO Customer");
	}),

	update_address: asyncWrapper(async (req: UserAuthRequest, res: Response) => {
		// validation
		let data = await Validate(res, [], schema.user.editAddress, req.body, {});

		let user = await models.users.findOne({
			where: {
				id: req.user?.id,
			},
		});

		if (!user) {
			return R(res, false, "Invalid user");
		}

		await user.update(data);
		// await user.save();

		return R(res, true, "profile updated");
	}),

	save_address: asyncWrapper(async (req: UserAuthRequest, res: Response) => {

		let data = req.body;
		console.log("data address", data);

		if (data?.checkstate === 'true') {
			let usr = await models.users.findOne({
				where: {
					id: data?.user_id
				}
			})

			console.log("user is--", usr)

			if (usr) {
				await usr?.update({ address1: data.address, city: data?.city, zcode: data?.postalcode })
				//console.log("updated usr", usr)
			}

		}


		let deladd = await models.delivery_contacts.findOne({
			where: {
				project_id: data?.project_id,
			}
		})

		if (!deladd) {
			let newAddress = await models.delivery_contacts.create(data);
			console.log("address gen----->>", newAddress);
			return R(res, true, "Address saved");
		}

		else {
			await deladd?.update({
				name: data?.name,
				address: data?.address,
				postalcode: data?.postalcode,
				city: data?.city,

			})
			return R(res, true, "Address saved");

		}

	}),



	change_password: asyncWrapper(async (req: UserAuthRequest, res: Response) => {
		// validation
		let data = await Validate(
			res,
			[],
			schema.user.change_password,
			req.body,
			{},
		);

		let user = await models.users.findOne({
			where: {
				id: req.user?.id,
			},
		});

		if (!user) {
			return R(res, false, "Invalid user");
		}

		function hashPassword(password: any) {
			const hash = crypto.createHash('md5');
			hash.update(password);
			const hashedPassword = hash.digest('hex');
			console.log("hashbefore", hashedPassword)
			return hashedPassword;
		}

		function verifyPassword(plainTextPassword: any, hashedPassword: any) {
			const hashedPlainTextPassword = hashPassword(plainTextPassword);
			return hashedPlainTextPassword === hashedPassword;
		}

		// Example usage
		let plainTextPassword = data.old_password;
		let hashedPasswordFromDatabase = user.password; // Example MD5 hashed password from the database

		console.log("plainTextPassword", plainTextPassword);
		console.log("hashedPasswordFromDatabase", hashedPasswordFromDatabase)

		const isMatch = verifyPassword(plainTextPassword, hashedPasswordFromDatabase);

		console.log("crypt veryfy is", isMatch);

		if (isMatch == false) {
			return R(res, false, "Old Password is not correct.");
		}


		const hash = crypto.createHash('md5');
		hash.update(data.new_password);
		const hashedPassword = hash.digest('hex');

		user.password = hashedPassword;

		await user.save();

		const api_data_rep: object = {
			"!username": user.user_name,
			"!data1": String(data.name),
			"!data2": String(data.surname),
			"!data3": String(data.user_name),
			"!data4": String(data.zcode),
			"!data5": String(data.description),
			"!url": `${mail.mailbaseurl}auth/sign-in`,
			"!newpassword": data.new_password
		};

		let task_id = 101;

		const mailData = await models.email_templates.findOne({
			where: {
				id: task_id,
				country_code: "en",
			},
			attributes: ["title", "mail_subject", "mail_body"],
		});

		var body = mailData?.mail_body;
		var title = mailData?.title;
		var subject = mailData?.mail_subject;

		(Object.keys(api_data_rep) as (keyof typeof api_data_rep)[]).forEach(
			(key) => {
				if (body?.includes(key)) {
					var re = new RegExp(key, "g");
					body = body.replace(re, api_data_rep[key]);
				}

				if (title?.includes(key)) {
					var re = new RegExp(key, "g");
					title = title.replace(re, api_data_rep[key]);
				}

				if (subject?.includes(key)) {
					var re = new RegExp(key, "g");
					subject = subject.replace(re, api_data_rep[key]);
				}
			}
		);

		(Object.keys(site_mail_data) as (keyof typeof site_mail_data)[]).forEach(
			(key) => {
				if (body?.includes(key)) {
					var re = new RegExp(key, "g");

					body = body.replace(re, site_mail_data[key]);
				}

				if (title?.includes(key)) {
					var re = new RegExp(key, "g");
					title = title.replace(re, site_mail_data[key]);
				}

				if (subject?.includes(key)) {
					var re = new RegExp(key, "g");
					subject = subject.replace(re, site_mail_data[key]);
				}
			}
		);

		sendMail({ to: user?.email, subject, body });

		return R(res, true, "Password Changed");
	}),

	list_countries: asyncWrapper(async (req: UserAuthRequest, res: Response) => {
		let countries = await models.country_master.findAll({});

		return R(res, true, "country data", countries);
	}),

	machanic_details: asyncWrapper(async (req: UserAuthRequest, res: Response) => {

		let machanic_id: number = Number(req.query.mach_id);
		console.log("recieved id--", machanic_id);

		let user = await models.users.findOne({
			where: {
				id: machanic_id,
			},
			include: [
				{
					model: models.country,
					as: "country_code_country",
				},
			],
			attributes: { exclude: ["password"] },
		});

		//console.log(user);

		if (!user) {
			return R(res, false, "Invalid User");
		}
		return R(res, true, "User data", user);


	}),

	user_balance: asyncWrapper(async (req: UserAuthRequest, res: Response) => {

		let userBalance = await models.user_balance.findOne({
			where: {
				user_id: req.user?.id,
			}
		});

		console.log(userBalance);

		if (!userBalance) {
			return R(res, false, "Invalid User");
		}
		return R(res, true, "User balance data", userBalance);

	}),

	update_balance: asyncWrapper(async (req: UserAuthRequest, res: Response) => {

		let balanceData = await models.user_balance.findOne({
			where: {
				user_id: req.user?.id,
			}
		});

		if (!balanceData) {
			return R(res, false, "Invalid User");
		}

		if (balanceData?.amount == 0 || balanceData?.amount_gbp == 0) return R(res, false, "No balance to withdraw!");


		if (req.body.val > balanceData?.amount) return R(res, false, "Insufficient balance to withdraw!");

		const user = await models.users.findOne({
			where: {
				id: req.user?.id
			}
		})

		const amt = req.body.val;
		const paypal_email = req.body.paypal_email ? req.body.paypal_email : "";

		let euro_amt = amt;

		const amountWithdraw = balanceData.amount_gbp - req.body.balance;

		balanceData.amount_gbp = req.body.balance
		balanceData.amount = req.body.balance


		//await balanceData.save();

		//const userMail = req.user?.email;

		//console.log(user?.email);


		if (req.body.method == "paypal") {


			let data22: any = {
				type: "Withdraw",
				creator_id: user?.id,
				buyer_id: 0,
				provider_id: user?.id,
				transaction_time: moment().unix(),
				amount: amt,
				amount_gbp: amt,
				status: "Pending",
				description: "Withdraw Amount From Paypal",
				paypal_address: paypal_email,
				user_type: "Supplier",
				country_code: "2"
			}

			let transac_create = await models.transactions.create(data22)


			const api_data_rep: object = {
				"!username": user?.user_name,
				"!amount": amountWithdraw

			}




			let task_id = 177;

			const mailData = await models.email_templates.findOne({
				where: {
					id: task_id,
					country_code: "en"
				},
				attributes: ["title", "mail_subject", "mail_body"],
			});

			var body = mailData?.mail_body;
			var title = mailData?.title;
			var subject = mailData?.mail_subject;

			(Object.keys(api_data_rep) as (keyof typeof api_data_rep)[]).forEach(key => {
				if (body?.includes(key)) {
					var re = new RegExp(key, 'g');
					body = body.replace(re, api_data_rep[key])
				}

				if (title?.includes(key)) {
					var re = new RegExp(key, 'g');
					title = title.replace(re, api_data_rep[key])
				}

				if (subject?.includes(key)) {
					var re = new RegExp(key, 'g');
					subject = subject.replace(re, api_data_rep[key])
				}




			});


			(Object.keys(site_mail_data) as (keyof typeof site_mail_data)[]).forEach(key => {


				if (body?.includes(key)) {

					var re = new RegExp(key, 'g');

					body = body.replace(re, site_mail_data[key])
				}

				if (title?.includes(key)) {
					var re = new RegExp(key, 'g');
					title = title.replace(re, site_mail_data[key])
				}

				if (subject?.includes(key)) {
					var re = new RegExp(key, 'g');
					subject = subject.replace(re, site_mail_data[key])
				}
			})

			sendMail({ to: user?.email, subject, body });

			const cdate = new Date()
			let data: any = {
				email_type: title,
				email_subject: subject,
				supplier_id: req.user?.id,
				email_body: body,
				notif_date: cdate,
				message_status: "R",
				project_id: 0,
				customer_id: 0

			}


			let notifs = await models.notif_email_list.create(data)


		}
		else {

			let data23: any = {
				type: "Withdraw",
				creator_id: user?.id,
				buyer_id: 0,
				provider_id: user?.id,
				transaction_time: moment().unix(),
				amount: euro_amt,
				amount_gbp: amt,
				status: "Pending",
				description: "Withdraw Amount From Bank",
				paypal_address: user?.email,
				user_type: "Supplier",
				country_code: "2"
			}

			let transac_create = await models.transactions.create(data23)


			const api_data_rep: object = {
				"!username": user?.user_name,
				"!amount": amountWithdraw

			}




			let task_id = 175;

			const mailData = await models.email_templates.findOne({
				where: {
					id: task_id,
					country_code: "en"
				},
				attributes: ["title", "mail_subject", "mail_body"],
			});

			var body = mailData?.mail_body;
			var title = mailData?.title;
			var subject = mailData?.mail_subject;

			(Object.keys(api_data_rep) as (keyof typeof api_data_rep)[]).forEach(key => {
				if (body?.includes(key)) {
					var re = new RegExp(key, 'g');
					body = body.replace(re, api_data_rep[key])
				}

				if (title?.includes(key)) {
					var re = new RegExp(key, 'g');
					title = title.replace(re, api_data_rep[key])
				}

				if (subject?.includes(key)) {
					var re = new RegExp(key, 'g');
					subject = subject.replace(re, api_data_rep[key])
				}




			});


			(Object.keys(site_mail_data) as (keyof typeof site_mail_data)[]).forEach(key => {


				if (body?.includes(key)) {

					var re = new RegExp(key, 'g');

					body = body.replace(re, site_mail_data[key])
				}

				if (title?.includes(key)) {
					var re = new RegExp(key, 'g');
					title = title.replace(re, site_mail_data[key])
				}

				if (subject?.includes(key)) {
					var re = new RegExp(key, 'g');
					subject = subject.replace(re, site_mail_data[key])
				}
			})

			sendMail({ to: user?.email, subject, body });

			const cdate = new Date()
			let data: any = {
				email_type: title,
				email_subject: subject,
				supplier_id: req.user?.id,
				email_body: body,
				notif_date: cdate,
				message_status: "R",
				project_id: 0,
				customer_id: 0

			}


			let notifs = await models.notif_email_list.create(data)


		}



		return R(res, true, "Updated balance data", balanceData);

	}),

	user_projects: asyncWrapper(async (req: UserAuthRequest, res: Response) => {

		let user = await models.users.findOne({
			where: {
				id: req.user?.id,
			},
		});

		if (user?.role_id == 1) {
			let user_project = await models.projects.findAll({
				where: {
					creator_id: req.user?.id,
					project_status: 5
				},
				attributes: ["id"],
			});


			return R(res, true, " Projects list", user_project);

		}



		let mach_project = await models.projects.findAll({
			where: {
				programmer_id: req.user?.id,
				project_status: 5
			},
			attributes: ["id"],
		});




		return R(res, true, " Projects list", mach_project);




	}),

	user_spent: asyncWrapper(async (req: UserAuthRequest, res: Response) => {

		let totalSpent = await models.transactions.findAll({
			where: {
				[Op.and]: [
					{
						creator_id: req.user?.id,
					},
					{
						type: 'PAID TO MACHINIST',
					},
				],

			},
			attributes: ["amount", "amount_gbp"]

		});

		if (!totalSpent) {
			return R(res, false, "Invalid User");
		}

		return R(res, true, "Updated balance data", totalSpent);

	}),
	update_modal: asyncWrapper(async (req: UserAuthRequest, res: Response) => {
		let id = req.body.id;
		let u = await models.users.findOne({
			where: {
				id: id
			}
		})
		u?.update({ show_modal: req.body.showmodal });
		return R(res, true, "Modal hidden");
	}),






	generate_new_password: asyncWrapper(async (req: UserAuthRequest, res: Response) => {

		let email = req.body.email;

		let users = await models.users.findOne({
			where: {
				email: email
			}
		})

		if (!users) {
			return R(res, false, "No user found with this email");
		}


		function generateRandomString(length: any) {
			const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';

			let password = '';
			for (let i = 0; i < length; i++) {
				const randomIndex = Math.floor(Math.random() * charset.length);
				password += charset[randomIndex];
			}

			return password;
		}

		// Generate a random string password with a length of 12 characters
		const randomPassword = generateRandomString(12);
		console.log(randomPassword);



		//creating hash and updating password


		const hash = crypto.createHash('md5');
		hash.update(randomPassword);
		const hashedPassword = hash.digest('hex');
		console.log("hashpassword", hashedPassword)

		await users?.update({ password: hashedPassword });



		//email functionality


		const api_data_rep: object = {
			"!newpassword": randomPassword,
			"!username": users?.user_name,
			"!url": `${mail?.mailbaseurl}auth/sign-in`
		}




		let task_id = 101;

		const mailData = await models.email_templates.findOne({
			where: {
				id: task_id,
				country_code: "en"
			},
			attributes: ["title", "mail_subject", "mail_body"],
		});

		var body = mailData?.mail_body;
		var title = mailData?.title;
		var subject = mailData?.mail_subject;

		(Object.keys(api_data_rep) as (keyof typeof api_data_rep)[]).forEach(key => {
			if (body?.includes(key)) {
				var re = new RegExp(key, 'g');
				body = body.replace(re, api_data_rep[key])
			}

			if (title?.includes(key)) {
				var re = new RegExp(key, 'g');
				title = title.replace(re, api_data_rep[key])
			}

			if (subject?.includes(key)) {
				var re = new RegExp(key, 'g');
				subject = subject.replace(re, api_data_rep[key])
			}




		});


		(Object.keys(site_mail_data) as (keyof typeof site_mail_data)[]).forEach(key => {


			if (body?.includes(key)) {

				var re = new RegExp(key, 'g');

				body = body.replace(re, site_mail_data[key])
			}

			if (title?.includes(key)) {
				var re = new RegExp(key, 'g');
				title = title.replace(re, site_mail_data[key])
			}

			if (subject?.includes(key)) {
				var re = new RegExp(key, 'g');
				subject = subject.replace(re, site_mail_data[key])
			}
		})

		sendMail({ to: users?.email, subject, body });


		return R(res, true, "Password set");

	}),


	forgot_username: asyncWrapper(async (req: UserAuthRequest, res: Response) => {

		let email = req.body.email;

		let users = await models.users.findOne({
			where: {
				email: email
			}
		})

		if (!users) {
			return R(res, false, "No user found with this email");
		}




		//email functionality


		const api_data_rep: object = {
			"!username": users?.user_name,
			"!url": `${mail.mailbaseurl}auth/sign-in`,
			"!email": users?.email
		}




		let task_id = 184;

		const mailData = await models.email_templates.findOne({
			where: {
				id: task_id,
				country_code: "en"
			},
			attributes: ["title", "mail_subject", "mail_body"],
		});

		var body = mailData?.mail_body;
		var title = mailData?.title;
		var subject = mailData?.mail_subject;

		(Object.keys(api_data_rep) as (keyof typeof api_data_rep)[]).forEach(key => {
			if (body?.includes(key)) {
				var re = new RegExp(key, 'g');
				body = body.replace(re, api_data_rep[key])
			}

			if (title?.includes(key)) {
				var re = new RegExp(key, 'g');
				title = title.replace(re, api_data_rep[key])
			}

			if (subject?.includes(key)) {
				var re = new RegExp(key, 'g');
				subject = subject.replace(re, api_data_rep[key])
			}




		});


		(Object.keys(site_mail_data) as (keyof typeof site_mail_data)[]).forEach(key => {


			if (body?.includes(key)) {

				var re = new RegExp(key, 'g');

				body = body.replace(re, site_mail_data[key])
			}

			if (title?.includes(key)) {
				var re = new RegExp(key, 'g');
				title = title.replace(re, site_mail_data[key])
			}

			if (subject?.includes(key)) {
				var re = new RegExp(key, 'g');
				subject = subject.replace(re, site_mail_data[key])
			}
		})

		sendMail({ to: users?.email, subject, body });


		return R(res, true, "Username sent to email");

	}),

	google_register: asyncWrapper(async (req: UserAuthRequest, res: Response) => {

		console.log("body console", req.body)
		const decoded: any = jwt.decode(req.body.token);
		// return R(res, true, "Registered", u);


		const address = req.body.address;
		const hash = crypto.createHash('md5');
		hash.update(req?.body.password);
		const hashedPassword = hash.digest('hex');
		const name = decoded.given_name;
		const lname = decoded.family_name
		const email = decoded.email;
		// const number = req?.body?.number || "";

		function generateRandomUsername(length = 8) {
			const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
			let username = '';

			for (let i = 0; i < length; i++) {
				const randomIndex = Math.floor(Math.random() * characters.length);
				username += characters[randomIndex];
			}

			return username;
		}

		// Example usage:
		const randomUsername = generateRandomUsername();
		console.log("randomUsername", randomUsername);

		const existingUser = await models.users.findOne({ where: { email } });
		if (existingUser) {
			return R(res, false, "User already exists. Please try again with a different email.");
		}
		const schema: any = {
			role_id: req.body.account === 'Customer' ? 1 : 2,
			account: 'Individual',
			name: name,
			surname: lname,
			user_name: randomUsername,
			email: email,
			password: hashedPassword,
			// address1: address,
			siren: '',
			company_name: '',
			company_number: '',
			pro_user: 0,
			show_modal: 0,
			// mobile_number: number,
			emailVerified: 1,
			country_code: 2,
		}


		let user = await models.users.create(schema);
		return R(res, true, "Registered", user);
	}),


	google_login: asyncWrapper(async (req: UserAuthRequest, res: Response) => {
		const { token } = req.body; // Extract token directly from req.body

		if (!token) {
			// Early return if token is missing
			return R(res, false, "Token is required.");
		}

		try {
			// Decode the token
			const decoded: any = jwt.decode(token);

			if (!decoded || !decoded.email) {
				// Return if decoding fails or email is missing
				return R(res, false, "Invalid or malformed token.");
			}

			console.log("Decoded token:", decoded);

			// Fetch the user using the email from decoded token
			const user: any = await models.users.findOne({
				where: {
					email: decoded.email,
				},
			});

			if (!user) {
				return R(res, false, "Invalid credentials or token.");
			}

			// Update user data
			user.last_seen = new Date();
			await user.save();

			// Generate a new token for the user
			const token2 = jwt.sign({ id: user.id }, env.secret);
			const userData = user.toJSON();
			delete userData.password;
			userData["token"] = token2;

			return R(res, true, "Logged in successfully", userData);
		} catch (error) {
			console.error("Token verification error:", error);
			return R(res, false, "Invalid or expired token.");
		}
	}),


	facebook_register: asyncWrapper(async (req: UserAuthRequest, res: Response) => {
		const { token, address, password, account, number } = req.body;

		console.log("Request body:", req.body);

		if (!token) {
			console.error("Access token missing in request body.");
			return res.status(400).json({ error: "Access token is required." });
		}

		try {
			// Fetch user details from Facebook Graph API
			const response = await fetch(`https://graph.facebook.com/me?fields=id,name,email&access_token=${token}`);
			const userData = await response.json();

			// Log if the Facebook API returns an error
			if (userData.error) {
				console.error("Facebook API error:", userData.error.message);
				return res.status(400).json({ error: userData.error.message });
			}

			// Hash the password
			const hash = crypto.createHash('md5');
			hash.update(password);
			const hashedPassword = hash.digest('hex');

			// Generate a random username using a function expression
			const generateRandomUsername = (length = 8) => {
				const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
				let username = '';
				for (let i = 0; i < length; i++) {
					const randomIndex = Math.floor(Math.random() * characters.length);
					username += characters[randomIndex];
				}
				return username;
			};
			const randomUsername = generateRandomUsername();

			// Check if the user already exists
			const existingUser = await models.users.findOne({ where: { email: userData.email } });
			if (existingUser) {
				console.log("User with this email already exists:", userData.email);
				return R(res, false, "User already exists. Please try again with a different email.");
			}

			// Create new user
			const schema: any = {
				role_id: account === 'Customer' ? 1 : 2,
				account: 'Individual',
				name: userData.name,
				surname: "",
				user_name: randomUsername,
				email: userData.email,
				password: hashedPassword,
				address1: address,
				siren: '',
				company_name: '',
				company_number: '',
				pro_user: 0,
				show_modal: 0,
				mobile_number: number,
				emailVerified: 1,
				country_code: 2,
			};

			const user = await models.users.create(schema);

			console.log('User created successfully:', user);
			return R(res, true, "Registered successfully", user);
		} catch (error: any) {
			console.error('Error fetching user data from Facebook:', error.message);
			return R(res, false, "Invalid or expired token.");
		}
	}),




	facebook_login: asyncWrapper(async (req: UserAuthRequest, res: Response) => {
		const { accessToken } = req.body; // Extract token directly from req.body
		console.log("facebook login", req.body);

		if (!accessToken) {
			// Early return if token is missing
			return R(res, false, "Token is required.");
		}

		try {
			// Decode the token
			const response = await fetch(`https://graph.facebook.com/me?fields=id,name,email&access_token=${accessToken}`);
			const decoded: any = await response.json()
			console.log("Decoded token:", decoded);


			if (!decoded || !decoded.email) {
				// Return if decoding fails or email is missing
				return R(res, false, "Invalid or malformed token.");
			}


			// Fetch the user using the email from decoded token
			const user: any = await models.users.findOne({
				where: {
					email: decoded.email,
				},
			});

			if (!user) {
				return R(res, false, "Invalid credentials or token.");
			}

			// Update user data
			user.last_seen = new Date();
			await user.save();

			// Generate a new token for the user
			const token2 = jwt.sign({ id: user.id }, env.secret);
			const userData = user.toJSON();
			delete userData.password;
			userData["token"] = token2;

			return R(res, true, "Logged in successfully", userData);
		} catch (error) {
			console.error("Token verification error:", error);
			return R(res, false, "Invalid or expired token.");
		}
	}),





	// For sending mobile OTP
	OTP_send: asyncWrapper(async (req: UserAuthRequest, res: Response) => {
		const { phoneNumber } = req.body;

		const OTP_REQUEST_LIMIT_MS = 60 * 1000; // 1 minute in milliseconds
		const IST_OFFSET_MS = 5.5 * 60 * 60 * 1000; // IST offset in milliseconds (+5:30)

		try {
			// Fetch user details from the database
			const user = await models.users.findOne({
				where: {
					mobile_number: phoneNumber
				}
			})

			if (!user) return R(res, false, 'No user found');

			// Check if the user has previously requested OTP
			if (user?.lastMobileOtpSentAt) {
				// Convert the stored IST time (in database) to UTC
				const userOtpSentAtIST = new Date(user.lastMobileOtpSentAt); // IST time

				// Convert IST to UTC by subtracting the IST offset (5 hours 30 minutes)
				const userOtpSentAtUTC = new Date(userOtpSentAtIST.getTime() - IST_OFFSET_MS);

				// Get the current time in UTC
				const currentUTC = new Date();

				// Calculate the time difference in milliseconds between the current UTC time and the last OTP sent time (in UTC)
				const timeSinceLastOtp = currentUTC.getTime() - userOtpSentAtUTC.getTime();


				// If the time difference is less than 1 minute (60,000 ms), do not send OTP
				if (timeSinceLastOtp < OTP_REQUEST_LIMIT_MS) {
					return R(res, false, 'OTP already sent. Please wait a minute before requesting a new one.');
				}
			}

			// Update the user's last OTP sent time to the current time
			user.lastMobileOtpSentAt = new Date();
			await user.save();

			const tel = `+91${phoneNumber}`;
			await sendOtp(String(tel)); // Uncomment to actually send OTP

			return R(res, true, "OTP sent successfully");
		} catch (error) {
			console.error("Error sending OTP:", error);
			return R(res, false, "Error sending OTP");
		}
	}),




	// For login with mobile OTP 
	OTP_verify: asyncWrapper(async (req: UserAuthRequest, res: Response) => {
		const { phoneNumber, code } = req.body;

		try {

			const user: any = await models.users.findOne({
				where: {
					mobile_number: phoneNumber
				}
			})

			if (!user) return R(res, false, "No user found with this email");


			const isVerified = await verifyOtp(`+91${phoneNumber}`, code);
			if (isVerified) {

				user.mobileVerified = 1;
				await user.save();

				const token2 = jwt.sign({ id: user.id }, env.secret);
				const userData: any = user.toJSON();
				delete userData.password;
				userData["token"] = token2;
				return R(res, true, "OTP verified successfully", userData);
			} else {
				return R(res, false, "Invalid OTP");
			}
		} catch (error) {
			return R(res, false, "Error validating OTP");
		}
	}),


	// Write api for updating mobile number



	update_mobile_OTP_send: asyncWrapper(async (req: UserAuthRequest, res: Response) => {
		const { userId, phoneNumber } = req.body;

		const OTP_REQUEST_LIMIT_MS = 60 * 1000; // 1 minute in milliseconds
		const IST_OFFSET_MS = 5.5 * 60 * 60 * 1000; // IST offset in milliseconds (+5:30)

		try {
			// Logic for rate limiting to limit sending otp's

			const user = await models.users.findOne({
				where: {
					id: userId
				}
			})

			if (!user) return R(res, false, 'No user found');


			const findMobile = await models.users.findOne({
				where: {
					mobile_number: phoneNumber
				}
			})

			if (findMobile) return R(res, false, 'This mobile number already exists, please provide another number');


			if (user?.lastMobileOtpSentAt) {
				// Convert the stored IST time (in database) to UTC
				const userOtpSentAtIST = new Date(user.lastMobileOtpSentAt); // IST time

				// Convert IST to UTC by subtracting the IST offset (5 hours 30 minutes)
				const userOtpSentAtUTC = new Date(userOtpSentAtIST.getTime() - IST_OFFSET_MS);

				// Get the current time in UTC
				const currentUTC = new Date();

				// Calculate the time difference in milliseconds between the current UTC time and the last OTP sent time (in UTC)
				const timeSinceLastOtp = currentUTC.getTime() - userOtpSentAtUTC.getTime();

				// If the time difference is less than 1 minute (60,000 ms), do not send OTP
				if (timeSinceLastOtp < OTP_REQUEST_LIMIT_MS) {
					return R(res, false, 'OTP already sent. Please wait a minute before requesting a new one.');
				}
			}


			user.lastMobileOtpSentAt = new Date();
			await user.save();
			const tel = `+91${phoneNumber}`
			await sendOtp(String(tel));
			return R(res, true, "OTP sent successfully for update");
		} catch (error) {
			return R(res, false, "Error sending OTP");
		}
	}),



	// For login with mobile OTP 
	update_mobile_OTP_verify: asyncWrapper(async (req: UserAuthRequest, res: Response) => {
		const { phoneNumber, code, userId } = req.body;

		try {

			const user: any = await models.users.findOne({
				where: {
					id: userId
				}
			})

			if (!user) return R(res, false, "No user found with this email");


			const isVerified = await verifyOtp(`+91${phoneNumber}`, code);
			if (isVerified) {

				user.mobileVerified = 1;
				user.mobile_number = phoneNumber;
				await user.save();
				return R(res, true, "OTP verified successfully");
			} else {
				return R(res, false, "Invalid OTP");
			}
		} catch (error) {
			return R(res, false, "Error validating OTP");
		}
	}),








	email_OTP_send: asyncWrapper(async (req: UserAuthRequest, res: Response) => {
		const { email } = req.body;
		const OTP_REQUEST_LIMIT_MS = 60 * 1000;
		try {
			const user = await models.users.findOne({
				where: {
					email: email
				}
			})

			if (!user) return R(res, false, "No user found with this email");

			// Rate limiting logic for email OTP

			if (user?.lastEmailOtpSentAt) {
				const timeSinceLastOtp = Date.now() - new Date(user?.lastEmailOtpSentAt).getTime();
				if (timeSinceLastOtp < OTP_REQUEST_LIMIT_MS) {
					return R(res, false, 'OTP already sent. Please wait a minute before requesting a new one.');
				}
			}

			user.lastEmailOtpSentAt = new Date();
			await user.save();

			const otp = await Math.floor(100000 + Math.random() * 900000).toString().slice(0, length);

			const otpToken = await jwt.sign({ otp, email }, env.secret, { expiresIn: '5m' });

			// Send OTP via email logic below

			const api_data_rep: object = {
				"!OTP": otp,
			}

			let task_id = 189;

			const mailData = await models.email_templates.findOne({
				where: {
					id: task_id,
					country_code: "en"
				},
				attributes: ["title", "mail_subject", "mail_body"],
			});

			var body = mailData?.mail_body;
			var title = mailData?.title;
			var subject = mailData?.mail_subject;

			(Object.keys(api_data_rep) as (keyof typeof api_data_rep)[]).forEach(key => {
				if (body?.includes(key)) {
					var re = new RegExp(key, 'g');
					body = body.replace(re, api_data_rep[key])
				}

				if (title?.includes(key)) {
					var re = new RegExp(key, 'g');
					title = title.replace(re, api_data_rep[key])
				}

				if (subject?.includes(key)) {
					var re = new RegExp(key, 'g');
					subject = subject.replace(re, api_data_rep[key])
				}




			});


			(Object.keys(site_mail_data) as (keyof typeof site_mail_data)[]).forEach(key => {


				if (body?.includes(key)) {

					var re = new RegExp(key, 'g');

					body = body.replace(re, site_mail_data[key])
				}

				if (title?.includes(key)) {
					var re = new RegExp(key, 'g');
					title = title.replace(re, site_mail_data[key])
				}

				if (subject?.includes(key)) {
					var re = new RegExp(key, 'g');
					subject = subject.replace(re, site_mail_data[key])
				}
			})

			sendMail({ to: user?.email, subject, body });

			return R(res, true, "OTP sent successfully", otpToken);
		} catch (error) {
			return R(res, false, "Error sending OTP");
		}
	}),




	email_OTP_verify: asyncWrapper(async (req: UserAuthRequest, res: Response) => {
		const { email, otp } = req.body;

		if (!email || !otp) {
			return R(res, false, "Email and OTP is required");
		}

		try {

			const user = await models.users.findOne({
				where: {
					email: email
				}
			})

			if (!user) {
				return R(res, false, "Invalid user");
			}
			// Retrieve and decode the JWT token
			const token = req.headers.authorization?.split(' ')[1]; // Assume JWT is passed as a Bearer token

			if (!token) {
				return R(res, false, "Invalid token");
			}

			const decoded = jwt.verify(token, env.secret) as { otp: string, email: string };

			if (decoded.email === email && decoded.otp === otp) {

				await user?.update({
					emailVerified: 1
				})

				// Login token generate
				const token2 = jwt.sign({ id: user.id }, env.secret);
				const userData: any = user.toJSON();
				delete userData.password;
				userData["token"] = token2;
				return R(res, true, "OTP verified successfuly", userData);
			} else {
				return R(res, false, "Invalid/Expired OTP. Please try again after sometime");
			}
		} catch (error) {
			return R(res, false, "Invalid/Expired OTP. Please try again after sometime");
		}
	}),


	register_OTP_send: asyncWrapper(async (req: UserAuthRequest, res: Response) => {
		const { phoneNumber, email, user_name } = req.body;

		// Log the phoneNumber to debug
		console.log("Received phoneNumber:", phoneNumber);

		// Validate the phoneNumber input
		if (!phoneNumber) {
			return R(res, false, "Phone number is required.");
		}

		const sendMoblenumber = `+91${phoneNumber}`;


		try {
			// Logic for rate limiting to limit sending otp's

			const user = await models.users.findOne({
				where: {
					[Op.or]: [
						{ mobile_number: phoneNumber },
						{ email: email },
						{ user_name: user_name }
					]
				}
			});


			// If there is user present
			if (user) {
				return R(res, false, `User with this phone number: ${phoneNumber}, already exists.`);
				// => reject(Register), because user already preseent, display in frontend also
			}

			// User is not present, so SEND OTP
			else {


				// Actual OTP SENDING LOGIC
				try {
					await sendOtp(sendMoblenumber);
					return R(res, true, "OTP sent successfully");
				} catch (e) {
					console.error("Error sending OTP:", e);
				}

			}


		} catch (error) {
			console.error("Unkown Error in registration OTP send", error)
			return R(res, false, "Unknown error occured");
		}
	}),

	// REGISTER VERIFY OTP

	RegisterOTP_verify: asyncWrapper(async (req: UserAuthRequest, res: Response) => {
		const { phoneNumber, code } = req.body;

		const sendMoblenumber = `+91${phoneNumber}`;
		// Validate required fields
		if (!phoneNumber || !code) {
			return R(res, false, "Phone number and verification code are required");
		}

		try {
			// First verify if the OTP is valid
			const isVerified = await verifyOtp(sendMoblenumber, code);

			if (!isVerified) {
				return R(res, false, "Invalid OTP");
			}

			// If we get here, the OTP is valid and the phone number is available
			// Return success so the frontend can proceed with registration
			return R(res, true, "Phone number verified successfully", {
				phoneNumber: phoneNumber,
				mobileVerified: 1
			});

		} catch (error) {
			console.error("Error in RegisterOTP_verify:", error);
			return R(res, false, "Error validating OTP");
		}
	}),
};


// [{ id: 1, user_id: 17281, title: "painting new", main_img: "imaZ2YCE2ZL172811.png",… }]