import dotenv from "dotenv";
import { Dialect } from "sequelize";

dotenv.config();

export default {
    // MySql
    host: '188.245.62.232',
    user: 'art',
    password: 'artisian',
    db: 'art',
    dialect: "mysql" as Dialect,
    pool: {
        max: 5,
        min: 0,
        acquire: 1000000,
        idle: 10000,
        port: 3306,
    },
};