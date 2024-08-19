
import * as Sequelize from 'sequelize';
import { DataTypes, Model, Optional } from 'sequelize';

export interface kycAttributes {
    id: number;
    user_id: number;
    pan: string;
    gst: string;
    company_name: string;
    company_address: string;
    company_address1: string;
    company_state: string;
    city: string;
    zip: number;
    bank_account: string;
    ifsc: string;
    bank_name: string;
    bank_address: string;
    bank_address1: string;
    bank_state: string;
    bank_zip: number;
    bank_city: string;
    attachments: string;
    upload: Date;
    admin_approve: number
}

export type kycPk = "id";
export type kycId = kycAttributes[kycPk];
export type kycOptionalAttributes = "id";
export type kycCreationAttributes = Optional<kycAttributes, kycOptionalAttributes>;

export class kyc extends Model<kycAttributes, kycCreationAttributes> implements kycAttributes {
    id!: number;
    user_id!: number;
    pan!: string;
    gst!: string;
    company_name!: string;
    company_address!: string;
    company_address1!: string;
    company_state!: string;
    city!: string;
    zip!: number;
    bank_account!: string;
    ifsc!: string;
    bank_name!: string;
    bank_address!: string;
    bank_address1!: string;
    bank_state!: string;
    bank_zip!: number;
    bank_city!: string;
    attachments!: string;
    upload!: Date;
    admin_approve!: number

    static initModel(sequelize: Sequelize.Sequelize): typeof kyc {
        return sequelize.define('kyc', {
            id: {
                autoIncrement: true,
                type: DataTypes.INTEGER,
                allowNull: false,
                primaryKey: true
            },
            user_id: {
                type: DataTypes.INTEGER,
                allowNull: false,
                references: {
                    model: 'users',
                    key: 'id'
                }
            },
            pan: {
                type: DataTypes.STRING(100),
                allowNull: false
            },
            gst: {
                type: DataTypes.STRING(200),
                allowNull: false
            },
            company_name: {
                type: DataTypes.STRING(200),
                allowNull: false
            },
            company_address: {
                type: DataTypes.TEXT,
                allowNull: false
            },
            company_address1: {
                type: DataTypes.STRING(255),
                allowNull: false
            },
            company_state: {
                type: DataTypes.STRING(200),
                allowNull: false
            },
            city: {
                type: DataTypes.STRING(200),
                allowNull: false
            },
            zip: {
                type: DataTypes.INTEGER,
                allowNull: false
            },
            bank_account: {
                type: DataTypes.STRING(255),
                allowNull: false
            },
            ifsc: {
                type: DataTypes.STRING(255),
                allowNull: false
            },
            bank_name: {
                type: DataTypes.STRING(255),
                allowNull: false
            },
            bank_address: {
                type: DataTypes.STRING(255),
                allowNull: false
            },
            bank_address1: {
                type: DataTypes.STRING(255),
                allowNull: false
            },
            bank_state: {
                type: DataTypes.STRING(255),
                allowNull: false
            },
            bank_zip: {
                type: DataTypes.STRING(255),
                allowNull: false
            },
            bank_city: {
                type: DataTypes.STRING(255),
                allowNull: false
            },
            attachments: {
                type: DataTypes.STRING(255),
                allowNull: false
            },
            upload: {
                type: DataTypes.STRING(255),
                allowNull: false
            },
            admin_approve: {
                type: DataTypes.INTEGER,
                allowNull: false
            }
        }, {
            tableName: 'kyc',
            timestamps: false,
            indexes: [
                {
                    name: "PRIMARY",
                    unique: true,
                    using: "BTREE",
                    fields: [
                        { name: "id" },
                    ]
                },
                {
                    name: "user_id",
                    using: "BTREE",
                    fields: [
                        { name: "user_id" },
                    ]
                },
            ]
        }) as typeof kyc;
    }

}

