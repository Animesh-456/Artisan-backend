
import * as Sequelize from 'sequelize';
import { DataTypes, Model, Optional } from 'sequelize';

export interface help_requestAttributes {
    id: number;
    attachments: string;
    role: number;
    name: string;
    email: string;
    mobile_number: number;
    subject: string;
    comment: string;
}

export type help_requestPk = "id";
export type help_requestId = help_requestAttributes[help_requestPk];
export type help_requestOptionalAttributes = "id";
export type help_requestCreationAttributes = Optional<help_requestAttributes, help_requestOptionalAttributes>;

export class help_request extends Model<help_requestAttributes, help_requestCreationAttributes> implements help_requestAttributes {
    id!: number;
    attachments!: string;
    role!: number;
    name!: string;
    email!: string;
    mobile_number!: number;
    subject!: string;
    comment!: string;


    static initModel(sequelize: Sequelize.Sequelize): typeof help_request {
        return sequelize.define('help_request', {
            id: {
                autoIncrement: true,
                type: DataTypes.INTEGER,
                allowNull: false,
                primaryKey: true
            },

            attachments: {
                type: DataTypes.STRING(255),
                allowNull: false
            },
            role: {
                type: DataTypes.INTEGER,
                allowNull: false
            },

            name: {
                type: DataTypes.STRING(255),
                allowNull: false
            },
            email: {
                type: DataTypes.STRING(255),
                allowNull: false
            },

            mobile_number: {
                type: DataTypes.INTEGER,
                allowNull: false
            },
            subject: {
                type: DataTypes.STRING(255),
                allowNull: false
            },

            comment: {
                type: DataTypes.STRING(255),
                allowNull: false
            },

        }, {
            tableName: 'help_request',
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
            ]
        }) as typeof help_request;
    }

}