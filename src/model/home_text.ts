
import * as Sequelize from 'sequelize';
import { DataTypes, Model, Optional } from 'sequelize';

export interface home_textAttributes {
    id: number;
    title: string;
    text: string;
    status: string;
    language: string;
}

export type home_textPk = "id";
export type home_textId = home_textAttributes[home_textPk];
export type home_textOptionalAttributes = "id";
export type home_textCreationAttributes = Optional<home_textAttributes, home_textOptionalAttributes>;

export class home_text extends Model<home_textAttributes, home_textCreationAttributes> implements home_textAttributes {
    id!: number;
    title!: string;
    text!: string;
    status!: string;
    language!: string;


    static initModel(sequelize: Sequelize.Sequelize): typeof home_text {
        return sequelize.define('home_text', {
            id: {
                autoIncrement: true,
                type: DataTypes.INTEGER,
                allowNull: false,
                primaryKey: true
            },

            title: {
                type: DataTypes.STRING(255),
                allowNull: false
            },
            text: {
                type: DataTypes.STRING(255),
                allowNull: false
            },

            language: {
                type: DataTypes.STRING(255),
                allowNull: false
            },


        }, {
            tableName: 'home_text',
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
        }) as typeof home_text;
    }

}