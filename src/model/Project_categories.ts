import * as Sequelize from 'sequelize';
import { DataTypes, Model, Optional } from 'sequelize';

export interface Project_categoriesAttributes {
    id: number;
    category_name: string;
    parent_id: number;
    description: string;
    meta_keywords: string;
    meta_description: string;
    is_active: number;
    created: number;
    modified: number;
}

export type Project_categoriesPk = "id";
export type Project_categoriesId = Project_categoriesAttributes[Project_categoriesPk];
export type Project_categoriesOptionalAttributes = "id" | "is_active";
export type Project_categoriesCreationAttributes = Optional<Project_categoriesAttributes, Project_categoriesOptionalAttributes>;

export class Project_categories extends Model<Project_categoriesAttributes, Project_categoriesCreationAttributes> implements Project_categoriesAttributes {
    id!: number;
    category_name!: string;
    parent_id!: number;
    description!: string;
    meta_keywords!: string;
    meta_description!: string;
    is_active!: number;
    created!: number;
    modified!: number;


    static initModel(sequelize: Sequelize.Sequelize): typeof Project_categories {
        return sequelize.define('Project_categories', {
            id: {
                autoIncrement: true,
                type: DataTypes.INTEGER.UNSIGNED,
                allowNull: false,
                primaryKey: true
            },
            category_name: {
                type: DataTypes.STRING(255),
                allowNull: false
            },
            parent_id: {
                type: DataTypes.INTEGER.UNSIGNED,
                allowNull: true
            },
            description: {
                type: DataTypes.TEXT,
                allowNull: false
            },
            meta_keywords: {
                type: DataTypes.TEXT,
                allowNull: false
            },
            meta_description: {
                type: DataTypes.TEXT,
                allowNull: false
            },
            is_active: {
                type: DataTypes.TINYINT,
                allowNull: false,
                defaultValue: 1
            },
            created: {
                type: DataTypes.INTEGER,
                allowNull: false
            },
            modified: {
                type: DataTypes.INTEGER,
                allowNull: false
            }
        }, {
            tableName: 'Project_categories',
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
        }) as typeof Project_categories;
    }
}
