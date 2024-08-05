// import * as Sequelize from 'sequelize';
// import { DataTypes, Model, Optional } from 'sequelize';

// export interface Project_categoriesAttributes {
//     id: number;
//     category_name: string;
//     parent_id: number;
//     description: string;
//     meta_keywords: string;
//     meta_description: string;
//     is_active: number;
//     created: number;
//     modified: number;
// }

// export type Project_categoriesPk = "id";
// export type Project_categoriesId = Project_categoriesAttributes[Project_categoriesPk];
// export type Project_categoriesOptionalAttributes = "id" | "category_name" | "is_active" | "parent_id" | "description" | "meta_keywords" | "meta_description" | "is_active" | "created" | "modified";
// export type Project_categoriesCreationAttributes = Optional<Project_categoriesAttributes, Project_categoriesOptionalAttributes>;

// export class Project_categories extends Model<Project_categoriesAttributes, Project_categoriesCreationAttributes> implements Project_categoriesAttributes {
//     id!: number;
//     category_name!: string;
//     parent_id!: number;
//     description!: string;
//     meta_keywords!: string;
//     meta_description!: string;
//     is_active!: number;
//     created!: number;
//     modified!: number;


//     Project_categories!: Project_categories;
//     getProject_categories!: Sequelize.BelongsToGetAssociationMixin<Project_categories>;
//     setProject_categories!: Sequelize.BelongsToSetAssociationMixin<Project_categories, Project_categoriesId>;
//     createProject_categories!: Sequelize.BelongsToCreateAssociationMixin<Project_categories>;

//     // getSubcategories!: Sequelize.HasManyGetAssociationsMixin<Project_categories>;
//     // setSubcategories!: Sequelize.HasManySetAssociationsMixin<Project_categories, Project_categoriesId>;
//     // addSubcategory!: Sequelize.HasManyAddAssociationMixin<Project_categories, Project_categoriesId>;
//     // addSubcategories!: Sequelize.HasManyAddAssociationsMixin<Project_categories, Project_categoriesId>;
//     // createSubcategory!: Sequelize.HasManyCreateAssociationMixin<Project_categories>;
//     // removeSubcategory!: Sequelize.HasManyRemoveAssociationMixin<Project_categories, Project_categoriesId>;
//     // removeSubcategories!: Sequelize.HasManyRemoveAssociationsMixin<Project_categories, Project_categoriesId>;
//     // hasSubcategory!: Sequelize.HasManyHasAssociationMixin<Project_categories, Project_categoriesId>;
//     // hasSubcategories!: Sequelize.HasManyHasAssociationsMixin<Project_categories, Project_categoriesId>;
//     // countSubcategories!: Sequelize.HasManyCountAssociationsMixin;


//     // getParent!: Sequelize.BelongsToGetAssociationMixin<Project_categories>;
//     // setParent!: Sequelize.BelongsToSetAssociationMixin<Project_categories, Project_categoriesId>;
//     // createParent!: Sequelize.BelongsToCreateAssociationMixin<Project_categories>;


//     static initModel(sequelize: Sequelize.Sequelize): typeof Project_categories {
//         return sequelize.define('Project_categories', {
//             id: {
//                 autoIncrement: true,
//                 type: DataTypes.INTEGER.UNSIGNED,
//                 allowNull: false,
//                 primaryKey: true
//             },
//             category_name: {
//                 type: DataTypes.STRING(255),
//                 allowNull: false
//             },
//             parent_id: {
//                 type: DataTypes.INTEGER.UNSIGNED,
//                 allowNull: true
//             },
//             description: {
//                 type: DataTypes.TEXT,
//                 allowNull: false
//             },
//             meta_keywords: {
//                 type: DataTypes.TEXT,
//                 allowNull: false
//             },
//             meta_description: {
//                 type: DataTypes.TEXT,
//                 allowNull: false
//             },
//             is_active: {
//                 type: DataTypes.TINYINT,
//                 allowNull: false,
//                 defaultValue: 1
//             },
//             created: {
//                 type: DataTypes.INTEGER,
//                 allowNull: false
//             },
//             modified: {
//                 type: DataTypes.INTEGER,
//                 allowNull: false
//             }
//         }, {
//             tableName: 'Project_categories',
//             timestamps: false,
//             indexes: [
//                 {
//                     name: "PRIMARY",
//                     unique: true,
//                     using: "BTREE",
//                     fields: [
//                         { name: "id" },
//                     ]
//                 },
//             ]
//         }) as typeof Project_categories;
//     }
// }


import * as Sequelize from 'sequelize';
import { DataTypes, Model, Optional } from 'sequelize';

export interface Project_categoriesAttributes {
    id: number;
    category_name: string;
    parent_id: number | null;
    description: string;
    meta_keywords: string;
    meta_description: string;
    is_active: number;
    created: number;
    modified: number;
}

export type Project_categoriesPk = "id";
export type Project_categoriesId = Project_categoriesAttributes[Project_categoriesPk];
export type Project_categoriesOptionalAttributes = "id" | "parent_id";
export type Project_categoriesCreationAttributes = Optional<Project_categoriesAttributes, Project_categoriesOptionalAttributes>;

export class Project_categories extends Model<Project_categoriesAttributes, Project_categoriesCreationAttributes> implements Project_categoriesAttributes {
    id!: number;
    category_name!: string;
    parent_id!: number | null;
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
                primaryKey: true,
            },
            category_name: {
                type: DataTypes.STRING(255),
                allowNull: false,
            },
            parent_id: {
                type: DataTypes.INTEGER.UNSIGNED,
                allowNull: true,
                defaultValue: null,
            },
            description: {
                type: DataTypes.TEXT,
                allowNull: false,
            },
            meta_keywords: {
                type: DataTypes.TEXT,
                allowNull: false,
            },
            meta_description: {
                type: DataTypes.TEXT,
                allowNull: false,
            },
            is_active: {
                type: DataTypes.TINYINT,
                allowNull: false,
                defaultValue: 1,
            },
            created: {
                type: DataTypes.INTEGER,
                allowNull: false,
            },
            modified: {
                type: DataTypes.INTEGER,
                allowNull: false,
            },
        }, {
            tableName: 'Project_categories',
            timestamps: false,
            indexes: [
                {
                    name: 'PRIMARY',
                    unique: true,
                    using: 'BTREE',
                    fields: [{ name: 'id' }],
                },
            ],
        }) as typeof Project_categories
    }
}
