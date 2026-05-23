use log::info;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, Database,
    DatabaseConnection, DbErr, EntityTrait, QueryFilter, QuerySelect, Set,
};
use sea_orm::entity::prelude::*;
use sea_orm::query::QueryOrder;
use sea_query::{Table, ColumnDef};
use serde::{Deserialize, Serialize};
use std::path::Path;

mod user {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, DeriveEntityModel)]
    #[sea_orm(table_name = "users")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub username: String,
        pub password_hash: String,
        pub role: String,
        pub created_at: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

mod session {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, DeriveEntityModel)]
    #[sea_orm(table_name = "sessions")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub user_id: i64,
        pub created_at: String,
        pub expires_at: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

mod app {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, DeriveEntityModel)]
    #[sea_orm(table_name = "apps")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub name: String,
        pub description: String,
        pub url: String,
        pub icon_url: String,
        pub is_active: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

mod user_app_permission {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, DeriveEntityModel)]
    #[sea_orm(table_name = "user_app_permissions")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub user_id: i64,
        pub app_id: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

mod audit_log {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, DeriveEntityModel)]
    #[sea_orm(table_name = "audit_logs")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub user_id: Option<i64>,
        pub action: String,
        pub source_ip: String,
        pub target_url: String,
        pub result: String,
        pub timestamp: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub use user::Entity as UserEntity;
pub use user::Column as UserColumn;
pub use user::ActiveModel as UserActiveModel;
pub use user::Model as UserModel;

pub use session::Entity as SessionEntity;
pub use session::Column as SessionColumn;
pub use session::ActiveModel as SessionActiveModel;
pub use session::Model as SessionModel;

pub use app::Entity as AppEntity;
pub use app::Column as AppColumn;
pub use app::ActiveModel as AppActiveModel;
pub use app::Model as AppModel;

pub use user_app_permission::Entity as UserAppPermissionEntity;
pub use user_app_permission::Column as UserAppPermissionColumn;
pub use user_app_permission::ActiveModel as UserAppPermissionActiveModel;

pub use audit_log::Entity as AuditLogEntity;
pub use audit_log::Column as AuditLogColumn;
pub use audit_log::ActiveModel as AuditLogActiveModel;
pub use audit_log::Model as AuditLogModel;

// ============ Public API types ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub role: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: i64,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct App {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub url: String,
    pub icon_url: String,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: i64,
    pub user_id: Option<i64>,
    pub action: String,
    pub source_ip: String,
    pub target_url: String,
    pub result: String,
    pub timestamp: String,
}

// ============ Helpers ============

fn model_to_user(m: UserModel) -> User {
    User { id: m.id, username: m.username, password_hash: m.password_hash, role: m.role, created_at: m.created_at }
}

fn model_to_session(m: SessionModel) -> Session {
    Session { id: m.id, user_id: m.user_id, created_at: m.created_at, expires_at: m.expires_at }
}

fn model_to_app(m: AppModel) -> App {
    App { id: m.id, name: m.name, description: m.description, url: m.url, icon_url: m.icon_url, is_active: m.is_active != 0 }
}

fn model_to_audit_log(m: AuditLogModel) -> AuditLog {
    AuditLog { id: m.id, user_id: m.user_id, action: m.action, source_ip: m.source_ip, target_url: m.target_url, result: m.result, timestamp: m.timestamp }
}

// ============ Database initialization ============

pub async fn init_database(db_path: &Path) -> Result<DatabaseConnection, DbErr> {
    let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());
    info!("Connecting to database: {}", db_url);
    let db = Database::connect(&db_url).await?;
    info!("Database connected successfully");
    create_tables(&db).await?;
    create_default_admin(&db).await?;
    Ok(db)
}

async fn create_tables(db: &DatabaseConnection) -> Result<(), DbErr> {
    db.execute(
        &Table::create()
            .table(UserEntity)
            .if_not_exists()
            .col(ColumnDef::new(UserColumn::Id).integer().not_null().auto_increment().primary_key())
            .col(ColumnDef::new(UserColumn::Username).string().not_null().unique_key())
            .col(ColumnDef::new(UserColumn::PasswordHash).string().not_null())
            .col(ColumnDef::new(UserColumn::Role).string().not_null().default("'user'"))
            .col(ColumnDef::new(UserColumn::CreatedAt).string().not_null().default("(datetime('now'))"))
            .to_owned()
    ).await.map(|_| ())?;

    db.execute(
        &Table::create()
            .table(SessionEntity)
            .if_not_exists()
            .col(ColumnDef::new(SessionColumn::Id).string().not_null().primary_key())
            .col(ColumnDef::new(SessionColumn::UserId).integer().not_null())
            .col(ColumnDef::new(SessionColumn::CreatedAt).string().not_null().default("(datetime('now'))"))
            .col(ColumnDef::new(SessionColumn::ExpiresAt).string().not_null())
            .to_owned()
    ).await.map(|_| ())?;

    db.execute(
        &Table::create()
            .table(AppEntity)
            .if_not_exists()
            .col(ColumnDef::new(AppColumn::Id).integer().not_null().auto_increment().primary_key())
            .col(ColumnDef::new(AppColumn::Name).string().not_null())
            .col(ColumnDef::new(AppColumn::Description).string().not_null().default("''"))
            .col(ColumnDef::new(AppColumn::Url).string().not_null())
            .col(ColumnDef::new(AppColumn::IconUrl).string().not_null().default("''"))
            .col(ColumnDef::new(AppColumn::IsActive).integer().not_null().default("1"))
            .to_owned()
    ).await.map(|_| ())?;

    db.execute(
        &Table::create()
            .table(UserAppPermissionEntity)
            .if_not_exists()
            .col(ColumnDef::new(UserAppPermissionColumn::Id).integer().not_null().auto_increment().primary_key())
            .col(ColumnDef::new(UserAppPermissionColumn::UserId).integer().not_null())
            .col(ColumnDef::new(UserAppPermissionColumn::AppId).integer().not_null())
            .to_owned()
    ).await.map(|_| ())?;

    db.execute(
        &Table::create()
            .table(AuditLogEntity)
            .if_not_exists()
            .col(ColumnDef::new(AuditLogColumn::Id).integer().not_null().auto_increment().primary_key())
            .col(ColumnDef::new(AuditLogColumn::UserId).integer())
            .col(ColumnDef::new(AuditLogColumn::Action).string().not_null())
            .col(ColumnDef::new(AuditLogColumn::SourceIp).string().not_null().default("''"))
            .col(ColumnDef::new(AuditLogColumn::TargetUrl).string().not_null().default("''"))
            .col(ColumnDef::new(AuditLogColumn::Result).string().not_null().default("'success'"))
            .col(ColumnDef::new(AuditLogColumn::Timestamp).string().not_null().default("(datetime('now'))"))
            .to_owned()
    ).await.map(|_| ())?;

    Ok(())
}

async fn create_default_admin(db: &DatabaseConnection) -> Result<(), DbErr> {
    let count = UserEntity::find().count(db).await?;
    if count == 0 {
        let hash = argon2::hash_encoded(
            b"admin123", b"web-ssl-vpn-salt-2024", &argon2::Config::default(),
        ).map_err(|e| DbErr::Custom(format!("argon2 error: {}", e)))?;

        UserActiveModel {
            username: Set("admin".to_string()),
            password_hash: Set(hash),
            role: Set("admin".to_string()),
            ..Default::default()
        }.insert(db).await?;
        info!("Default admin user created: admin / admin123");
    }
    Ok(())
}

// ============ User operations ============

pub async fn find_user_by_username(db: &DatabaseConnection, username: &str) -> Result<Option<User>, DbErr> {
    let result = UserEntity::find().filter(UserColumn::Username.eq(username)).one(db).await?;
    Ok(result.map(model_to_user))
}

pub async fn find_user_by_id(db: &DatabaseConnection, user_id: i64) -> Result<Option<User>, DbErr> {
    let result = UserEntity::find_by_id(user_id).one(db).await?;
    Ok(result.map(model_to_user))
}

pub async fn get_all_users(db: &DatabaseConnection) -> Result<Vec<User>, DbErr> {
    let users = UserEntity::find().all(db).await?;
    Ok(users.into_iter().map(model_to_user).collect())
}

pub async fn create_user(db: &DatabaseConnection, username: &str, password_hash: &str, role: &str) -> Result<User, DbErr> {
    let result = UserActiveModel {
        username: Set(username.to_string()),
        password_hash: Set(password_hash.to_string()),
        role: Set(role.to_string()),
        ..Default::default()
    }.insert(db).await?;
    Ok(model_to_user(result))
}

#[allow(dead_code)]
pub async fn is_admin(db: &DatabaseConnection, user_id: i64) -> Result<bool, DbErr> {
    let user = find_user_by_id(db, user_id).await?;
    Ok(user.map(|u| u.role == "admin").unwrap_or(false))
}

// ============ Session operations ============

pub async fn create_session(db: &DatabaseConnection, user_id: i64, session_id: &str, expires_at: &str) -> Result<(), DbErr> {
    SessionActiveModel {
        id: Set(session_id.to_string()),
        user_id: Set(user_id),
        created_at: Set(chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()),
        expires_at: Set(expires_at.to_string()),
    }.insert(db).await?;
    Ok(())
}

pub async fn find_session(db: &DatabaseConnection, session_id: &str) -> Result<Option<Session>, DbErr> {
    let result = SessionEntity::find_by_id(session_id).one(db).await?;
    Ok(result.map(model_to_session))
}

pub async fn delete_session(db: &DatabaseConnection, session_id: &str) -> Result<(), DbErr> {
    SessionEntity::delete_by_id(session_id).exec(db).await?;
    Ok(())
}

pub async fn cleanup_expired_sessions(_db: &DatabaseConnection) -> Result<(), DbErr> {
    Ok(())
}

// ============ App operations ============

pub async fn get_all_apps(db: &DatabaseConnection) -> Result<Vec<App>, DbErr> {
    let apps = AppEntity::find().filter(AppColumn::IsActive.eq(1)).all(db).await?;
    Ok(apps.into_iter().map(model_to_app).collect())
}

pub async fn get_user_apps(db: &DatabaseConnection, user_id: i64) -> Result<Vec<App>, DbErr> {
    let apps = AppEntity::find().filter(AppColumn::IsActive.eq(1)).all(db).await?;
    let permissions = UserAppPermissionEntity::find().filter(UserAppPermissionColumn::UserId.eq(user_id)).all(db).await?;
    let permitted_ids: std::collections::HashSet<i64> = permissions.into_iter().map(|p| p.app_id).collect();
    Ok(apps.into_iter().filter(|a| permitted_ids.contains(&a.id)).map(model_to_app).collect())
}

pub async fn create_app(db: &DatabaseConnection, name: &str, description: &str, url: &str, icon_url: &str) -> Result<App, DbErr> {
    let result = AppActiveModel {
        name: Set(name.to_string()),
        description: Set(description.to_string()),
        url: Set(url.to_string()),
        icon_url: Set(icon_url.to_string()),
        ..Default::default()
    }.insert(db).await?;
    Ok(model_to_app(result))
}

pub async fn get_app_by_id(db: &DatabaseConnection, app_id: i64) -> Result<Option<App>, DbErr> {
    let result = AppEntity::find_by_id(app_id).one(db).await?;
    Ok(result.map(model_to_app))
}

pub async fn delete_app(db: &DatabaseConnection, app_id: i64) -> Result<(), DbErr> {
    AppEntity::delete_by_id(app_id).exec(db).await?;
    Ok(())
}

// ============ Permission operations ============

pub async fn user_has_app_permission(db: &DatabaseConnection, user_id: i64, app_id: i64) -> Result<bool, DbErr> {
    let count = UserAppPermissionEntity::find()
        .filter(UserAppPermissionColumn::UserId.eq(user_id))
        .filter(UserAppPermissionColumn::AppId.eq(app_id))
        .count(db).await?;
    Ok(count > 0)
}

#[allow(dead_code)]
pub async fn grant_app_permission(db: &DatabaseConnection, user_id: i64, app_id: i64) -> Result<(), DbErr> {
    let existing = UserAppPermissionEntity::find()
        .filter(UserAppPermissionColumn::UserId.eq(user_id))
        .filter(UserAppPermissionColumn::AppId.eq(app_id))
        .one(db).await?;
    if existing.is_none() {
        UserAppPermissionActiveModel {
            user_id: Set(user_id), app_id: Set(app_id), ..Default::default()
        }.insert(db).await?;
    }
    Ok(())
}

#[allow(dead_code)]
pub async fn revoke_app_permission(db: &DatabaseConnection, user_id: i64, app_id: i64) -> Result<(), DbErr> {
    UserAppPermissionEntity::delete_many()
        .filter(UserAppPermissionColumn::UserId.eq(user_id))
        .filter(UserAppPermissionColumn::AppId.eq(app_id))
        .exec(db).await?;
    Ok(())
}

#[allow(dead_code)]
pub async fn get_user_permissions(db: &DatabaseConnection, user_id: i64) -> Result<Vec<i64>, DbErr> {
    let perms = UserAppPermissionEntity::find().filter(UserAppPermissionColumn::UserId.eq(user_id)).all(db).await?;
    Ok(perms.into_iter().map(|p| p.app_id).collect())
}

pub async fn set_user_permissions(db: &DatabaseConnection, user_id: i64, app_ids: &[i64]) -> Result<(), DbErr> {
    UserAppPermissionEntity::delete_many().filter(UserAppPermissionColumn::UserId.eq(user_id)).exec(db).await?;
    for app_id in app_ids {
        UserAppPermissionActiveModel { user_id: Set(user_id), app_id: Set(*app_id), ..Default::default() }.insert(db).await?;
    }
    Ok(())
}

// ============ Audit log operations ============

pub async fn create_audit_log(db: &DatabaseConnection, user_id: Option<i64>, action: &str, source_ip: &str, target_url: &str, result: &str) -> Result<(), DbErr> {
    AuditLogActiveModel {
        user_id: Set(user_id),
        action: Set(action.to_string()),
        source_ip: Set(source_ip.to_string()),
        target_url: Set(target_url.to_string()),
        result: Set(result.to_string()),
        ..Default::default()
    }.insert(db).await?;
    Ok(())
}

pub async fn get_audit_logs(db: &DatabaseConnection, limit: u64) -> Result<Vec<AuditLog>, DbErr> {
    let logs = AuditLogEntity::find().order_by_desc(AuditLogColumn::Id).limit(Some(limit)).all(db).await?;
    Ok(logs.into_iter().map(model_to_audit_log).collect())
}
